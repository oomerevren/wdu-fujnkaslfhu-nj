import stripe
from app.config import settings

stripe.api_key = settings.STRIPE_SECRET_KEY

# Stripe Price ID'leri — production'da güncellenecek
PRICE_MAPPING = {
    "starter": "price_starter_monthly",    # $99/ay
    "solo": "price_solo_monthly",          # $199/ay
    "pro": "price_pro_monthly",            # $499/ay
    "enterprise": "price_enterprise",      # Custom
}

# Tersine mapping: Price ID -> plan_id (webhook'ta kullanılır)
PRICE_TO_PLAN = {v: k for k, v in PRICE_MAPPING.items()}


def create_checkout_session(user_id: str, email: str, plan_id: str):
    """
    Verilen plan_id için Stripe Checkout Session oluşturur.
    plan_id, PRICE_MAPPING'te bulunmalıdır.
    """
    price_id = PRICE_MAPPING.get(plan_id)
    if not price_id:
        raise ValueError(f"Geçersiz plan_id: {plan_id}. Desteklenen planlar: {list(PRICE_MAPPING.keys())}")

    try:
        checkout_session = stripe.checkout.Session.create(
            customer_email=email,
            payment_method_types=['card'],
            line_items=[
                {
                    'price': price_id,
                    'quantity': 1,
                },
            ],
            mode='subscription',
            success_url=settings.FRONTEND_URL + '/dashboard?session_id={CHECKOUT_SESSION_ID}',
            cancel_url=settings.FRONTEND_URL + '/billing',
            metadata={
                'user_id': user_id,
                'plan_id': plan_id,
            }
        )
        return checkout_session
    except stripe.error.StripeError as e:
        # Stripe hatalarını yukarı fırlat, caller try/except ile yönetsin
        raise
    except Exception as e:
        raise RuntimeError(f"Checkout session oluşturulurken beklenmeyen hata: {e}") from e


def get_plan_from_price_id(price_id: str) -> str:
    """
    Stripe Price ID'sinden plan_id döndürür.
    Webhook event'lerinde price_id'den plan bilgisini çıkarmak için kullanılır.
    Eşleşme bulunamazsa 'unknown' döndürür.
    """
    return PRICE_TO_PLAN.get(price_id, "unknown")

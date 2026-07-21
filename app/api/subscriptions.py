from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session
from app.database import get_db
from app.models.user import User
from app.models.subscription import Subscription, PlanType
from app.services.auth_service import get_current_user
from app.services.payment_service import create_checkout_session, PRICE_MAPPING
from app.services.plan_service import get_plan_features
from app.config import settings
import stripe

router = APIRouter()


@router.post("/create-checkout")
def create_checkout(
    plan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if plan_id not in PRICE_MAPPING:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid plan: '{plan_id}'. Supported plans: {list(PRICE_MAPPING.keys())}"
        )

    try:
        session = create_checkout_session(str(current_user.id), current_user.email, plan_id)
    except (ValueError, RuntimeError) as e:
        raise HTTPException(status_code=400, detail=str(e))
    except stripe.error.StripeError as e:
        raise HTTPException(status_code=502, detail=f"Stripe error: {e.user_message or str(e)}")

    if not hasattr(session, 'url') or not session.url:
        raise HTTPException(status_code=500, detail="Could not create checkout session")

    return {"url": session.url}


@router.get("/my-plan")
def get_my_plan(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    subscription = db.query(Subscription).filter(
        Subscription.user_id == current_user.id
    ).first()

    if not subscription:
        # Henüz abonelik kaydı yoksa varsayılan FREE plan dön
        features = get_plan_features(PlanType.FREE)
        return {
            "plan": PlanType.FREE.value,
            "is_active": True,
            "scans_used": 0,
            "scans_limit": features.scans_limit,
            "features": features.model_dump(),
        }

    plan_type = subscription.plan if isinstance(subscription.plan, PlanType) else PlanType(subscription.plan)
    features = get_plan_features(plan_type)
    return {
        "plan": plan_type.value,
        "is_active": subscription.is_active,
        "scans_used": subscription.scans_used,
        "scans_limit": features.scans_limit,
        "features": features.model_dump(),
        "current_period_start": subscription.current_period_start.isoformat() if subscription.current_period_start else None,
        "current_period_end": subscription.current_period_end.isoformat() if subscription.current_period_end else None,
    }


@router.get("/usage")
def get_usage(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    from app.services.usage_service import get_usage
    return get_usage(current_user.id, db)


@router.post("/webhook")
async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
    payload = await request.body()
    sig_header = request.headers.get('stripe-signature')

    try:
        event = stripe.Webhook.construct_event(
            payload, sig_header, settings.STRIPE_WEBHOOK_SECRET
        )
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError:
        raise HTTPException(status_code=400, detail="Invalid signature")

    event_type = event.get("type")
    data = event.get("data", {}).get("object", {})

    if event_type == "checkout.session.completed":
        # Ödeme başarılı - subscription oluştur/güncelle
        user_id = data.get("metadata", {}).get("user_id")
        plan_id = data.get("metadata", {}).get("plan_id")
        stripe_subscription_id = data.get("subscription")
        stripe_customer_id = data.get("customer")

        if user_id and plan_id:
            sub = db.query(Subscription).filter(Subscription.user_id == user_id).first()
            if sub:
                sub.plan = PlanType(plan_id)
                sub.stripe_subscription_id = stripe_subscription_id
                sub.stripe_customer_id = stripe_customer_id
                sub.is_active = True
            else:
                sub = Subscription(
                    user_id=user_id,
                    plan=PlanType(plan_id),
                    stripe_subscription_id=stripe_subscription_id,
                    stripe_customer_id=stripe_customer_id,
                    is_active=True,
                )
                db.add(sub)
            db.commit()

    elif event_type == "customer.subscription.updated":
        # Subscription güncellendi
        stripe_sub_id = data.get("id")
        status = data.get("status")
        cancel_at_period_end = data.get("cancel_at_period_end", False)

        sub = db.query(Subscription).filter(
            Subscription.stripe_subscription_id == stripe_sub_id
        ).first()
        if sub:
            sub.is_active = (status == "active" or status == "trialing")
            sub.current_period_start = datetime.fromtimestamp(data.get("current_period_start", 0))
            sub.current_period_end = datetime.fromtimestamp(data.get("current_period_end", 0))
            db.commit()

    elif event_type == "customer.subscription.deleted":
        # Subscription iptal edildi
        stripe_sub_id = data.get("id")

        sub = db.query(Subscription).filter(
            Subscription.stripe_subscription_id == stripe_sub_id
        ).first()
        if sub:
            sub.plan = PlanType.FREE
            sub.is_active = False
            sub.stripe_subscription_id = None
            db.commit()

    elif event_type == "invoice.paid":
        # Fatura ödendi
        stripe_sub_id = data.get("subscription")

        sub = db.query(Subscription).filter(
            Subscription.stripe_subscription_id == stripe_sub_id
        ).first()
        if sub:
            sub.scans_used = 0  # Yeni dönemde scan hakkını sıfırla
            db.commit()

    elif event_type == "invoice.payment_failed":
        # Ödeme başarısız - notify user
        stripe_sub_id = data.get("subscription")

        sub = db.query(Subscription).filter(
            Subscription.stripe_subscription_id == stripe_sub_id
        ).first()
        if sub:
            # TODO: Send email to user about payment failure
            pass

    return {"status": "success"}

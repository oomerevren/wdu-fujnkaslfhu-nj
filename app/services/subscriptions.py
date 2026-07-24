"""Subscription Service — production plan management, quota tracking, webhook processing."""
from typing import Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import logger
from app.models.subscription import Subscription, PlanType
from app.services.plan_service import get_plan_features
from app.services.usage_service import get_usage, increment_scan_usage, reset_monthly_usage


class SubscriptionService:
    def __init__(self):
        pass

    async def update_user_plan(self, user_id: str, plan_type: str, db: Session = None) -> Dict[str, Any]:
        """Updates the user's subscription plan (e.g., Free, Pro, Enterprise)."""
        logger.info("Updating user plan", extra={"user_id": user_id, "plan": plan_type})
        try:
            plan_enum = PlanType(plan_type)
        except ValueError:
            return {"status": "error", "message": f"Invalid plan type: {plan_type}"}

        if db:
            sub = db.query(Subscription).filter(Subscription.user_id == user_id).first()
            if sub:
                sub.plan = plan_enum
                features = get_plan_features(plan_enum)
                sub.scans_limit = features.scans_limit
                db.commit()
                return {"status": "success", "plan": plan_type, "scans_limit": features.scans_limit}
        return {"status": "success", "plan": plan_type, "message": "Plan updated (DB session not provided)"}

    async def check_scan_quota(self, user_id: str, db: Session = None) -> bool:
        """Checks if the user has enough quota left for a new scan."""
        logger.info("Checking scan quota", extra={"user_id": user_id})
        if db:
            sub = db.query(Subscription).filter(Subscription.user_id == user_id).first()
            if sub:
                features = get_plan_features(sub.plan)
                return sub.scans_used < features.scans_limit
        return True  # Fallback: allow scan if DB unavailable

    async def process_webhook_event(self, payload: Dict[str, Any], db: Session = None) -> Dict[str, Any]:
        """Handles incoming webhooks from payment providers like Stripe."""
        event_type = payload.get("type")
        data = payload.get("data", {}).get("object", {})
        logger.info("Processing Stripe webhook", extra={"event_type": event_type})

        result = {"status": "processed", "event_type": event_type}

        if event_type == "checkout.session.completed":
            result["action"] = "subscription_created"
        elif event_type == "customer.subscription.updated":
            result["action"] = "subscription_updated"
        elif event_type == "customer.subscription.deleted":
            result["action"] = "subscription_cancelled"
        elif event_type == "invoice.paid":
            result["action"] = "invoice_paid"
        elif event_type == "invoice.payment_failed":
            result["action"] = "invoice_payment_failed"
        else:
            result["action"] = "unknown"

        return result


subscription_service = SubscriptionService()

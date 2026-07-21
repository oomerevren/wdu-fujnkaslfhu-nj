from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import Session

from app.models.subscription import Subscription, PlanType
from app.services.plan_service import get_plan_features


# ── Sync ─────────────────────────────────────────────────────────────────────

def get_usage(user_id: UUID, db: Session) -> dict:
    """Get current usage statistics for a user."""
    sub = db.query(Subscription).filter(Subscription.user_id == user_id).first()
    if not sub:
        return {
            "scans_used": 0,
            "scans_limit": get_plan_features(PlanType.FREE).scans_limit,
            "scans_remaining": get_plan_features(PlanType.FREE).scans_limit,
        }

    features = get_plan_features(sub.plan)
    return {
        "scans_used": sub.scans_used,
        "scans_limit": features.scans_limit,
        "scans_remaining": max(0, features.scans_limit - sub.scans_used),
        "plan": sub.plan.value if hasattr(sub.plan, 'value') else sub.plan,
    }


def increment_scan_usage(user_id: UUID, db: Session) -> bool:
    """Increment scan usage counter. Returns False if limit reached."""
    sub = db.query(Subscription).filter(Subscription.user_id == user_id).first()
    if not sub:
        sub = Subscription(user_id=user_id, plan=PlanType.FREE, scans_used=0, scans_limit=1)
        db.add(sub)
        db.flush()

    features = get_plan_features(sub.plan)
    if sub.scans_used >= features.scans_limit:
        return False

    sub.scans_used += 1
    db.commit()
    return True


def reset_monthly_usage(db: Session) -> int:
    """Reset scans_used for all active subscriptions (cron job)."""
    count = db.query(Subscription).filter(
        Subscription.is_active == True,
        Subscription.scans_used > 0,
    ).update({"scans_used": 0})
    db.commit()
    return count


# ── Async ────────────────────────────────────────────────────────────────────

async def get_usage_async(user_id: UUID, db: AsyncSession) -> dict:
    """Get current usage statistics for a user (async)."""
    result = await db.execute(
        select(Subscription).where(Subscription.user_id == user_id)
    )
    sub = result.scalar_one_or_none()
    if not sub:
        return {
            "scans_used": 0,
            "scans_limit": get_plan_features(PlanType.FREE).scans_limit,
            "scans_remaining": get_plan_features(PlanType.FREE).scans_limit,
        }

    features = get_plan_features(sub.plan)
    return {
        "scans_used": sub.scans_used,
        "scans_limit": features.scans_limit,
        "scans_remaining": max(0, features.scans_limit - sub.scans_used),
        "plan": sub.plan.value if hasattr(sub.plan, 'value') else sub.plan,
    }


async def increment_scan_usage_async(user_id: UUID, db: AsyncSession) -> bool:
    """Increment scan usage counter (async). Returns False if limit reached."""
    result = await db.execute(
        select(Subscription).where(Subscription.user_id == user_id)
    )
    sub = result.scalar_one_or_none()
    if not sub:
        sub = Subscription(user_id=user_id, plan=PlanType.FREE, scans_used=0, scans_limit=1)
        db.add(sub)
        await db.flush()

    features = get_plan_features(sub.plan)
    if sub.scans_used >= features.scans_limit:
        return False

    sub.scans_used += 1
    await db.commit()
    return True


async def reset_monthly_usage_async(db: AsyncSession) -> int:
    """Reset scans_used for all active subscriptions (async - cron job)."""
    result = await db.execute(
        select(Subscription).where(
            Subscription.is_active == True,
            Subscription.scans_used > 0,
        )
    )
    subs = result.scalars().all()
    count = len(subs)
    for sub in subs:
        sub.scans_used = 0
    await db.commit()
    return count

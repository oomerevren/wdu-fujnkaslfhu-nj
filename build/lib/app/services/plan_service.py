from pydantic import BaseModel
from sqlalchemy.orm import Session
from app.models.subscription import PlanType, Subscription


class PlanFeatures(BaseModel):
    scans_limit: int
    users_limit: int
    api_access: bool
    max_targets: int
    report_export: bool
    priority_support: bool


PLAN_FEATURES: dict[PlanType, PlanFeatures] = {
    PlanType.FREE: PlanFeatures(
        scans_limit=1,
        users_limit=1,
        api_access=False,
        max_targets=3,
        report_export=False,
        priority_support=False,
    ),
    PlanType.STARTER: PlanFeatures(
        scans_limit=10,
        users_limit=1,
        api_access=False,
        max_targets=10,
        report_export=True,
        priority_support=False,
    ),
    PlanType.SOLO: PlanFeatures(
        scans_limit=50,
        users_limit=1,
        api_access=True,
        max_targets=50,
        report_export=True,
        priority_support=False,
    ),
    PlanType.PRO: PlanFeatures(
        scans_limit=200,
        users_limit=5,
        api_access=True,
        max_targets=200,
        report_export=True,
        priority_support=True,
    ),
    PlanType.ENTERPRISE: PlanFeatures(
        scans_limit=9999,
        users_limit=999,
        api_access=True,
        max_targets=9999,
        report_export=True,
        priority_support=True,
    ),
}


def get_plan_features(plan_type: PlanType) -> PlanFeatures:
    """Return the feature set for the given plan type."""
    return PLAN_FEATURES.get(plan_type, PLAN_FEATURES[PlanType.FREE])


def check_scan_limit(user_id, db: Session) -> bool:
    """Check whether the user has remaining scans according to their plan.

    Returns True if the user can still create scans, False if the limit
    has been reached.
    """
    sub = db.query(Subscription).filter(Subscription.user_id == user_id).first()
    if not sub:
        # No subscription record → treat as FREE plan with 0 scans used
        return True

    features = get_plan_features(sub.plan)
    return sub.scans_used < features.scans_limit


def get_plan_name(plan_type: PlanType) -> str:
    """Return a human-readable name for the given plan type."""
    names = {
        PlanType.FREE: "Free",
        PlanType.STARTER: "Starter",
        PlanType.SOLO: "Solo",
        PlanType.PRO: "Pro",
        PlanType.ENTERPRISE: "Enterprise",
    }
    return names.get(plan_type, "Free")

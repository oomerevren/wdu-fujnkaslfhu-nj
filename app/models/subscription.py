import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, ForeignKey, Enum, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base
import enum

class PlanType(str, enum.Enum):
    FREE = "free"
    STARTER = "starter"  # $99/test
    SOLO = "solo"        # $199/ay
    PRO = "pro"          # $499/ay
    ENTERPRISE = "enterprise"

class Subscription(Base):
    __tablename__ = "subscriptions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False, unique=True)
    plan = Column(Enum(PlanType), default=PlanType.FREE)
    stripe_customer_id = Column(String(255), nullable=True)
    stripe_subscription_id = Column(String(255), nullable=True)
    is_active = Column(Boolean, default=True)
    current_period_start = Column(DateTime, nullable=True)
    current_period_end = Column(DateTime, nullable=True)
    scans_used = Column(Integer, default=0)
    scans_limit = Column(Integer, default=1)  # Free: 1 scan
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

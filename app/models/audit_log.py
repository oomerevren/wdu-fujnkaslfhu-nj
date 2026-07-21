import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    action = Column(String(100), nullable=False)  # e.g. "scan.created", "finding.updated", "user.login"
    resource_type = Column(String(50), nullable=True)  # e.g. "scan", "finding", "target"
    resource_id = Column(String(100), nullable=True)
    details = Column(JSON, nullable=True)
    ip_address = Column(String(50), nullable=True)
    user_agent = Column(String(500), nullable=True)
    request_fingerprint = Column(String(64), nullable=True)
    hmac_signature = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, ForeignKey, Enum, Text, JSON, Float
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base
import enum

class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class FindingStatus(str, enum.Enum):
    OPEN = "open"
    FALSE_POSITIVE = "false_positive"
    FIXED = "fixed"
    ACKNOWLEDGED = "acknowledged"

class Finding(Base):
    __tablename__ = "findings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    target_id = Column(UUID(as_uuid=True), ForeignKey("targets.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    source = Column(String(50), nullable=False)  # nuclei, zap, promptfoo
    template_id = Column(String(255), nullable=True)  # Nuclei template ID
    name = Column(String(500), nullable=False)
    severity = Column(Enum(Severity), nullable=False)
    description = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    evidence = Column(JSON, nullable=True)  # İspat (request/response, curl command)
    cvss_score = Column(Float, nullable=True)  # 0-10
    cve_id = Column(String(50), nullable=True)
    status = Column(Enum(FindingStatus), default=FindingStatus.OPEN)
    comment = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

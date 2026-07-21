import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, ForeignKey, Enum, Text, JSON, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import relationship
from app.database import Base
import enum

class ScanType(str, enum.Enum):
    NUCLEI = "nuclei"
    ZAP = "zap"
    PROMPTFOO = "promptfoo"
    FULL = "full"  # Tümünü çalıştır
    AI_DRIVEN = "ai_driven"  # AI-driven scan using the agent pipeline

class ScanStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"

class Scan(Base):
    __tablename__ = "scans"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    target_id = Column(UUID(as_uuid=True), ForeignKey("targets.id"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    scan_type = Column(Enum(ScanType), nullable=False)
    status = Column(Enum(ScanStatus), default=ScanStatus.QUEUED)
    progress = Column(Integer, default=0)  # 0-100
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error_message = Column(Text, nullable=True)
    raw_results = Column(JSON, nullable=True)  # Scanner'dan gelen ham JSON
    created_at = Column(DateTime, default=datetime.utcnow)

    target = relationship("Target")
    user = relationship("User")

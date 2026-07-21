import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, ForeignKey, Enum, Text, JSON
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base
import enum

class TargetType(str, enum.Enum):
    WEB = "web"          # Web uygulaması (URL)
    API = "api"          # API endpoint
    LLM = "llm"          # LLM endpoint

class TargetStatus(str, enum.Enum):
    PENDING = "pending"
    VERIFIED = "verified"
    FAILED = "failed"

class Target(Base):
    __tablename__ = "targets"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    name = Column(String(255), nullable=True)
    target_type = Column(Enum(TargetType), default=TargetType.WEB)
    url = Column(Text, nullable=False)
    auth_header = Column(Text, nullable=True)  # Opsiyonel: Bearer token
    auth_type = Column(String(50), nullable=True)  # header, cookie, form
    status = Column(Enum(TargetStatus), default=TargetStatus.PENDING)
    metadata_json = Column(JSON, default=dict)  # "metadata" is a reserved word in SQLAlchemy Base
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, DateTime, Integer
from sqlalchemy.dialects.postgresql import UUID
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=True)  # Nullable çünkü OAuth kullanıcısı şifresiz olabilir
    full_name = Column(String(255), nullable=True)
    company_name = Column(String(255), nullable=True)
    avatar_url = Column(String(500), nullable=True)
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=False)  # Email verification required before activation
    is_verified = Column(Boolean, default=False)
    is_superuser = Column(Boolean, default=False)
    google_id = Column(String(255), unique=True, nullable=True)
    onboarding_step = Column(String(50), default="welcome")  # Görev 3'teki onboarding alanını buraya şimdiden ekliyorum
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

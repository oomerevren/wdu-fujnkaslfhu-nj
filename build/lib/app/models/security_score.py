"""SecurityScore model for tracking domain security scores."""

from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Column, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID

from app.database import Base


class SecurityScore(Base):
    """Stores aggregated security scores for domains.

    Each row represents the security posture of a domain at a point in time,
    with a 0-100 score, letter grade, and breakdown by severity.
    """

    __tablename__ = "security_scores"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    domain = Column(Text, nullable=False, index=True, unique=True)
    score = Column(Integer, nullable=False, default=0)  # 0-100
    grade = Column(String(3), nullable=False, default="F")  # A+, A, B, C, D, F
    total_scans = Column(Integer, nullable=False, default=0)
    critical_count = Column(Integer, nullable=False, default=0)
    high_count = Column(Integer, nullable=False, default=0)
    medium_count = Column(Integer, nullable=False, default=0)
    low_count = Column(Integer, nullable=False, default=0)
    trend = Column(String(20), nullable=False, default="stable")  # improving, declining, stable
    last_scan_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

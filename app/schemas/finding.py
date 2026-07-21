from pydantic import BaseModel, Field, field_validator
from typing import Optional, Any
from datetime import datetime
from uuid import UUID

class FindingStatusUpdate(BaseModel):
    status: str  # "open", "false_positive", "fixed", "acknowledged"
    comment: Optional[str] = None  # Neden false_positive işaretlendi?


class FindingResponse(BaseModel):
    id: UUID
    source: str
    template_id: Optional[str]
    name: str
    severity: str
    description: Optional[str]
    remediation: Optional[str]
    evidence: Optional[dict]
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    cve_id: Optional[str]
    status: str
    comment: Optional[str]
    created_at: datetime

    @field_validator("cvss_score", mode="before")
    @classmethod
    def validate_cvss_score(cls, v: Any) -> Optional[float]:
        """Validate and coerce cvss_score to float in [0.0, 10.0] range."""
        if v is None:
            return None
        try:
            val = float(v)
        except (TypeError, ValueError):
            return None
        if val < 0.0 or val > 10.0:
            raise ValueError(f"cvss_score must be between 0.0 and 10.0, got {val}")
        return round(val, 1)

    class Config:
        from_attributes = True

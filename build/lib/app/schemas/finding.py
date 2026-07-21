from pydantic import BaseModel
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
    cvss_score: Optional[int]
    cve_id: Optional[str]
    status: str
    comment: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True

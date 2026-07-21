from pydantic import BaseModel, Field
from typing import Optional, Any
from datetime import datetime
from uuid import UUID

class ScanCreate(BaseModel):
    target_id: UUID
    scan_type: str = "full"  # nuclei, zap, promptfoo, full, ai_driven

class AIOptionalScanRequest(BaseModel):
    """Optional parameters for AI-driven scans."""
    target_type: Optional[str] = Field(default="web", description="Type of target: web, api, llm")
    auth_header: Optional[str] = Field(default=None, description="Bearer token or auth header")
    depth: Optional[str] = Field(default="standard", description="Scan depth: standard, deep")

class AIScanCreate(BaseModel):
    """Request model for creating an AI-driven scan."""
    target_id: UUID
    target_type: str = Field(default="web", description="Type of target: web, api, llm")
    scan_type: str = Field(default="ai_driven", description="Must be 'ai_driven'")
    options: Optional[AIOptionalScanRequest] = Field(default=None)

class AIScanResponse(BaseModel):
    """Response from an AI-driven scan."""
    scan_id: UUID
    target_id: UUID
    target_url: str
    status: str
    progress: int
    pipeline_stage: str
    created_at: datetime

class ScanResponse(BaseModel):
    id: UUID
    target_id: UUID
    scan_type: str
    status: str
    progress: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True

from pydantic import BaseModel
from typing import Optional
from datetime import datetime
from uuid import UUID

class TargetCreate(BaseModel):
    name: Optional[str] = None
    url: str  # http:// veya https:// ile
    target_type: str = "web"  # web, api, llm
    auth_header: Optional[str] = None

class TargetResponse(BaseModel):
    id: UUID
    name: Optional[str]
    target_type: str
    url: str
    status: str
    created_at: datetime

    class Config:
        from_attributes = True

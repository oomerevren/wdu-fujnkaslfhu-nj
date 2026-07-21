from pydantic import BaseModel

class ScanRequest(BaseModel):
    target_url: str
    scan_profile: str = 'full'

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    target_url: str
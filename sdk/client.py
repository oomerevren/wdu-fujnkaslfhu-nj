
import httpx
from typing import Optional, Dict, Any
from .models import ScanRequest, ScanResponse

class PentestAIClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip('/')
        self.headers = {
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        }

    async def start_scan(self, target_url: str) -> ScanResponse:
        async with httpx.AsyncClient() as client:
            payload = ScanRequest(target_url=target_url).dict()
            response = await client.post(
                f'{self.base_url}/api/v1/scans',
                json=payload,
                headers=self.headers
            )
            response.raise_for_status()
            return ScanResponse(**response.json())

    async def get_scan_status(self, scan_id: str) -> Dict[str, Any]:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f'{self.base_url}/api/v1/scans/{scan_id}',
                headers=self.headers
            )
            response.raise_for_status()
            return response.json()

import httpx
import asyncio
import time
from typing import Optional, List, Dict, Any
from app.config import settings
from app.core.logging import logger

ZAP_API_KEY = settings.ZAP_API_KEY
ZAP_BASE_URL = settings.ZAP_BASE_URL

async def _zap_api_async(path: str, params: Dict[str, Any] = None) -> Dict[str, Any]:
    if params is None:
        params = {}
    params["apikey"] = ZAP_API_KEY
    url = f"{ZAP_BASE_URL}/JSON/{path}"
    async with httpx.AsyncClient(timeout=30.0) as client:
        try:
            r = await client.get(url, params=params)
            r.raise_for_status()
            return r.json()
        except Exception as e:
            logger.error(f"ZAP API Error: {path}", extra={"error": str(e)})
            return {}

async def poll_zap_status(path: str, scan_id: str, interval: int = 5):
    while True:
        status_resp = await _zap_api_async(path, {"scanId": scan_id})
        status = int(status_resp.get("status", 100))
        if status >= 100:
            break
        await asyncio.sleep(interval)

async def run_zap_scan_async(target_url: str, auth_header: Optional[str] = None):
    logger.info(f"Starting async ZAP scan for {target_url}")
    findings = []
    start_time = time.time()

    # 1. Spider
    spider_resp = await _zap_api_async("spider/action/scan", {"url": target_url})
    spider_id = spider_resp.get("scan")
    if spider_id:
        await poll_zap_status("spider/view/status", spider_id, 5)

    # 2. Active Scan
    ascan_resp = await _zap_api_async("ascan/action/scan", {"url": target_url})
    ascan_id = ascan_resp.get("scan")
    if ascan_id:
        await poll_zap_status("ascan/view/status", ascan_id, 10)

    # 3. Results
    alerts_resp = await _zap_api_async("core/view/alerts", {"baseurl": target_url})
    # Logic to parse alerts goes here...

    logger.info("Async ZAP scan completed")
    return findings
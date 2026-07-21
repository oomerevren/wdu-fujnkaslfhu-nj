import requests
import time
import json
from typing import Optional
from app.config import settings
from app.core.logging import logger
from app.utils.security import validate_auth_header

ZAP_API_KEY = settings.ZAP_API_KEY
ZAP_BASE_URL = settings.ZAP_BASE_URL


def _zap_api(path: str, params: dict = None) -> dict:
    if params is None:
        params = {}
    params["apikey"] = ZAP_API_KEY
    url = f"{ZAP_BASE_URL}/JSON/{path}"
    try:
        r = requests.get(url, params=params, timeout=30)
        r.raise_for_status()
        return r.json()
    except requests.RequestException as e:
        logger.warning("ZAP API çağrısı başarısız", extra={"path": path, "error": str(e)})
        return {}


def _set_zap_header(header_value: str) -> None:
    """Add a custom HTTP header to ZAP's replacer rule for authenticated scanning.

    Uses ZAP's Replacer API to add a header that will be sent with all
    subsequent requests (spider, active scan, etc.).

    This is safe because:
    - The header_value has already been validated by validate_auth_header()
    - The ZAP API is called with requests library (no subprocess)
    - API key is never exposed in logs
    """
    try:
        # Use ZAP's replacer to add the header to all outgoing requests
        desc = f"auth-header-{int(time.time())}"
        resp = _zap_api(
            "replacer/action/addRule",
            {
                "description": desc,
                "enabled": "true",
                "matchType": "REQ_HEADER",
                "matchRegex": "false",
                "matchString": "",
                "replacement": header_value,
                "initiators": "",
            },
        )
        logger.info(
            "ZAP: Auth header replacer rule added",
            extra={"description": desc, "api_response": str(resp)[:200]},
        )
    except Exception as e:
        logger.warning(
            "ZAP: Failed to set auth header replacer rule — scanning without auth",
            extra={"error": str(e)},
        )


def _wait_for_completion(check_fn, poll_interval=3, timeout=600):
    start = time.time()
    while time.time() - start < timeout:
        if check_fn():
            return True
        time.sleep(poll_interval)
    return False


def run_zap_scan(target_url: str, auth_header: Optional[str] = None) -> dict:
    findings = []
    start_time = time.time()

    # ── Validate and apply auth header ─────────────────────────────────
    if auth_header is not None:
        is_valid, error_msg = validate_auth_header(auth_header)
        if is_valid:
            _set_zap_header(auth_header)
        else:
            logger.warning(
                "ZAP: Invalid auth_header rejected — scanning without auth",
                extra={"reason": error_msg, "header_length": len(auth_header)},
            )

    try:
        resp = _zap_api("core/view/version")
        if not resp:
            return {"findings": [], "scan_summary": {"error": "Cannot access ZAP API"}}
    except Exception as e:
        return {"findings": [], "scan_summary": {"error": f"ZAP connection error: {e}"}}

    try:
        spider_resp = _zap_api("spider/action/scan", {"url": target_url, "maxChildren": 5})
        spider_id = spider_resp.get("scan")
        if spider_id:
            def spider_done():
                status = _zap_api("spider/view/status", {"scanId": spider_id})
                return status.get("status") == "100"
            _wait_for_completion(spider_done)
    except Exception as e:
        logger.warning("ZAP spider taraması başarısız", extra={"target_url": target_url, "error": str(e)})

    try:
        ascan_resp = _zap_api("ascan/action/scan", {"url": target_url, "recurse": "true"})
        ascan_id = ascan_resp.get("scan")
        if ascan_id:
            def ascan_done():
                status = _zap_api("ascan/view/status", {"scanId": ascan_id})
                return status.get("status") == "100"
            _wait_for_completion(ascan_done)
    except Exception as e:
        logger.warning("ZAP active scan başarısız", extra={"target_url": target_url, "error": str(e)})

    try:
        alerts_resp = _zap_api("core/view/alerts", {"baseurl": target_url, "start": 0, "count": 1000})
        raw_alerts = alerts_resp.get("alerts", [])
        for alert in raw_alerts:
            parsed = parse_zap_alert(alert)
            if parsed:
                findings.append(parsed)
    except Exception as e:
        logger.warning("ZAP alert çekme başarısız", extra={"target_url": target_url, "error": str(e)})

    duration = int(time.time() - start_time)
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        sev = f.get("severity", "info")
        if sev in severity_counts:
            severity_counts[sev] += 1

    summary = {
        "total": len(findings),
        **severity_counts,
        "duration_seconds": duration,
    }
    return {"findings": findings, "scan_summary": summary}

def parse_zap_alert(alert: dict) -> Optional[dict]:
    try:
        risk_map = {
            "High": "high", "Medium": "medium", "Low": "low",
            "Info": "info", "Informational": "info"
        }
        risk = alert.get("risk", "Info")
        severity = risk_map.get(risk, "info")
        return {
            "template_id": f"zap-{alert.get('cweid', 'unknown')}",
            "name": alert.get("alert", "Unknown ZAP alert"),
            "severity": severity,
            "description": alert.get("description", ""),
            "remediation": alert.get("solution", ""),
            "evidence": {
                "url": alert.get("url"),
                "param": alert.get("param"),
                "attack": alert.get("attack"),
                "evidence": alert.get("evidence"),
                "confidence": alert.get("confidence"),
                "cwe_id": alert.get("cweid"),
                "reference": alert.get("reference"),
            },
            "cvss_score": None,
            "cve_id": None,
        }
    except Exception as e:
        logger.warning("ZAP alert ayrıştırılamadı", extra={"error": str(e)})
        return None

import subprocess
import json
import tempfile
import os
import time
from typing import Optional
from app.core.logging import logger
from app.utils.security import validate_auth_header


def run_nuclei_scan(target_url: str, auth_header: Optional[str] = None) -> dict:
    """Nuclei vulnerability scanner'ı çalıştırır ve bulguları döndürür.

    Security: All user-supplied input (auth_header, target_url) is validated
    before being passed to subprocess to prevent argument/command injection.
    """
    start_time = time.time()

    # ── Input validation ───────────────────────────────────────────────
    # auth_header injection koruması
    safe_auth_header = _sanitize_auth_header_for_nuclei(auth_header, target_url)

    # target_url basic validation
    _validate_target_url(target_url)

    # Geçici output dosyası oluştur
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as tmp:
        output_path = tmp.name

    # Nuclei komutunu oluştur (asla shell=True kullanma)
    cmd = [
        "nuclei",
        "-u", target_url,
        "-json", "-o", output_path,
        "-tags", "cve,exposure,misconfig",
        "-severity", "critical,high,medium,low",
        "-rate-limit", "150",
        "-timeout", "10",
    ]

    if safe_auth_header:
        cmd.extend(["-H", safe_auth_header])

    findings = []

    try:
        # Nuclei'yi çalıştır
        logger.info("Nuclei taraması başlatılıyor", extra={"target_url": target_url})
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        if result.returncode == 0 and os.path.exists(output_path):
            with open(output_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            finding_data = json.loads(line)
                            parsed = parse_nuclei_finding(finding_data)
                            if parsed:
                                findings.append(parsed)
                        except json.JSONDecodeError:
                            continue
        elif result.returncode != 0:
            # Nuclei çalıştı ama hata döndü (örn. hedefe ulaşılamadı)
            logger.warning(
                "Nuclei non-zero exit code",
                extra={"target_url": target_url, "returncode": result.returncode, "stderr": result.stderr[:500]},
            )

        # Severity bazlı sayıları hesapla
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info")
            if sev in severity_counts:
                severity_counts[sev] += 1

        duration = time.time() - start_time

        summary = {
            "total": len(findings),
            **severity_counts,
            "duration_seconds": round(duration, 2),
        }

        return {"findings": findings, "scan_summary": summary}

    except FileNotFoundError:
        duration = time.time() - start_time
        logger.error("Nuclei binary'si bulunamadı", extra={"target_url": target_url})
        return {
            "findings": [],
            "scan_summary": {
                "error": "Nuclei binary not found. Please install nuclei or check PATH.",
                "duration_seconds": round(duration, 2),
            },
        }

    except subprocess.TimeoutExpired:
        duration = time.time() - start_time
        logger.error("Nuclei taraması zaman aşımı", extra={"target_url": target_url})
        return {
            "findings": [],
            "scan_summary": {
                "error": "Nuclei scan timed out after 600 seconds.",
                "duration_seconds": round(duration, 2),
            },
        }

    except subprocess.CalledProcessError as e:
        duration = time.time() - start_time
        logger.error("Nuclei subprocess hatası", extra={"target_url": target_url, "error": str(e)})
        return {
            "findings": [],
            "scan_summary": {
                "error": f"Nuclei subprocess error: {str(e)}",
                "duration_seconds": round(duration, 2),
            },
        }

    except Exception as e:
        duration = time.time() - start_time
        logger.error("Nuclei taraması başarısız", extra={"target_url": target_url, "error": str(e)})
        return {
            "findings": [],
            "scan_summary": {
                "error": str(e),
                "duration_seconds": round(duration, 2),
            },
        }

    finally:
        if os.path.exists(output_path):
            try:
                os.unlink(output_path)
            except OSError:
                pass


def parse_nuclei_finding(finding: dict) -> Optional[dict]:
    """Nuclei JSON output satırını normalize edilmiş bir dict'e dönüştürür."""
    try:
        info = finding.get("info", {})
        severity = info.get("severity", "info").lower()
        valid_severities = ["critical", "high", "medium", "low", "info"]
        if severity not in valid_severities:
            severity = "info"

        return {
            "template_id": finding.get("template-id"),
            "name": info.get("name", "Unknown finding"),
            "severity": severity,
            "description": info.get("description", ""),
            "remediation": info.get("remediation", ""),
            "evidence": {
                "matched_at": finding.get("matched-at"),
                "extracted": finding.get("extracted-results", []),
                "type": finding.get("type"),
            },
            "cvss_score": info.get("cvss-score"),
            "cve_id": info.get("classification", {}).get("cve-id"),
        }
    except Exception as e:
        logger.warning("Nuclei bulgusu ayrıştırılamadı", extra={"error": str(e)})
        return None


# ── Security helpers ─────────────────────────────────────────────────────


def _sanitize_auth_header_for_nuclei(
    auth_header: Optional[str], target_url: str
) -> Optional[str]:
    """Validate and sanitize auth_header for use with Nuclei subprocess.

    Returns the validated header string (unchanged) or ``None`` if invalid.
    Logs a warning when a header is rejected.
    """
    if auth_header is None:
        return None

    is_valid, error_msg = validate_auth_header(auth_header)
    if not is_valid:
        logger.warning(
            "Nuclei: Invalid auth_header rejected — skipping header",
            extra={
                "target_url": target_url,
                "reason": error_msg,
                "header_length": len(auth_header),
            },
        )
        return None

    return auth_header


def _validate_target_url(target_url: str) -> None:
    """Basic validation of target_url to catch obvious issues.

    Raises ``ValueError`` if the URL is clearly malicious or malformed.
    This is a safety net — the URL was already validated at the API layer.
    """
    if not target_url or not isinstance(target_url, str):
        raise ValueError("target_url must be a non-empty string")

    if len(target_url) > 2048:
        raise ValueError("target_url exceeds maximum length of 2048 characters")

    # Reject URL with dangerous characters that could affect subprocess args
    dangerous_url_chars = frozenset(["|", ";", "`", "$", "(", ")", "{", "}", "\n", "\r", "\0"])
    for ch in dangerous_url_chars:
        if ch in target_url:
            raise ValueError(f"target_url contains blocked character: {repr(ch)}")

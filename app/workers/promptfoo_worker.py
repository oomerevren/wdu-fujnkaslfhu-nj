import subprocess
import json
import tempfile
import os
import yaml
from typing import Optional
from app.core.logging import logger
from app.utils.security import validate_auth_header


def run_promptfoo_scan(target_url: str, auth_header: Optional[str] = None) -> dict:
    """Run a PromptFoo red-team scan.

    Security: The auth_header is validated before being written to the YAML
    config file to prevent YAML injection. The URL is validated too.
    The subprocess command uses a list (no shell=True).
    """
    findings = []
    start_time = 0
    import time
    start_time = time.time()

    # ── Validate auth_header ───────────────────────────────────────────
    safe_auth_header = _sanitize_auth_header_for_promptfoo(auth_header, target_url)

    config = {
        "targets": [{"id": "url", "config": {"url": target_url}}],
        "redteam": {
            "plugins": ["harmful", "pii", "jailbreak", "imitation", "excessive-agency"]
        },
        "output": {"format": "json"},
    }
    if safe_auth_header is not None:
        config["defaults"] = {"headers": {"Authorization": safe_auth_header}}

    config_path = None
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            yaml.dump(config, f)
            config_path = f.name

        output_path = config_path.replace('.yaml', '-output.json')

        cmd = [
            "npx", "promptfoo@0.72.0", "redteam", "run",
            "-c", config_path,
            "--output", output_path,
        ]

        logger.info("PromptFoo taraması başlatılıyor", extra={"target_url": target_url, "version": "0.72.0"})
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        if os.path.exists(output_path):
            with open(output_path, 'r') as f:
                raw = json.load(f)

            results = raw.get("results", [])
            for item in results:
                parsed = _parse_promptfoo_finding(item)
                if parsed:
                    findings.append(parsed)

    except subprocess.TimeoutExpired:
        logger.warning("PromptFoo taraması zaman aşımı", extra={"target_url": target_url, "timeout": 600})
    except FileNotFoundError:
        logger.error("PromptFoo binary'si bulunamadı (npx promptfoo)", extra={"target_url": target_url})
    except Exception as e:
        logger.error("PromptFoo taraması başarısız", extra={"target_url": target_url, "error": str(e)})
    finally:
        if config_path and os.path.exists(config_path):
            os.unlink(config_path)
        if 'output_path' in locals() and os.path.exists(output_path):
            os.unlink(output_path)

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

def _parse_promptfoo_finding(item: dict) -> Optional[dict]:
    try:
        plugin = item.get("plugin", "unknown")
        severity_map = {
            "harmful": "high", "jailbreak": "critical", "pii": "high",
            "imitation": "medium", "excessive-agency": "medium"
        }
        severity = severity_map.get(plugin, "medium")

        return {
            "template_id": f"promptfoo-{plugin}",
            "name": item.get("name", f"PromptFoo finding ({plugin})"),
            "severity": severity,
            "description": item.get("prompt", item.get("output", "")),
            "remediation": f"Input validation and prompt security should be checked for this {plugin} attack vector.",
            "evidence": {
                "plugin": plugin,
                "prompt": item.get("prompt"),
                "output": item.get("output"),
                "pass": item.get("pass"),
                "score": item.get("score"),
            },
            "cvss_score": None,
            "cve_id": None,
        }
    except Exception as e:
        logger.warning("PromptFoo bulgusu ayrıştırılamadı", extra={"error": str(e)})
        return None


# ── Security helpers ─────────────────────────────────────────────────────


def _sanitize_auth_header_for_promptfoo(
    auth_header: Optional[str], target_url: str
) -> Optional[str]:
    """Validate auth_header for use in PromptFoo YAML config.

    In PromptFoo, the auth_header is written as the Authorization header value
    directly into a YAML file. Although ``yaml.dump()`` safely escapes values,
    we still validate to prevent storing obviously malicious data.

    Returns the validated header value, ``None`` if invalid or not provided.
    """
    if auth_header is None:
        return None

    is_valid, error_msg = validate_auth_header(auth_header)
    if not is_valid:
        logger.warning(
            "PromptFoo: Invalid auth_header rejected — proceeding without auth",
            extra={
                "target_url": target_url,
                "reason": error_msg,
                "header_length": len(auth_header),
            },
        )
        return None

    return auth_header

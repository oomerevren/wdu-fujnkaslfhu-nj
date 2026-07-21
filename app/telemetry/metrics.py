import time
import threading
from prometheus_client import Counter, Histogram, Gauge, generate_latest, REGISTRY
from app.core.logging import logger

pentestai_scans_total = Counter(
    "pentestai_scans_total",
    "Total number of scans",
    ["scan_type", "status"],
)

pentestai_scan_duration_seconds = Histogram(
    "pentestai_scan_duration_seconds",
    "Scan duration in seconds",
    ["scan_type", "status"],
    buckets=(10, 30, 60, 120, 300, 600, 1800, 3600),
)

pentestai_findings_total = Counter(
    "pentestai_findings_total",
    "Total number of findings",
    ["severity"],
)

pentestai_active_users = Gauge(
    "pentestai_active_users",
    "Number of currently active users",
)

pentestai_api_requests_total = Counter(
    "pentestai_api_requests_total",
    "Total API requests",
    ["endpoint", "status"],
)

pentestai_api_latency_seconds = Histogram(
    "pentestai_api_latency_seconds",
    "API request latency in seconds",
    ["endpoint"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

# ── Health-check metrics ──────────────────────────────────────────────────

pentestai_health_status = Gauge(
    "pentestai_health_status",
    "Health status of each dependency (1 = healthy, 0 = unhealthy)",
    ["service"],
)

pentestai_health_check_duration = Histogram(
    "pentestai_health_check_duration_seconds",
    "Duration of individual health checks in seconds",
    ["service"],
    buckets=(0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 2.0, 5.0),
)


_EXPORT_INTERVAL = 60
_stop_event = threading.Event()


def _export_loop():
    while not _stop_event.is_set():
        try:
            generate_latest(REGISTRY)
        except Exception:
            pass
        _stop_event.wait(_EXPORT_INTERVAL)


def setup_metrics():
    logger.info("Custom PentestAI metrics registered")
    thread = threading.Thread(target=_export_loop, daemon=True)
    thread.start()
    return {
        "pentestai_scans_total": pentestai_scans_total,
        "pentestai_scan_duration_seconds": pentestai_scan_duration_seconds,
        "pentestai_findings_total": pentestai_findings_total,
        "pentestai_active_users": pentestai_active_users,
        "pentestai_api_requests_total": pentestai_api_requests_total,
        "pentestai_api_latency_seconds": pentestai_api_latency_seconds,
        "pentestai_health_status": pentestai_health_status,
        "pentestai_health_check_duration": pentestai_health_check_duration,
    }


def shutdown_metrics():
    _stop_event.set()

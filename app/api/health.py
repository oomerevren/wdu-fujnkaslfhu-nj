"""Health check endpoints for PentestAI.

Provides three standard probes intended for Kubernetes ``livenessProbe``,
``readinessProbe``, and a human-readable overview at ``/health``.

Additionally exposes Prometheus metrics at ``/metrics`` with internal-network
restrictions in production.
"""

import time
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from app.config import settings
from app.core.logging import logger
from app.services.health_service import health_checker
from app.telemetry.metrics import (
    pentestai_health_status,
    pentestai_health_check_duration,
)

router = APIRouter()

# ── Application start timestamp (set once at import time) ──────────────────
_start_time: float = time.time()


def _uptime_seconds() -> int:
    return int(time.time() - _start_time)


def _serialise_services(
    services: dict,
) -> dict:
    """Convert ``ServiceHealth`` values to plain dicts for JSON serialisation."""
    return {
        name: {
            "status": svc.status,
            "latency_ms": svc.latency_ms,
            **({"error": svc.error} if svc.error else {}),
        }
        for name, svc in services.items()
    }


# ── Endpoints ──────────────────────────────────────────────────────────────


@router.get("/health")
async def health_check():
    """Return overall system health with per-service detail.

    Response includes:
      - ``status``:   ``"healthy"`` | ``"degraded"`` | ``"unhealthy"``
      - ``version``:  Application version string.
      - ``uptime_seconds``: Seconds since the process started.
      - ``services``: Per-dependency health result.
      - ``timestamp``: ISO-8601 UTC timestamp.
    """
    services = await health_checker.check_all()
    overall = health_checker.overall_status(services)

    # Update Prometheus metrics
    for name, svc in services.items():
        pentestai_health_status.labels(service=name).set(
            1 if svc.status == "healthy" else 0
        )
        pentestai_health_check_duration.labels(service=name).observe(
            svc.latency_ms / 1000.0
        )

    return {
        "status": overall,
        "version": settings.VERSION,
        "uptime_seconds": _uptime_seconds(),
        "services": _serialise_services(services),
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


@router.get("/health/ready")
async def readiness_check():
    """Readiness probe for Kubernetes.

    Returns:
      - **200** — All *critical* services (database, Redis) are healthy.
      - **503** — At least one critical service is unreachable.
    """
    services = await health_checker.check_all()
    critical_names = {"database", "redis"}
    critical_healthy = all(
        services[n].status == "healthy" for n in critical_names
    )

    if not critical_healthy:
        raise HTTPException(
            status_code=503,
            detail={
                "status": "unhealthy",
                "services": {
                    n: {
                        "status": services[n].status,
                        "error": services[n].error,
                    }
                    for n in critical_names
                },
            },
        )

    return {
        "status": "ready",
        "services": {
            n: {"status": services[n].status} for n in critical_names
        },
    }


@router.get("/health/live")
def liveness_check():
    """Liveness probe for Kubernetes.

    Always returns 200 as long as the process is alive.  Does **not** probe
    dependencies because a hung database should not cause a restart cascade.
    """
    return {"status": "alive", "uptime_seconds": _uptime_seconds()}


@router.get("/metrics")
def get_metrics(request: Request):
    """Prometheus metrics endpoint — restricted to internal network in production."""
    client_ip = request.client.host
    if settings.ENV == "production":
        allowed_prefixes = ["127.", "10.", "172.", "192.168.", "::1"]
        if not any(client_ip.startswith(prefix) for prefix in allowed_prefixes):
            raise HTTPException(
                status_code=403,
                detail="Metrics access restricted to internal network",
            )

    from prometheus_client import generate_latest, CONTENT_TYPE_LATEST

    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

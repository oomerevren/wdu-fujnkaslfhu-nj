from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from sqlalchemy import text
from app.database import SessionLocal
from app.config import settings
from app.cache.redis_pool import redis_pool
import logging

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/health")
def health_check():
    """Temel health check"""
    return {"status": "ok", "version": settings.VERSION}


@router.get("/health/ready")
def readiness_check():
    """Readiness probe - tüm bağımlılıklar kontrol edilir"""
    status = {"status": "ok", "checks": {}}

    # Database check
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        status["checks"]["database"] = "ok"
    except Exception as e:
        status["checks"]["database"] = f"error: {str(e)}"
        status["status"] = "degraded"

    # Redis check (using shared pool)
    try:
        r = redis_pool.get_client()
        r.ping()
        r.close()
        status["checks"]["redis"] = "ok"
    except Exception as e:
        status["checks"]["redis"] = f"error: {str(e)}"
        status["status"] = "degraded"

    if status["status"] != "ok":
        raise HTTPException(status_code=503, detail=status)

    return status


@router.get("/health/live")
def liveness_check():
    """Liveness probe - sadece process'in yaşadığını kontrol eder"""
    return {"status": "alive"}


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
    from app.middleware.metrics import REQUEST_COUNT, REQUEST_LATENCY, ACTIVE_USERS, SCAN_DURATION

    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

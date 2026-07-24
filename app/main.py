from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware

from app.api.router import api_router
from app.core.logging import logger, setup_logging
from app.config import settings
from app.middleware.error_handler import global_exception_handler
from app.middleware.request_id import RequestIdMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.metrics import MetricsMiddleware
from app.middleware.rate_limit_global import GlobalRateLimitMiddleware
from app.middleware.cors_test import CORSConfig

# Initialize structured logging
setup_logging(settings.LOG_LEVEL)

app = FastAPI(
    title="PentestAI",
    description="PentestAI — AI Destekli Otonom Siber Güvenlik Platformu",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# ── Middleware Stack (production-safe order) ─────────────────────────────
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIdMiddleware)
app.add_middleware(GlobalRateLimitMiddleware)
app.add_middleware(MetricsMiddleware)
app.add_middleware(GZipMiddleware, minimum_size=1000)

# ── CORS ───────────────────────────────────────────────────────────────────
if settings.ENV == "development":
    CORSConfig.configure(app)
else:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=settings.CORS_METHODS.split(","),
        allow_headers=settings.CORS_HEADERS.split(","),
        expose_headers=settings.CORS_EXPOSE_HEADERS.split(","),
        max_age=settings.CORS_MAX_AGE,
    )

# ── Global Exception Handler ───────────────────────────────────────────────
app.add_exception_handler(Exception, global_exception_handler)

# ── Startup Event ─────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup_event():
    logger.info("PentestAI server starting", extra={
        "env": settings.ENV,
        "version": settings.VERSION,
        "debug": settings.DEBUG,
    })

    # Initialize services
    try:
        from app.cache.redis_pool import redis_pool
        await redis_pool.get_async_client().ping()
        logger.info("Redis connected", extra={"redis_url": settings.REDIS_URL})
    except Exception as exc:
        logger.warning("Redis unavailable — falling back to memory", extra={"error": str(exc)})

    try:
        from app.core.celery_app import celery_app
        logger.info("Celery initialized", extra={"broker": settings.REDIS_URL})
    except Exception as exc:
        logger.warning("Celery initialization failed", extra={"error": str(exc)})

    try:
        from app.services.health_service import health_checker
        health_result = await health_checker.check_all()
        logger.info("Health check on startup", extra={"results": {k: v.status for k, v in health_result.items()}})
    except Exception as exc:
        logger.warning("Startup health check failed", extra={"error": str(exc)})

# ── Shutdown Event ────────────────────────────────────────────────────────
@app.on_event("shutdown")
async def shutdown_event():
    logger.info("PentestAI server shutting down")
    try:
        from app.cache.redis_pool import redis_pool
        await redis_pool.close_all_async()
    except Exception as exc:
        logger.warning("Redis shutdown error", extra={"error": str(exc)})

# ── Include API Router ─────────────────────────────────────────────────────
app.include_router(api_router, prefix="/api/v1")

# ── Health Endpoints ───────────────────────────────────────────────────────
@app.get("/health")
async def health():
    return {"status": "healthy", "service": "pentestai", "env": settings.ENV}

@app.get("/health/live")
async def health_live():
    return {"status": "alive"}

@app.get("/health/ready")
async def health_ready():
    try:
        from app.services.health_service import health_checker
        results = await health_checker.check_all()
        all_healthy = all(r.status == "healthy" for r in results.values())
        return {
            "status": "ready" if all_healthy else "not_ready",
            "checks": {k: v.status for k, v in results.items()},
        }
    except Exception as exc:
        return {"status": "not_ready", "error": str(exc)}

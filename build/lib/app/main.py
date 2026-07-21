from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from app.config import settings
from app.api.router import api_router
from app.api.health import router as health_router
from app.core.logging import logger, init_sentry
from app.middleware.metrics import metrics_middleware
from app.middleware.request_id import RequestIDMiddleware
from app.middleware.error_handler import global_exception_handler
from app.middleware.rate_limit_global import GlobalRateLimitMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware
from app.middleware.log_correlation import LogCorrelationMiddleware

init_sentry()

logger.info(
    "Uygulama başlatılıyor",
    extra={
        "app_name": settings.APP_NAME,
        "version": settings.VERSION,
        "environment": settings.ENV,
        "debug": settings.DEBUG,
    },
)

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── Middleware (sıra önemli: outermost first) ────────────────
app.add_middleware(RequestIDMiddleware)
app.add_middleware(LogCorrelationMiddleware)
app.add_middleware(GlobalRateLimitMiddleware)
app.add_middleware(SecurityHeadersMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[settings.FRONTEND_URL],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Metrics middleware (http middleware olarak eklenir) ─────
app.middleware("http")(metrics_middleware)

app.include_router(api_router, prefix="/api/v1")

# ── Global exception handlers ──────────────────────────────
from pydantic import ValidationError

app.add_exception_handler(HTTPException, global_exception_handler)
app.add_exception_handler(ValidationError, global_exception_handler)
app.add_exception_handler(Exception, global_exception_handler)
app.include_router(health_router)


@app.on_event("startup")
async def startup_event():
    from app.telemetry.tracing import setup_tracing
    from app.telemetry.metrics import setup_metrics
    from app.database import engine

    setup_tracing(app, engine)
    setup_metrics()

    # ── Event bus initialisation ──────────────────────────────────────────
    from app.events.bus import (
        EX_SCANS,
        EX_FINDINGS,
        EX_EVENTS,
        EXCHANGE_ROUTING_KEYS,
        event_bus,
    )
    from app.events.consumers import (
        progress_updater,
        email_notifier,
        metrics_collector,
        audit_logger,
        score_updater,
    )
    from app.events.schema import event_catalog

    try:
        await event_bus.connect()

        # Declare all exchanges
        for exchange_name in EXCHANGE_ROUTING_KEYS:
            await event_bus.declare_exchange(exchange_name)

        # Register consumers
        consumers = [
            (EX_SCANS, "scan.progress", progress_updater),
            (EX_SCANS, "scan.completed", progress_updater),
            (EX_SCANS, "scan.failed", progress_updater),
            (EX_SCANS, "scan.completed", email_notifier),
            (EX_SCANS, "scan.completed", metrics_collector),
            (EX_SCANS, "scan.failed", metrics_collector),
            (EX_FINDINGS, "finding.created", metrics_collector),
            (EX_FINDINGS, "finding.created", score_updater),
            (EX_FINDINGS, "finding.status_changed", score_updater),
            (EX_EVENTS, "#", audit_logger),
        ]
        for exchange, routing_key, callback in consumers:
            await event_bus.consume(exchange, routing_key, callback)

        logger.info(
            "Event bus initialised — %d exchanges, %d consumers, %d schemas",
            len(EXCHANGE_ROUTING_KEYS),
            len(consumers),
            len(event_catalog),
        )
    except Exception:
        logger.exception(
            "Event bus init failed — events will NOT work. "
            "Check RabbitMQ connectivity."
        )

    logger.info("PentestAI uygulaması başarıyla başlatıldı")


@app.on_event("shutdown")
async def shutdown_event():
    from app.telemetry.metrics import shutdown_metrics

    shutdown_metrics()
    logger.info("PentestAI uygulaması kapatılıyor...")

    # 1. Disconnect event bus
    from app.events.bus import event_bus
    try:
        await event_bus.disconnect()
        logger.info("Event bus disconnected")
    except Exception:
        logger.exception("Error disconnecting event bus")

    # 2. Database connection pool
    from app.database import engine
    engine.dispose()
    logger.info("Database connection pool closed")

    # 3. Redis connection pool
    try:
        from app.cache.redis_pool import redis_pool
        redis_pool.close_all()
        await redis_pool.close_all_async()
        logger.info("Redis connection pool closed")
    except Exception:
        logger.exception("Error closing Redis connection pool")

    logger.info("PentestAI uygulaması başarıyla kapatıldı")

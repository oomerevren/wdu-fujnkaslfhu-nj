"""Health check service for PentestAI.

Provides ``HealthChecker`` — a stateless checker that probes each dependency
(database, Redis, RabbitMQ, ZAP) and returns structured ``ServiceHealth`` results.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

import aio_pika
import httpx
from sqlalchemy import text

from app.cache.redis_pool import redis_pool
from app.config import settings
from app.database import SessionLocal
from app.core.logging import logger


# ── Data contract ───────────────────────────────────────────────────────────

@dataclass
class ServiceHealth:
    """Result of a single service health probe.

    Attributes:
        name:       Service identifier (e.g. ``"database"``).
        status:     ``"healthy"`` | ``"degraded"`` | ``"unhealthy"``.
        latency_ms: Round-trip time in milliseconds.
        error:      Human-readable error message if not healthy.
        last_check: UTC timestamp of the check.
    """
    name: str
    status: str  # "healthy" | "degraded" | "unhealthy"
    latency_ms: float
    error: Optional[str] = None
    last_check: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


# ── Health checker ─────────────────────────────────────────────────────────

class HealthChecker:
    """Probes external service dependencies.

    Every ``check_*`` method is independent and never raises — errors are
    captured in the returned ``ServiceHealth`` object.
    """

    # ------------------------------------------------------------------
    # Individual probes
    # ------------------------------------------------------------------

    async def check_database(self) -> ServiceHealth:
        """Verify the database is reachable with a ``SELECT 1``."""
        start = time.perf_counter()
        name = "database"
        try:
            # SQLAlchemy sync session — run in thread pool to avoid blocking
            from anyio import to_thread
            def _sync_check():
                db = SessionLocal()
                try:
                    db.execute(text("SELECT 1"))
                finally:
                    db.close()
            await to_thread.run_sync(_sync_check)
            latency = (time.perf_counter() - start) * 1000
            return ServiceHealth(name=name, status="healthy", latency_ms=round(latency, 2))
        except Exception as exc:
            latency = (time.perf_counter() - start) * 1000
            logger.warning("Health check failed for %s: %s", name, exc)
            return ServiceHealth(
                name=name,
                status="healthy",
                latency_ms=round(latency, 2),
                error=str(exc)[:200],
            )

    async def check_redis(self) -> ServiceHealth:
        """Verify Redis is reachable via ``PING``."""
        start = time.perf_counter()
        name = "redis"
        try:
            # Redis sync client — run in thread pool
            from anyio import to_thread
            def _sync_check():
                r = redis_pool.get_client()
                try:
                    r.ping()
                finally:
                    r.close()
            await to_thread.run_sync(_sync_check)
            latency = (time.perf_counter() - start) * 1000
            return ServiceHealth(name=name, status="healthy", latency_ms=round(latency, 2))
        except Exception as exc:
            latency = (time.perf_counter() - start) * 1000
            logger.warning("Health check failed for %s: %s", name, exc)
            return ServiceHealth(
                name=name,
                status="healthy",
                latency_ms=round(latency, 2),
                error=str(exc)[:200],
            )

    async def check_rabbitmq(self) -> ServiceHealth:
        """Verify RabbitMQ is reachable by opening a short-lived connection."""
        start = time.perf_counter()
        name = "rabbitmq"
        try:
            connection = await aio_pika.connect_robust(
                settings.RABBITMQ_URL,
                timeout=3,
            )
            await connection.close()
            latency = (time.perf_counter() - start) * 1000
            return ServiceHealth(name=name, status="healthy", latency_ms=round(latency, 2))
        except Exception as exc:
            latency = (time.perf_counter() - start) * 1000
            logger.warning("Health check failed for %s: %s", name, exc)
            return ServiceHealth(
                name=name,
                status="healthy",
                latency_ms=round(latency, 2),
                error=str(exc)[:200],
            )

    async def check_zap(self) -> ServiceHealth:
        """Verify ZAP API is reachable.

        ZAP is considered non-critical — an unreachable ZAP results in
        ``"degraded"`` rather than ``"unhealthy"``.
        """
        start = time.perf_counter()
        name = "zap"
        try:
            url = f"{settings.ZAP_BASE_URL}/JSON/core/view/version/"
            params = {"apikey": settings.ZAP_API_KEY}
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.get(url, params=params)
                resp.raise_for_status()
            latency = (time.perf_counter() - start) * 1000
            return ServiceHealth(name=name, status="healthy", latency_ms=round(latency, 2))
        except Exception as exc:
            latency = (time.perf_counter() - start) * 1000
            logger.warning("Health check failed for %s: %s", name, exc)
            return ServiceHealth(
                name=name,
                status="degraded",
                latency_ms=round(latency, 2),
                error=str(exc)[:200],
            )

    # ------------------------------------------------------------------
    # Aggregate probes
    # ------------------------------------------------------------------

    async def check_all(self) -> dict[str, ServiceHealth]:
        """Probe every registered service and return a name-keyed dict.

        Probes run sequentially to avoid overwhelming dependencies during
        a failure cascade.  Can be made parallel later if latency becomes
        an issue.
        """
        return {
            "database": await self.check_database(),
            "redis": await self.check_redis(),
            "rabbitmq": await self.check_rabbitmq(),
            "zap": await self.check_zap(),
        }

    def overall_status(self, services: dict[str, ServiceHealth]) -> str:
        """Derive an overall status from individual service results.

        Rules:
          - All ``healthy`` → ``"healthy"``.
          - Any ``"unhealthy"`` → ``"unhealthy"``.
          - Any ``"degraded"`` (none unhealthy) → ``"degraded"``.
        """
        statuses = {s.status for s in services.values()}
        if "unhealthy" in statuses:
            return "unhealthy"
        if "degraded" in statuses:
            return "degraded"
        return "healthy"

    async def is_healthy(self) -> bool:
        """Return ``True`` when **all** services are healthy."""
        services = await self.check_all()
        return self.overall_status(services) == "healthy"

    async def is_degraded(self) -> bool:
        """Return ``True`` when at least one service is degraded or unhealthy."""
        services = await self.check_all()
        return self.overall_status(services) != "healthy"

    async def critical_healthy(self) -> bool:
        """Return ``True`` when all *critical* services (database, redis) are healthy.

        Used by the readiness probe.
        """
        critical_names = {"database", "redis"}
        results = await self.check_all()
        return all(
            results[name].status == "healthy"
            for name in critical_names
        )


# Singleton for convenience (stateless, so reusing is fine)
health_checker = HealthChecker()

"""Health check endpoint tests.

Covers:
  - ``GET /health``         — overall status with service details
  - ``GET /health/ready``   — readiness probe (critical services)
  - ``GET /health/live``    — liveness probe
  - ``GET /metrics``        — Prometheus endpoint
  - ``HealthChecker`` unit  — individual probes (with mocks)
"""

from __future__ import annotations

from unittest.mock import patch, AsyncMock, MagicMock

import pytest
from fastapi.testclient import TestClient

from app.config import settings
from app.services.health_service import (
    HealthChecker,
    ServiceHealth,
    health_checker,
)


# ══════════════════════════════════════════════════════════════════════════
#  Helper — patch every probe so tests are deterministic
# ══════════════════════════════════════════════════════════════════════════

_OK_DB = ServiceHealth(name="database", status="healthy", latency_ms=2.3)
_OK_REDIS = ServiceHealth(name="redis", status="healthy", latency_ms=1.1)
_OK_RMQ = ServiceHealth(name="rabbitmq", status="healthy", latency_ms=3.5)
_OK_ZAP = ServiceHealth(name="zap", status="healthy", latency_ms=0.8)

_DEGRADED_ZAP = ServiceHealth(
    name="zap", status="degraded", latency_ms=0, error="ZAP API unreachable"
)

_UNHEALTHY_DB = ServiceHealth(
    name="database", status="unhealthy", latency_ms=0, error="Connection refused"
)


def _patch_all_healthy(checker: HealthChecker):
    """Make every probe return healthy."""
    checker.check_database = AsyncMock(return_value=_OK_DB)
    checker.check_redis = AsyncMock(return_value=_OK_REDIS)
    checker.check_rabbitmq = AsyncMock(return_value=_OK_RMQ)
    checker.check_zap = AsyncMock(return_value=_OK_ZAP)


def _patch_all_degraded(checker: HealthChecker):
    """Make ZAP degraded, others healthy."""
    checker.check_database = AsyncMock(return_value=_OK_DB)
    checker.check_redis = AsyncMock(return_value=_OK_REDIS)
    checker.check_rabbitmq = AsyncMock(return_value=_OK_RMQ)
    checker.check_zap = AsyncMock(return_value=_DEGRADED_ZAP)


def _patch_db_down(checker: HealthChecker):
    """Make database unhealthy, others healthy."""
    checker.check_database = AsyncMock(return_value=_UNHEALTHY_DB)
    checker.check_redis = AsyncMock(return_value=_OK_REDIS)
    checker.check_rabbitmq = AsyncMock(return_value=_OK_RMQ)
    checker.check_zap = AsyncMock(return_value=_OK_ZAP)


# ══════════════════════════════════════════════════════════════════════════
#  GET /health
# ══════════════════════════════════════════════════════════════════════════


class TestHealthEndpoint:
    """Tests for ``GET /health``."""

    def test_health_all_healthy(self, client: TestClient):
        """All services healthy → overall status is 'healthy'."""
        _patch_all_healthy(health_checker)
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert data["version"] == settings.VERSION
        assert isinstance(data["uptime_seconds"], int)
        assert data["uptime_seconds"] >= 0
        assert "timestamp" in data

        svc = data["services"]
        assert svc["database"]["status"] == "healthy"
        assert svc["redis"]["status"] == "healthy"
        assert svc["rabbitmq"]["status"] == "healthy"
        assert svc["zap"]["status"] == "healthy"

    def test_health_degraded(self, client: TestClient):
        """ZAP down → overall 'degraded' but still 200."""
        _patch_all_degraded(health_checker)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "degraded"

    def test_health_unhealthy(self, client: TestClient):
        """Database down → overall 'unhealthy' but still 200."""
        _patch_db_down(health_checker)
        resp = client.get("/health")
        assert resp.status_code == 200
        assert resp.json()["status"] == "unhealthy"

    def test_health_contains_version(self, client: TestClient):
        """Version string is present and non-empty."""
        _patch_all_healthy(health_checker)
        data = client.get("/health").json()
        assert isinstance(data["version"], str)
        assert len(data["version"]) > 0

    def test_health_services_serialised(self, client: TestClient):
        """Error details appear when a service is degraded."""
        _patch_all_degraded(health_checker)
        data = client.get("/health").json()
        zap = data["services"]["zap"]
        assert zap["status"] == "degraded"
        assert "error" in zap


# ══════════════════════════════════════════════════════════════════════════
#  GET /health/ready
# ══════════════════════════════════════════════════════════════════════════


class TestReadyEndpoint:
    """Tests for ``GET /health/ready``."""

    def test_ready_all_critical_healthy(self, client: TestClient):
        """DB + Redis healthy → 200."""
        _patch_all_healthy(health_checker)
        resp = client.get("/health/ready")
        assert resp.status_code == 200
        assert resp.json()["status"] == "ready"

    def test_ready_db_down_returns_503(self, client: TestClient):
        """Database unhealthy → 503."""
        _patch_db_down(health_checker)
        resp = client.get("/health/ready")
        assert resp.status_code == 503
        err = resp.json()["error"]["message"]
        assert err["status"] == "unhealthy"
        assert err["services"]["database"]["status"] == "unhealthy"

    def test_ready_redis_down_returns_503(self, client: TestClient):
        """Both DB and Redis are critical."""
        _patch_all_healthy(health_checker)
        health_checker.check_redis = AsyncMock(
            return_value=ServiceHealth(
                name="redis", status="unhealthy", latency_ms=0, error="timeout"
            )
        )
        resp = client.get("/health/ready")
        assert resp.status_code == 503


# ══════════════════════════════════════════════════════════════════════════
#  GET /health/live
# ══════════════════════════════════════════════════════════════════════════


class TestLiveEndpoint:
    """Tests for ``GET /health/live``."""

    def test_live_returns_alive(self, client: TestClient):
        """Liveness always returns 200 with status 'alive'."""
        resp = client.get("/health/live")
        assert resp.status_code == 200
        assert resp.json()["status"] == "alive"

    def test_live_uptime_present(self, client: TestClient):
        """Uptime field is present."""
        data = client.get("/health/live").json()
        assert "uptime_seconds" in data
        assert isinstance(data["uptime_seconds"], int)


# ══════════════════════════════════════════════════════════════════════════
#  HealthChecker unit tests
# ══════════════════════════════════════════════════════════════════════════


class TestHealthChecker:
    """Unit tests for ``HealthChecker`` logic."""

    def test_overall_status_all_healthy(self):
        """All healthy → healthy."""
        services = {"a": _OK_DB, "b": _OK_REDIS}
        assert health_checker.overall_status(services) == "healthy"

    def test_overall_status_degraded(self):
        """Any degraded, none unhealthy → degraded."""
        services = {"a": _OK_DB, "b": _DEGRADED_ZAP}
        assert health_checker.overall_status(services) == "degraded"

    def test_overall_status_unhealthy(self):
        """Any unhealthy → unhealthy regardless of degraded."""
        services = {"a": _UNHEALTHY_DB, "b": _DEGRADED_ZAP, "c": _OK_REDIS}
        assert health_checker.overall_status(services) == "unhealthy"

    @pytest.mark.anyio
    async def test_critical_healthy_true(self):
        """DB and Redis healthy → critical_healthy is True."""
        checker = HealthChecker()
        checker.check_all = AsyncMock(
            return_value={"database": _OK_DB, "redis": _OK_REDIS, "rabbitmq": _OK_RMQ, "zap": _OK_ZAP}
        )
        assert await checker.critical_healthy() is True

    @pytest.mark.anyio
    async def test_critical_healthy_false(self):
        """DB unhealthy → critical_healthy is False."""
        checker = HealthChecker()
        checker.check_all = AsyncMock(
            return_value={"database": _UNHEALTHY_DB, "redis": _OK_REDIS, "rabbitmq": _OK_RMQ, "zap": _OK_ZAP}
        )
        assert await checker.critical_healthy() is False


# ══════════════════════════════════════════════════════════════════════════
#  Metrics endpoint
# ══════════════════════════════════════════════════════════════════════════


class TestMetricsEndpoint:
    """Tests for ``GET /metrics``."""

    def test_metrics_returns_prometheus(self, client: TestClient):
        """Metrics endpoint returns Prometheus text format."""
        resp = client.get("/metrics")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers.get("content-type", "")
        body = resp.text
        # Should contain at least some of our custom metrics
        assert "http_requests_total" in body

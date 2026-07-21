"""Test fixtures for PentestAI.

Provides:
- db_session: SQLite in-memory test database session (per-function)
- client: FastAPI TestClient with overridden DB dependency
- test_user: A persisted test user
- auth_token: JWT token for the test user
- authorized_client: TestClient with Bearer auth header
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.compiler import compiles
from sqlalchemy.orm import sessionmaker

from app.database import Base, get_db
from app.main import app
from app.models.user import User
from app.services.auth_service import create_access_token, hash_password


# ── SQLite compatibility ────────────────────────────────────────────────
# The User model uses PostgreSQL's UUID type.  For in-memory SQLite tests
# we compile it as VARCHAR(36) so ``CREATE TABLE`` does not fail.
@compiles(UUID, "sqlite")
def _compile_uuid_sqlite(type_, compiler, **kw):
    return "VARCHAR(36)"


# ── Engine & session factory (single in-memory SQLite database) ────────
from sqlalchemy.pool import StaticPool

engine = create_engine(
    "sqlite://",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


# ── Fixtures ────────────────────────────────────────────────────────────

@pytest.fixture(scope="function")
def db_session():
    """Create tables, yield a fresh session, then drop everything.

    Every test function gets its own isolated database.
    """
    Base.metadata.create_all(bind=engine)
    session = TestingSessionLocal()
    try:
        yield session
    finally:
        session.close()
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db_session):
    """FastAPI TestClient wired to the test database session."""

    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def test_user(db_session):
    """Create and return a persisted test user."""
    user = User(
        email="test@example.com",
        hashed_password=hash_password("testpass123"),
        full_name="Test User",
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


@pytest.fixture(scope="function")
def auth_token(test_user):
    """JWT access token for the test user."""
    return create_access_token(test_user.id)


@pytest.fixture(scope="function")
def authorized_client(client, auth_token):
    """TestClient with ``Authorization: Bearer <token>`` already set."""
    client.headers["Authorization"] = f"Bearer {auth_token}"
    return client


# ── Global Test Mocks ───────────────────────────────────────────────────
from unittest.mock import AsyncMock, patch
from app.services.health_service import ServiceHealth

@pytest.fixture(scope="session", autouse=True)
def mock_event_bus():
    """Mock the EventBus to avoid RabbitMQ connection overhead during tests."""
    with patch("app.events.bus.EventBus.connect", new_callable=AsyncMock) as mock_connect, \
         patch("app.events.bus.EventBus.disconnect", new_callable=AsyncMock) as mock_disconnect, \
         patch("app.events.bus.EventBus.publish", new_callable=AsyncMock) as mock_publish, \
         patch("app.events.bus.EventBus.declare_exchange", new_callable=AsyncMock) as mock_decl, \
         patch("app.events.bus.EventBus.consume", new_callable=AsyncMock) as mock_consume:
        yield


@pytest.fixture(scope="function", autouse=True)
def mock_health_checks(request):
    """Mock health checker to return healthy immediately during tests, except when testing health."""
    if "test_health" in request.node.fspath.basename:
        yield
        return

    async def mock_check_all():
        return {
            "database": ServiceHealth("database", "healthy", 0.1),
            "redis": ServiceHealth("redis", "healthy", 0.1),
            "rabbitmq": ServiceHealth("rabbitmq", "healthy", 0.1),
            "zap": ServiceHealth("zap", "healthy", 0.1),
        }
    with patch("app.services.health_service.health_checker.check_all", side_effect=mock_check_all):
        yield


@pytest.fixture(scope="function", autouse=True)
def mock_rate_limiters(request):
    """Bypass rate limiters during test execution, except when testing rate limiters."""
    if "test_rate_limiter" in request.node.fspath.basename:
        yield
        return

    async def mock_dispatch(self, request, call_next):
        return await call_next(request)

    def mock_is_rate_limited(self, ip, action, max_attempts=5, window=60):
        return False

    with patch("app.middleware.rate_limit_global.GlobalRateLimitMiddleware.dispatch", mock_dispatch), \
         patch("app.utils.rate_limiter.AuthRateLimiter.is_rate_limited", mock_is_rate_limited):
        yield


@pytest.fixture(scope="session", autouse=True)
def mock_emails():
    """Mock the email sending functions to avoid SMTP timeout delay."""
    with patch("app.services.email_service.send_email") as mock_send, \
         patch("app.services.email_service.send_verification_email") as mock_verify, \
         patch("app.services.email_service.send_password_reset_email") as mock_reset, \
         patch("app.services.email_service.send_scan_completed_email") as mock_scan:
        yield

import re

from pydantic import model_validator, computed_field
from pydantic_settings import BaseSettings
from typing_extensions import Self


class Settings(BaseSettings):
    APP_NAME: str = "PentestAI"
    VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENV: str = "development"  # development | staging | production

    DATABASE_URL: str = "postgresql://postgres:postgres@localhost:5432/pentestai"
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 40
    DB_POOL_TIMEOUT: int = 30
    DB_POOL_RECYCLE: int = 3600
    DB_ECHO: bool = False
    DB_POOL_USE_LIFO: bool = True

    @computed_field
    @property
    def ASYNC_DATABASE_URL(self) -> str:
        """Derive async URL from sync DATABASE_URL by replacing the driver."""
        return self.DATABASE_URL.replace(
            "postgresql://", "postgresql+asyncpg://"
        ).replace(
            "postgresql+psycopg2://", "postgresql+asyncpg://"
        )

    REDIS_URL: str = "redis://localhost:6379/0"
    RABBITMQ_URL: str = "amqp://guest:guest@localhost:5672/"

    JWT_ALGORITHM: str = "HS512"
    JWT_SECRET_KEY: str = "change-me-at-least-64-chars-with-digits-123-and-special-!@char"
    JWT_ACCESS_EXPIRATION_MINUTES: int = 30
    JWT_REFRESH_EXPIRATION_DAYS: int = 30
    JWT_ISSUER: str = "pentestai"

    STRIPE_SECRET_KEY: str = ""
    STRIPE_WEBHOOK_SECRET: str = ""

    ENCRYPTION_KEY: str = ""  # Fernet key for encrypting sensitive fields (auth_header, etc.)

    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    FROM_EMAIL: str = "noreply@pentestai.com"

    FRONTEND_URL: str = "http://localhost:3000"

    # ── CORS ───────────────────────────────────────────────────────────────
    CORS_ORIGINS: list[str] = ["http://localhost:3000", "https://app.pentestai.com"]
    CORS_ORIGINS_REGEX: str = r"https://[a-z0-9-]+\.pentestai\.com$"
    CORS_METHODS: str = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
    CORS_HEADERS: str = "Authorization,Content-Type,X-Request-ID,Idempotency-Key"
    CORS_EXPOSE_HEADERS: str = "X-Request-ID,X-RateLimit-Limit,X-RateLimit-Remaining,X-RateLimit-Reset"
    CORS_MAX_AGE: int = 3600

    ZAP_BASE_URL: str = "http://localhost:8080"
    ZAP_API_KEY: str = "pentestai-zap-key"

    OPENAI_API_KEY: str = ""  # OpenAI API key for LLM-powered agents
    OPENAI_MODEL: str = "gpt-4o-mini"  # Default model for agent reasoning

    NEO4J_URI: str = ""  # "bolt://localhost:7687"
    NEO4J_USER: str = "neo4j"
    NEO4J_PASSWORD: str = "pentestai"

    OTEL_ENDPOINT: str = ""
    OTEL_TOKEN: str = ""
    SENTRY_DSN: str = ""
    LOG_LEVEL: str = "INFO"
    API_KEY_ROTATION_DAYS: int = 90

    class Config:
        env_file = ".env"

    @model_validator(mode="after")
    def validate_jwt_secret(self) -> Self:
        """JWT_SECRET_KEY'i güçlendir: min 64 karakter, en az 1 rakam, 1 özel karakter."""
        key = self.JWT_SECRET_KEY

        # Check default hasn't been left in place
        if key == "change-me-at-least-64-chars-with-digits-123-and-special-!@char":
            raise ValueError(
                "CRITICAL: JWT_SECRET_KEY .env dosyasında değiştirilmemiş! "
                "Lütfen en az 64 karakterli, rakam ve özel karakter içeren "
                "rastgele bir anahtar belirleyin.\n"
                "Öneri: python -c \"import secrets,base64; "
                "print(base64.b64encode(secrets.token_bytes(64)).decode())\""
            )

        if len(key) < 64:
            raise ValueError(
                f"JWT_SECRET_KEY must be at least 64 characters long "
                f"(got {len(key)})."
            )
        if not re.search(r"\d", key):
            raise ValueError(
                "JWT_SECRET_KEY must contain at least one digit (0-9)."
            )
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-]", key):
            raise ValueError(
                "JWT_SECRET_KEY must contain at least one special character "
                "(!@#$%^&*(),.?\":{}|<>_-)."
            )
        return self


try:
    settings = Settings()
except:
    class MockSettings:
        APP_NAME = "PentestAI"
        VERSION = "1.0.0"
        ENV = "dev"
        DEBUG = True
        CORS_ORIGINS = ["*"]
        CORS_ORIGINS_REGEX = ".*"
        CORS_METHODS = "*"
        CORS_HEADERS = "*"
        CORS_EXPOSE_HEADERS = "*"
        CORS_MAX_AGE = 600
        LOG_LEVEL = "INFO"
    settings = MockSettings()

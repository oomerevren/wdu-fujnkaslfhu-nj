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

    JWT_SECRET_KEY: str = "your-secret-key-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRATION_MINUTES: int = 60

    STRIPE_SECRET_KEY: str = ""
    STRIPE_WEBHOOK_SECRET: str = ""

    ENCRYPTION_KEY: str = ""  # Fernet key for encrypting sensitive fields (auth_header, etc.)

    SMTP_HOST: str = "localhost"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    FROM_EMAIL: str = "noreply@pentestai.com"

    FRONTEND_URL: str = "http://localhost:3000"

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
        """JWT_SECRET_KEY'in default değerde olmadığını kontrol et."""
        if self.JWT_SECRET_KEY == "your-secret-key-change-in-production":
            raise ValueError(
                "CRITICAL: JWT_SECRET_KEY .env dosyasında değiştirilmemiş! "
                "Lütfen 64+ karakterli rastgele bir anahtar belirleyin."
            )
        return self


settings = Settings()

"""Structured JSON logging for PentestAI production environment."""
import sys
import json
from loguru import logger

def init_sentry():
    """Sentry integration placeholder — initialize with SENTRY_DSN from settings."""
    pass

def setup_logging(log_level="INFO"):
    """Configure structured JSON logging for production and development."""
    logger.remove()
    # Structured JSON format for production
    logger.add(
        sys.stdout,
        format="{\"timestamp\":\"{time}\",\"level\":\"{level}\",\"message\":\"{message}\",\"extra\":{extra}}",
        level=log_level,
        serialize=True,
        backtrace=True,
        diagnose=True,
    )
    logger.info("Structured logging initialized", extra={"level": log_level, "format": "json"})
    return logger

# Initialize with default INFO level; can be overridden by app.config
logger = setup_logging()

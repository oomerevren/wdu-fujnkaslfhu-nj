import sys
import json
import os
from pathlib import Path
from loguru import logger as _logger
from app.config import settings

_logger.remove()

LOG_LEVEL = os.getenv("LOG_LEVEL", settings.LOG_LEVEL).upper()


def _serialize_record(record) -> str:
    extra = record.get("extra", {})
    request_id = extra.pop("request_id", None)
    trace_id = extra.pop("trace_id", None)
    span_id = extra.pop("span_id", None)

    log_entry = {
        "timestamp": record["time"].strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
        "level": record["level"].name,
        "module": record["name"],
        "function": record["function"],
        "line": record["line"],
        "message": record["message"],
    }
    if request_id:
        log_entry["request_id"] = request_id
    if trace_id:
        log_entry["trace_id"] = trace_id
    if span_id:
        log_entry["span_id"] = span_id
    if extra:
        log_entry["extra"] = extra
    if record["exception"]:
        log_entry["exception"] = _format_exception(record["exception"])

    return json.dumps(log_entry, ensure_ascii=False, default=str)


def _format_exception(exc_info) -> str:
    if exc_info is None:
        return ""
    exc_type, exc_value, _ = exc_info
    return f"{exc_type.__name__}: {exc_value}"


def _console_format(record) -> str:
    level = record["level"].name
    time = record["time"].strftime("%H:%M:%S")
    module = record["name"]
    line = record["line"]
    message = record["message"]
    extra = record.get("extra", {})
    request_id = extra.get("request_id")
    trace_id = extra.get("trace_id")
    span_id = extra.get("span_id")

    parts = [f"[{time}]", f"[{level:8}]", f"{module}:{line}"]
    if request_id:
        parts.append(f"[req={request_id}]")
    if trace_id:
        parts.append(f"[trace={trace_id[:12]}]")
    if span_id:
        parts.append(f"[span={span_id[:8]}]")
    parts.append(f" — {message}")

    if record["exception"]:
        parts.append(f" | {_format_exception(record['exception'])}")

    return " ".join(parts) + "\n"


_logger.add(
    sink=sys.stdout,
    format=_console_format,
    level=LOG_LEVEL,
    colorize=True,
    enqueue=True,
)

log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)

_logger.add(
    sink=str(log_dir / "pentestai-{time:YYYY-MM-DD}.json"),
    format=_serialize_record,
    level="INFO",
    rotation="50 MB",
    retention="30 days",
    compression="gz",
    enqueue=True,
    serialize=False,
)

_logger.add(
    sink=str(log_dir / "pentestai-error-{time:YYYY-MM-DD}.json"),
    format=_serialize_record,
    level="ERROR",
    rotation="50 MB",
    retention="90 days",
    compression="gz",
    enqueue=True,
)


def get_logger(**context):
    return _logger.bind(**context)


def init_sentry():
    if not settings.SENTRY_DSN:
        return
    try:
        import sentry_sdk
        sentry_sdk.init(
            dsn=settings.SENTRY_DSN,
            environment=settings.ENV,
            traces_sample_rate=0.2 if settings.ENV == "production" else 1.0,
        )
        _logger.info("Sentry initialized")
    except Exception as exc:
        _logger.warning("Failed to initialize Sentry", extra={"error": str(exc)})


logger = get_logger()

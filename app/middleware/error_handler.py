import hashlib
from fastapi import Request, HTTPException
from fastapi.responses import JSONResponse
import logging

logger = logging.getLogger(__name__)


def _fingerprint(request: Request) -> str:
    ip = request.client.host if request.client else "unknown"
    ua = request.headers.get("User-Agent", "")
    raw = f"{ip}|{ua}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    fp = _fingerprint(request)

    if isinstance(exc, HTTPException):
        if exc.status_code in (401, 403):
            logger.warning(
                "Security event: %s %s",
                exc.status_code,
                request.url.path,
                extra={
                    "status_code": exc.status_code,
                    "path": request.url.path,
                    "method": request.method,
                    "fingerprint": fp,
                    "client_host": request.client.host if request.client else None,
                    "user_agent": request.headers.get("User-Agent"),
                },
            )
        return JSONResponse(
            status_code=exc.status_code,
            content={
                "error": {
                    "code": exc.status_code,
                    "message": exc.detail,
                    "type": "http_error",
                }
            },
        )

    from pydantic import ValidationError

    if isinstance(exc, ValidationError):
        return JSONResponse(
            status_code=422,
            content={
                "error": {
                    "code": 422,
                    "message": "Validation error",
                    "type": "validation_error",
                    "details": exc.errors(),
                }
            },
        )

    logger.exception("Unhandled exception: %s", str(exc))
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": 500,
                "message": "Internal server error",
                "type": "internal_error",
            }
        },
    )

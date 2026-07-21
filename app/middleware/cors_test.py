"""
CORS Test Middleware (development only).

Validates that the CORS configuration is correct by intercepting OPTIONS
(preflight) responses and verifying that all required headers are present.
This middleware is a no-op in production (ENV != "development").
"""

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from app.config import settings
from app.core.logging import logger


CORS_REQUIRED_HEADERS: dict[str, str] = {
    "access-control-allow-origin": "Origin must be explicitly allowed",
    "access-control-allow-methods": "Must list allowed HTTP methods",
    "access-control-allow-headers": "Must list allowed request headers",
    "access-control-max-age": "Preflight cache duration must be set",
}

CORS_OPTIONAL_HEADERS: dict[str, str] = {
    "access-control-expose-headers": "Should list exposed response headers",
    "access-control-allow-credentials": "Should be 'true' when credentials are allowed",
}


class CORSTestMiddleware(BaseHTTPMiddleware):
    """Validates CORS headers on OPTIONS responses in development environments."""

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        response = await call_next(request)

        if settings.ENV != "development":
            return response

        if request.method != "OPTIONS":
            return response

        missing_required: list[str] = []
        missing_optional: list[str] = []

        for header, description in CORS_REQUIRED_HEADERS.items():
            value = response.headers.get(header)
            if not value:
                missing_required.append(f"  - {header}: {description}")
            elif value == "*":
                logger.warning(
                    "CORS [%s] is wildcard '*' — consider tightening",
                    header,
                    extra={
                        "path": str(request.url),
                        "header": header,
                        "value": value,
                    },
                )

        for header, description in CORS_OPTIONAL_HEADERS.items():
            value = response.headers.get(header)
            if not value:
                missing_optional.append(f"  - {header}: {description}")
            elif value == "*":
                logger.warning(
                    "CORS [%s] is wildcard '*' — consider tightening",
                    header,
                    extra={
                        "path": str(request.url),
                        "header": header,
                        "value": value,
                    },
                )

        origin = request.headers.get("origin", "(none)")
        allow_origin = response.headers.get("access-control-allow-origin", "")

        if allow_origin and origin != "(none)" and origin != allow_origin:
            if allow_origin != "*":
                logger.warning(
                    "CORS origin mismatch: request Origin=%s but response "
                    "Access-Control-Allow-Origin=%s",
                    origin,
                    allow_origin,
                    extra={
                        "request_origin": origin,
                        "response_allow_origin": allow_origin,
                        "path": str(request.url),
                    },
                )

        if missing_required:
            logger.warning(
                "CORS test FAILED — OPTIONS response missing required header(s):\n%s",
                "\n".join(missing_required),
                extra={
                    "path": str(request.url),
                    "origin": origin,
                    "missing": [h.split(":")[0].strip() for h in missing_required],
                },
            )

        if missing_optional:
            logger.debug(
                "CORS test — OPTIONS response missing optional header(s):\n%s",
                "\n".join(missing_optional),
                extra={
                    "path": str(request.url),
                    "origin": origin,
                    "missing": [h.split(":")[0].strip() for h in missing_optional],
                },
            )

        return response

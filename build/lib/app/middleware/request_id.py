import uuid
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response
from app.core.logging import logger


class RequestIDMiddleware(BaseHTTPMiddleware):
    """FastAPI middleware that attaches a unique request ID to every request.

    - Reads the ``X-Request-ID`` header from the incoming request if present.
    - Otherwise generates a new UUIDv4.
    - Injects the ID into the logging context so all log records emitted during
      the request carry it.
    - Echoes the ID back in the ``X-Request-ID`` response header.
    """

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # 1. Extract or create request ID
        request_id = request.headers.get("X-Request-ID")
        if not request_id:
            request_id = str(uuid.uuid4())

        # 2. Bind the ID to a contextual logger for this request
        ctx_logger = logger.bind(request_id=request_id)
        # Store the contextual logger on the request state so handlers can use it
        request.state.request_id = request_id
        request.state.logger = ctx_logger

        # 3. Process the request
        response: Response = await call_next(request)

        # 4. Echo the request ID in the response
        response.headers["X-Request-ID"] = request_id

        return response

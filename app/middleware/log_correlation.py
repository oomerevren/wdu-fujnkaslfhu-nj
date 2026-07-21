from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


class LogCorrelationMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        trace_id = None
        span_id = None

        try:
            from opentelemetry import trace
            span = trace.get_current_span()
            if span and span.is_recording():
                ctx = span.get_span_context()
                trace_id = format(ctx.trace_id, "032x")
                span_id = format(ctx.span_id, "016x")
        except Exception:
            pass

        request.state.trace_id = trace_id
        request.state.span_id = span_id

        response = await call_next(request)

        if trace_id:
            response.headers["X-Trace-ID"] = trace_id
        if span_id:
            response.headers["X-Span-ID"] = span_id

        return response

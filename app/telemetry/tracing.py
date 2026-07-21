from fastapi import FastAPI
from sqlalchemy import Engine as SAEngine
from app.config import settings
from app.core.logging import logger


def setup_tracing(app: FastAPI, engine: SAEngine):
    if not settings.OTEL_ENDPOINT:
        logger.info("OTEL_ENDPOINT not configured — skipping OpenTelemetry setup")
        return

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
        from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor

        provider = TracerProvider()

        headers = {}
        if settings.OTEL_TOKEN:
            headers["Authorization"] = f"Bearer {settings.OTEL_TOKEN}"

        exporter = OTLPSpanExporter(
            endpoint=settings.OTEL_ENDPOINT,
            headers=headers,
        )
        processor = BatchSpanProcessor(exporter)
        provider.add_span_processor(processor)
        trace.set_tracer_provider(provider)

        FastAPIInstrumentor.instrument_app(app)

        SQLAlchemyInstrumentor().instrument(
            engine=engine,
        )

        HTTPXClientInstrumentor().instrument()

        logger.info("OpenTelemetry tracing initialized", extra={"endpoint": settings.OTEL_ENDPOINT})

    except Exception as exc:
        logger.warning("Failed to initialize OpenTelemetry", extra={"error": str(exc)})

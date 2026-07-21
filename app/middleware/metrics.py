import time
from fastapi import Request, Response
from prometheus_client import Counter, Histogram, Gauge, generate_latest

# Metrics
REQUEST_COUNT = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status"],
)

REQUEST_LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint"],
    buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)

ACTIVE_USERS = Gauge("active_users", "Currently active users")

SCAN_DURATION = Histogram(
    "scan_duration_seconds",
    "Scan duration in seconds",
    ["scan_type", "status"],
    buckets=(10, 30, 60, 120, 300, 600, 1800, 3600),
)


async def metrics_middleware(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    duration = time.time() - start_time

    REQUEST_COUNT.labels(
        method=request.method,
        endpoint=request.url.path,
        status=response.status_code,
    ).inc()

    REQUEST_LATENCY.labels(
        method=request.method,
        endpoint=request.url.path,
    ).observe(duration)

    return response

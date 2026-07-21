import asyncio
import logging
from typing import Optional

from celery import Celery, signals
from app.config import settings

logger = logging.getLogger(__name__)

celery_app = Celery(
    "pentestai",
    broker=settings.REDIS_URL,
    backend=settings.REDIS_URL,
)

celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    task_time_limit=900,
    task_soft_time_limit=600,
    result_expires=86400,
    worker_concurrency=4,
    task_default_queue="default",
    task_queues={
        "default": {
            "exchange": "default",
            "routing_key": "default",
        },
        "scans": {
            "exchange": "scans",
            "routing_key": "scans",
        },
    },
    task_routes={
        "app.tasks.scan_tasks.run_scan": {"queue": "scans"},
    },
)

celery_app.autodiscover_tasks(["app.tasks"])

# ── Event bus integration ───────────────────────────────────────────────
#
# Unlike scan tasks (which use asyncio.run() for isolated one-shot async),
# the event bus needs a **persistent** event loop because aio_pika keeps
# a TCP connection alive across multiple publish/consume calls.  We store
# a dedicated loop at module level and reuse it for all bus operations.
# This loop is created on first use (lazy) and torn down on worker shutdown.

_event_bus_initialized: bool = False
_event_bus_loop: Optional[asyncio.AbstractEventLoop] = None


def _get_event_bus_loop() -> asyncio.AbstractEventLoop:
    """Return or create the dedicated event bus loop.

    Using a single persistent loop (instead of ``asyncio.run()``) is
    intentional: aio_pika's ``RobustConnection`` remains bound to the
    loop that created it.  Creating a fresh loop per operation would
    orphan the connection and eventually exhaust resources.
    """
    global _event_bus_loop
    if _event_bus_loop is None or _event_bus_loop.is_closed():
        _event_bus_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_event_bus_loop)
    return _event_bus_loop


def get_event_bus():
    """Return the global event bus instance, initialising it if needed.

    Called lazily from Celery tasks so that the bus is only connected when
    a task actually publishes an event.
    """
    global _event_bus_initialized
    from app.events.bus import event_bus

    if not _event_bus_initialized:
        loop = _get_event_bus_loop()
        try:
            loop.run_until_complete(event_bus.connect())
            _event_bus_initialized = True
            logger.info("Event bus initialised for Celery worker")
        except Exception:
            logger.exception("Failed to initialise event bus for Celery worker")
    return event_bus


@signals.task_prerun.connect
def on_task_prerun(*args, **kwargs):
    """Ensure the event bus is connected before a task runs."""
    try:
        get_event_bus()
    except Exception:
        logger.warning("Event bus unavailable for task — events will not be published")


@signals.worker_shutdown.connect
def on_worker_shutdown(*args, **kwargs):
    """Disconnect the event bus when the Celery worker shuts down."""
    global _event_bus_initialized, _event_bus_loop
    if _event_bus_initialized:
        from app.events.bus import event_bus

        try:
            loop = _get_event_bus_loop()
            loop.run_until_complete(event_bus.disconnect())
            _event_bus_initialized = False
            logger.info("Event bus disconnected on Celery worker shutdown")
        except Exception:
            logger.exception("Error disconnecting event bus on shutdown")
    if _event_bus_loop is not None and not _event_bus_loop.is_closed():
        _event_bus_loop.close()
        _event_bus_loop = None


# ── Helper to publish events from Celery tasks ──────────────────────────


def publish_event_from_task(
    event_type: str,
    payload: dict,
    routing_key: str,
    exchange_name: str = "pentestai.events",
) -> None:
    """Publish an event synchronously from a Celery task context.

    Uses the dedicated event-bus loop (see ``_get_event_bus_loop``) to
    avoid creating a throw-away loop for every publish call.  This is
    safe because the event bus connection lives on that same loop.

    This is a low-level helper. For specific events, use the producer
    functions from ``app.events.producers`` instead.

    Example::

        from app.events.producers import publish_scan_completed_sync

        publish_scan_completed_sync(
            scan_id=str(scan.id),
            findings_count=len(findings),
            duration_seconds=duration,
        )
    """
    from app.events.bus import Event, event_bus

    bus = get_event_bus()
    event = Event(type=event_type, payload=payload)

    loop = _get_event_bus_loop()
    loop.run_until_complete(
        bus.publish(exchange_name=exchange_name, routing_key=routing_key, event=event)
    )
    logger.debug(
        "Published event %s to %s/%s",
        event_type,
        exchange_name,
        routing_key,
    )

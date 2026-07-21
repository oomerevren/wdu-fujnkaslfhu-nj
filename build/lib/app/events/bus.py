"""Async event bus implementation backed by RabbitMQ via aio_pika.

Provides:
  - ``Event`` dataclass (type, payload, metadata)
  - ``EventBus`` singleton with connect/disconnect, publish, and consume
  - Predefined exchange names and routing key constants
  - Module-level ``event_bus`` singleton
"""

from __future__ import annotations

import asyncio
import json
import logging
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Awaitable, Callable

import aio_pika
from aio_pika import DeliveryMode, ExchangeType, Message, RobustConnection

logger = logging.getLogger(__name__)

# ── Exchange names ──────────────────────────────────────────────────────
EX_SCANS: str = "pentestai.scans"
EX_FINDINGS: str = "pentestai.findings"
EX_USERS: str = "pentestai.users"
EX_EVENTS: str = "pentestai.events"

# ── Routing keys ────────────────────────────────────────────────────────
RK_SCAN_CREATED: str = "scan.created"
RK_SCAN_PROGRESS: str = "scan.progress"
RK_SCAN_COMPLETED: str = "scan.completed"
RK_SCAN_FAILED: str = "scan.failed"
RK_FINDING_CREATED: str = "finding.created"
RK_FINDING_STATUS_CHANGED: str = "finding.status_changed"
RK_USER_REGISTERED: str = "user.registered"
RK_USER_LOGIN: str = "user.login"

# ── Exchange-to-routing-key mapping for consumer registration ───────────
EXCHANGE_ROUTING_KEYS: dict[str, list[str]] = {
    EX_SCANS: [
        RK_SCAN_CREATED,
        RK_SCAN_PROGRESS,
        RK_SCAN_COMPLETED,
        RK_SCAN_FAILED,
    ],
    EX_FINDINGS: [
        RK_FINDING_CREATED,
        RK_FINDING_STATUS_CHANGED,
    ],
    EX_USERS: [
        RK_USER_REGISTERED,
        RK_USER_LOGIN,
    ],
    EX_EVENTS: [
        RK_SCAN_CREATED,
        RK_SCAN_PROGRESS,
        RK_SCAN_COMPLETED,
        RK_SCAN_FAILED,
        RK_FINDING_CREATED,
        RK_FINDING_STATUS_CHANGED,
        RK_USER_REGISTERED,
        RK_USER_LOGIN,
    ],
}


@dataclass
class Event:
    """Universal event envelope.

    Attributes:
        type:    Dot-notation event type, e.g. ``"scan.created"``.
        payload: Domain-specific data for the event.
        metadata: Envelope metadata (timestamp, correlation_id, source, version).
    """

    type: str
    payload: dict[str, Any]
    metadata: dict[str, Any] = field(
        default_factory=lambda: {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "correlation_id": str(uuid.uuid4()),
            "source": "pentestai",
            "version": "1.0",
        }
    )


class EventBus:
    """Async event bus — singleton, backed by RabbitMQ (aio_pika).

    Usage::

        bus = EventBus(settings.RABBITMQ_URL)
        await bus.connect()

        # Publish
        event = Event(type="scan.created", payload={"scan_id": "…", …})
        await bus.publish(EX_SCANS, RK_SCAN_CREATED, event)

        # Consume
        await bus.consume(EX_SCANS, RK_SCAN_PROGRESS, my_callback)

        # Shutdown
        await bus.disconnect()
    """

    _instance: EventBus | None = None

    def __new__(cls, *args: Any, **kwargs: Any) -> EventBus:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, rabbitmq_url: str | None = None) -> None:
        if getattr(self, "_initialized", False):
            return
        self._rabbitmq_url: str = rabbitmq_url or "amqp://guest:guest@localhost:5672/"
        self._connection: RobustConnection | None = None
        self._channel: aio_pika.Channel | None = None
        self._exchanges: dict[str, aio_pika.Exchange] = {}
        self._consumer_tasks: list[asyncio.Task] = []
        self._consume_iterators: list[Any] = []
        self._initialized: bool = True

    # ── Lifecycle ───────────────────────────────────────────────────────

    async def connect(self) -> None:
        """Open a robust connection + channel to RabbitMQ.

        Safe to call multiple times — idempotent if already connected.
        """
        if self._connection is not None and not self._connection.is_closed:
            return
        try:
            self._connection = await aio_pika.connect_robust(self._rabbitmq_url)
            self._channel = await self._connection.channel()
            await self._channel.set_qos(prefetch_count=10)
            logger.info("EventBus connected to RabbitMQ at %s", self._rabbitmq_url)
        except Exception:
            logger.exception("EventBus failed to connect to RabbitMQ")
            raise

    async def disconnect(self) -> None:
        """Close all consumers, the channel, and the connection."""
        # Cancel consumer tasks
        for task in self._consumer_tasks:
            task.cancel()
        if self._consumer_tasks:
            await asyncio.gather(*self._consumer_tasks, return_exceptions=True)
        self._consumer_tasks.clear()
        self._consume_iterators.clear()

        # Close channel
        if self._channel is not None and not self._channel.is_closed:
            await self._channel.close()
            self._channel = None

        # Close connection
        if self._connection is not None and not self._connection.is_closed:
            await self._connection.close()
            self._connection = None

        self._exchanges.clear()
        logger.info("EventBus disconnected from RabbitMQ")

    # ── Exchange declaration ────────────────────────────────────────────

    async def declare_exchange(
        self,
        name: str,
        exchange_type: ExchangeType = ExchangeType.TOPIC,
    ) -> aio_pika.Exchange:
        """Declare a topic exchange and cache it locally.

        Returns the cached exchange on subsequent calls with the same name.
        """
        if name in self._exchanges:
            return self._exchanges[name]
        if self._channel is None:
            raise RuntimeError("EventBus not connected — call connect() first")
        exchange = await self._channel.declare_exchange(
            name=name,
            type=exchange_type,
            durable=True,
        )
        self._exchanges[name] = exchange
        logger.debug("Declared exchange: %s (type=%s)", name, exchange_type.value)
        return exchange

    # ── Publish ─────────────────────────────────────────────────────────

    async def publish(
        self,
        exchange_name: str,
        routing_key: str,
        event: Event,
    ) -> None:
        """Publish an *event* to *exchange_name* with the given *routing_key*.

        Auto-connects if the connection is closed.
        """
        if self._connection is None or self._connection.is_closed:
            await self.connect()

        exchange = await self.declare_exchange(exchange_name)

        body_bytes = json.dumps(asdict(event), default=str).encode("utf-8")
        message = Message(
            body=body_bytes,
            delivery_mode=DeliveryMode.PERSISTENT,
            content_type="application/json",
            headers={
                "event_type": event.type,
                "correlation_id": event.metadata.get("correlation_id", ""),
            },
        )
        await exchange.publish(message, routing_key=routing_key)
        logger.debug(
            "Published event type=%s to %s/%s (correlation_id=%s)",
            event.type,
            exchange_name,
            routing_key,
            event.metadata.get("correlation_id"),
        )

    # ── Consume ─────────────────────────────────────────────────────────

    async def consume(
        self,
        exchange_name: str,
        routing_key: str,
        callback: Callable[[str, dict[str, Any], dict[str, Any]], Awaitable[None]],
        queue_name: str | None = None,
    ) -> asyncio.Task:
        """Register an async *callback* as a consumer on the given exchange/routing_key.

        A durable queue named *queue_name* (defaults to ``{routing_key}.queue``)
        is declared and bound to the exchange with the given routing key.

        Returns the ``asyncio.Task`` running the consumer loop.
        """
        if self._connection is None or self._connection.is_closed:
            await self.connect()

        exchange = await self.declare_exchange(exchange_name)
        qname = queue_name or f"pentestai.{routing_key.replace('.', '_')}.queue"
        queue = await self._channel.declare_queue(name=qname, durable=True)
        await queue.bind(exchange, routing_key=routing_key)

        logger.info(
            "Consumer registered: %s/%s -> queue=%s",
            exchange_name,
            routing_key,
            qname,
        )

        async def _consumer_loop() -> None:
            async with queue.iterator() as qiter:
                self._consume_iterators.append(qiter)
                async for message in qiter:
                    async with message.process(ignore_processed=True):
                        try:
                            body: dict[str, Any] = json.loads(
                                message.body.decode("utf-8")
                            )
                            event_type = body.get("type", "")
                            payload = body.get("payload", {})
                            metadata = body.get("metadata", {})
                            await callback(event_type, payload, metadata)
                            await message.ack()
                        except Exception:
                            logger.exception(
                                "Error processing event on %s/%s",
                                exchange_name,
                                routing_key,
                            )
                            # Reject and do NOT requeue — dead-letter handling
                            await message.reject(requeue=False)

        task = asyncio.create_task(_consumer_loop())
        self._consumer_tasks.append(task)
        return task


# Module-level singleton — import this from anywhere in the application.
event_bus = EventBus()

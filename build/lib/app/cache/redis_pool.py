"""
Redis connection pool singleton — sync + async.

Eliminates redundant ``redis.from_url()`` calls throughout the codebase.
All Redis clients share a single connection pool, reducing resource usage
and avoiding connection-limit exhaustion.

Usage::

    from app.cache.redis_pool import redis_pool

    # Sync usage
    r = redis_pool.get_client()
    r.set("key", "value")
    r.close()  # returns connection to the pool, does NOT disconnect

    # Async usage
    r = await redis_pool.get_async_client()
    await r.set("key", "value")
    await r.close()  # returns connection to the pool

    # Graceful shutdown (typically in app lifespan)
    redis_pool.close_all()
"""

from redis import Redis, ConnectionPool as SyncConnectionPool
from redis.asyncio import Redis as AsyncRedis, ConnectionPool as AsyncConnectionPool

from app.config import settings

_POOL_OPTIONS = {
    "max_connections": 50,
    "decode_responses": True,
    "socket_connect_timeout": 2,
    "socket_timeout": 5,
    "retry_on_timeout": True,
    "health_check_interval": 30,
}


class RedisPool:
    """Singleton holding both a sync and an async connection pool.

    Calling ``get_client()`` / ``get_async_client()`` returns lightweight
    Redis wrapper instances that borrow connections from the underlying pool.
    The pool handles connection lifecycle, health checks, and retries.
    """

    _instance: "RedisPool | None" = None
    _sync_pool: SyncConnectionPool | None = None
    _async_pool: AsyncConnectionPool | None = None

    def __new__(cls) -> "RedisPool":
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._sync_pool = SyncConnectionPool.from_url(
                settings.REDIS_URL,
                **_POOL_OPTIONS,
            )
            cls._async_pool = AsyncConnectionPool.from_url(
                settings.REDIS_URL,
                **_POOL_OPTIONS,
            )
        return cls._instance

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_client(self) -> Redis:
        """Return a **sync** Redis client that borrows from the shared pool.

        The caller **should** call ``.close()`` after use so the connection
        is returned to the pool (it does *not* disconnect the underlying
        TCP socket).
        """
        return Redis(connection_pool=self._sync_pool)

    def get_async_client(self) -> AsyncRedis:
        """Return an **async** Redis client that borrows from the shared pool.

        The caller **should** ``await .close()`` after use.
        """
        return AsyncRedis(connection_pool=self._async_pool)

    def close_all(self) -> None:
        """Disconnect **all** connections in the sync pool.

        Safe to call multiple times — the operation is idempotent.
        """
        if self._sync_pool is not None:
            self._sync_pool.disconnect()

    async def close_all_async(self) -> None:
        """Disconnect **all** connections in the async pool.

        Safe to call multiple times.
        """
        if self._async_pool is not None:
            await self._async_pool.disconnect()


# Singleton — import this everywhere you need a Redis client
redis_pool = RedisPool()

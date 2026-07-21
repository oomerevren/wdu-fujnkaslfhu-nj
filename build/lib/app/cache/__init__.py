"""
Redis caching layer for PentestAI.

Provides async get/set/delete operations with TTL support,
plus a get_or_compute helper for cache-aside pattern.

Usage:
    from app.cache import cache

    # Simple get/set
    value = await cache.get("mykey")
    await cache.set("mykey", {"data": 42}, ttl=300)

    # Cache-aside pattern
    async def compute():
        return await expensive_operation()

    result = await cache.get_or_compute("mykey", ttl=300, factory_func=compute)

    # Delete by pattern
    await cache.delete("scan:*")
"""

import asyncio
import json
import logging
from typing import Any, Callable, Optional

from redis.asyncio import Redis as AsyncRedis

from app.cache.redis_pool import redis_pool

logger = logging.getLogger(__name__)


class RedisCache:
    """Async Redis cache client backed by the shared connection pool.

    Every call to ``_get_client()`` borrows a connection from the pool managed
    by ``app.cache.redis_pool`` instead of opening a new TCP socket.
    """

    def __init__(self) -> None:
        self._client: Optional[AsyncRedis] = None
        self._lock = asyncio.Lock()

    async def _get_client(self) -> AsyncRedis:
        """Get or create a Redis client from the shared pool."""
        if self._client is None:
            async with self._lock:
                # Double-check after acquiring lock
                if self._client is None:
                    self._client = redis_pool.get_async_client()
                    try:
                        await self._client.ping()
                        logger.info("Redis cache connection established")
                    except Exception as exc:
                        logger.warning("Redis cache unavailable, falling through", extra={"error": str(exc)})
                        self._client = None
                        raise
        return self._client

    async def get(self, key: str) -> Any | None:
        """Get a value by key.

        Returns deserialized JSON data, or None if key doesn't exist.
        """
        try:
            client = await self._get_client()
            value = await client.get(key)
            if value is not None:
                return json.loads(value)
            return None
        except Exception as exc:
            logger.debug("Cache GET error", extra={"key": key, "error": str(exc)})
            return None

    async def set(self, key: str, value: Any, ttl: int = 300) -> bool:
        """Set a value with TTL (seconds).

        Automatically serializes to JSON.
        Returns True on success, False on failure.
        """
        try:
            client = await self._get_client()
            serialized = json.dumps(value, default=str)
            await client.setex(key, ttl, serialized)
            return True
        except Exception as exc:
            logger.debug("Cache SET error", extra={"key": key, "error": str(exc)})
            return False

    async def delete(self, pattern: str) -> int:
        """Delete all keys matching the given glob pattern.

        Returns the number of keys deleted.
        """
        try:
            client = await self._get_client()
            # Scan for matching keys
            cursor = 0
            deleted = 0
            while True:
                cursor, keys = await client.scan(cursor=cursor, match=pattern, count=100)
                if keys:
                    deleted += await client.delete(*keys)
                if cursor == 0:
                    break
            if deleted:
                logger.debug("Cache DELETE", extra={"pattern": pattern, "deleted": deleted})
            return deleted
        except Exception as exc:
            logger.debug("Cache DELETE error", extra={"pattern": pattern, "error": str(exc)})
            return 0

    async def get_or_compute(
        self,
        key: str,
        ttl: int = 300,
        factory_func: Callable[..., Any] = None,
        *args,
        **kwargs,
    ) -> Any:
        """Cache-aside pattern: return cached value or compute and cache.

        Args:
            key: Cache key.
            ttl: Time-to-live in seconds (default 300).
            factory_func: Async callable that computes the value if not cached.
            *args, **kwargs: Passed to factory_func.

        Returns:
            The cached or freshly computed value.
        """
        # 1. Try cache
        cached = await self.get(key)
        if cached is not None:
            return cached

        # 2. Compute fresh value
        if factory_func is None:
            return None

        try:
            if asyncio.iscoroutinefunction(factory_func):
                value = await factory_func(*args, **kwargs)
            else:
                value = factory_func(*args, **kwargs)
        except Exception as exc:
            logger.warning("Cache factory function failed", extra={"key": key, "error": str(exc)})
            raise

        # 3. Store in cache (best-effort)
        await self.set(key, value, ttl=ttl)

        return value

    async def close(self) -> None:
        """Close the Redis connection."""
        if self._client is not None:
            try:
                await self._client.aclose()
                logger.info("Redis cache connection closed")
            except Exception as exc:
                logger.warning("Error closing Redis cache", extra={"error": str(exc)})
            finally:
                self._client = None

    async def ping(self) -> bool:
        """Check if Redis is reachable."""
        try:
            client = await self._get_client()
            return await client.ping()
        except Exception:
            return False

    async def flush_all(self) -> bool:
        """Flush all keys (use with caution in development only)."""
        try:
            client = await self._get_client()
            await client.flushall()
            logger.warning("Redis cache flushed all keys")
            return True
        except Exception as exc:
            logger.warning("Redis flush failed", extra={"error": str(exc)})
            return False


# Singleton cache instance
cache = RedisCache()


async def get(key: str) -> Any | None:
    """Convenience: get cached value."""
    return await cache.get(key)


async def set(key: str, value: Any, ttl: int = 300) -> bool:
    """Convenience: set cached value with TTL."""
    return await cache.set(key, value, ttl=ttl)


async def delete(pattern: str) -> int:
    """Convenience: delete keys matching pattern."""
    return await cache.delete(pattern)


async def get_or_compute(
    key: str,
    ttl: int = 300,
    factory_func: Callable = None,
    *args,
    **kwargs,
) -> Any:
    """Convenience: cache-aside pattern."""
    return await cache.get_or_compute(key, ttl, factory_func, *args, **kwargs)

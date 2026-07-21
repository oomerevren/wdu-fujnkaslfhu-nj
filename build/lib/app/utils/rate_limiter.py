"""
Redis-backed rate limiter for auth endpoints.
Falls back to in-memory dict if Redis is unavailable.
"""
import time
from typing import Optional

from app.cache.redis_pool import redis_pool


class AuthRateLimiter:
    """Rate limiter with Redis backend and in-memory fallback.

    Tracks attempt counts per IP per action (e.g. login, register).
    Redis keys follow the pattern: ``auth_rate_limit:{action}:{ip}``
    """

    def __init__(self) -> None:
        self.redis: Optional["redis.Redis"] = None  # type: ignore[name-defined]
        self._memory_store: dict[str, list[float]] = {}
        self._connect_redis()

    def _connect_redis(self) -> None:
        """Try connecting to Redis; fall back to in-memory on failure."""
        try:
            self.redis = redis_pool.get_client()
            self.redis.ping()
        except Exception:
            self.redis = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _redis_key(ip: str, action: str) -> str:
        return f"auth_rate_limit:{action}:{ip}"

    @staticmethod
    def _mem_key(ip: str, action: str) -> str:
        return f"{action}:{ip}"

    def _prune(self, key: str, window: int) -> None:
        """Remove entries older than *window* seconds from an in-memory list."""
        now = time.time()
        if key in self._memory_store:
            self._memory_store[key] = [
                t for t in self._memory_store[key] if now - t < window
            ]

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_rate_limited(self, ip: str, action: str, max_attempts: int, window: int) -> bool:
        """Check whether *ip* has exceeded *max_attempts* for *action* within *window* seconds.

        Returns ``True`` when the request should be rejected.
        """
        if self.redis is not None:
            count = self.redis.get(self._redis_key(ip, action))
            return count is not None and int(count) >= max_attempts

        # ---- in-memory fallback ----
        key = self._mem_key(ip, action)
        self._prune(key, window)
        return len(self._memory_store.get(key, [])) >= max_attempts

    def increment(self, ip: str, action: str, window: int) -> None:
        """Record one attempt for *ip* under *action*.

        Key auto-expires after *window* seconds when Redis is available.
        """
        if self.redis is not None:
            key = self._redis_key(ip, action)
            count = self.redis.incr(key)
            if count == 1:
                self.redis.expire(key, window)
            return

        # ---- in-memory fallback ----
        key = self._mem_key(ip, action)
        self._prune(key, window)
        if key not in self._memory_store:
            self._memory_store[key] = []
        self._memory_store[key].append(time.time())

    def reset(self, ip: str, action: str) -> None:
        """Clear all recorded attempts for *ip* under *action*."""
        if self.redis is not None:
            self.redis.delete(self._redis_key(ip, action))
            return

        # ---- in-memory fallback ----
        self._memory_store.pop(self._mem_key(ip, action), None)


# Singleton — reused across the application
auth_limiter = AuthRateLimiter()

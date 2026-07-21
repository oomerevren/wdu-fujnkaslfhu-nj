"""
Redis-backed rate limiter for auth endpoints.
Falls back to in-memory LRU cache if Redis is unavailable.
Includes periodic pruning to prevent memory leaks.
"""
import time
import threading
from collections import OrderedDict
from typing import Optional

from app.cache.redis_pool import redis_pool

# ── LRU Cache implementation ─────────────────────────────────────────────
MAX_MEMORY_ENTRIES = 10_000
PRUNE_INTERVAL = 300  # 5 minutes


class LRUCache:
    """Thread-safe LRU cache with a fixed maximum size.

    When *maxsize* is exceeded the least-recently-used item is evicted.
    """

    def __init__(self, maxsize: int = MAX_MEMORY_ENTRIES) -> None:
        self._cache: OrderedDict[str, list[float]] = OrderedDict()
        self._maxsize = maxsize
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[list[float]]:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
            return None

    def set(self, key: str, value: list[float]) -> None:
        with self._lock:
            self._cache[key] = value
            self._cache.move_to_end(key)
            if len(self._cache) > self._maxsize:
                self._cache.popitem(last=False)

    def delete(self, key: str) -> None:
        with self._lock:
            self._cache.pop(key, None)

    def prune(self, window: int) -> int:
        """Remove entries older than *window* seconds. Returns count removed."""
        now = time.time()
        removed = 0
        with self._lock:
            stale_keys = []
            for key, timestamps in self._cache.items():
                fresh = [t for t in timestamps if now - t < window]
                if not fresh:
                    stale_keys.append(key)
                else:
                    self._cache[key] = fresh
            for key in stale_keys:
                del self._cache[key]
                removed += 1
        return removed

    def __len__(self) -> int:
        with self._lock:
            return len(self._cache)


# ── Rate limiter ─────────────────────────────────────────────────────────


class AuthRateLimiter:
    """Rate limiter with Redis backend and in-memory LRU fallback.

    Tracks attempt counts per IP per action (e.g. login, register).
    Redis keys follow the pattern: ``auth_rate_limit:{action}:{ip}``

    When Redis is unavailable the in-memory fallback uses an LRU cache
    capped at ``MAX_MEMORY_ENTRIES`` entries and runs a background prune
    thread every ``PRUNE_INTERVAL`` seconds.
    """

    def __init__(self) -> None:
        self.redis: Optional["redis.Redis"] = None  # type: ignore[name-defined]
        self._memory_store: LRUCache = LRUCache()
        self._prune_timer: Optional[threading.Timer] = None
        self._connect_redis()
        self._start_prune_loop()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def _connect_redis(self) -> None:
        """Try connecting to Redis; fall back to in-memory on failure."""
        try:
            self.redis = redis_pool.get_client()
            self.redis.ping()
        except Exception:
            self.redis = None

    def _start_prune_loop(self) -> None:
        """Start a background timer that prunes expired entries periodically."""

        def _prune_worker() -> None:
            removed = self._memory_store.prune(window=self._max_window())
            if removed:
                import logging

                logging.getLogger(__name__).debug(
                    "Pruned %d expired rate-limit entries", removed
                )
            self._start_prune_loop()  # reschedule

        self._prune_timer = threading.Timer(PRUNE_INTERVAL, _prune_worker)
        self._prune_timer.daemon = True
        self._prune_timer.start()

    @staticmethod
    def _max_window() -> int:
        """Return the longest window used anywhere.

        Override this if you add actions with longer windows so the
        background prune does not discard live entries.
        """
        return 3600  # 1 hour — safely covers login/register windows

    def shutdown(self) -> None:
        """Cancel the background prune timer. Idempotent."""
        if self._prune_timer is not None:
            self._prune_timer.cancel()
            self._prune_timer = None

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
        entries = self._memory_store.get(key)
        if entries is not None:
            fresh = [t for t in entries if now - t < window]
            if fresh:
                self._memory_store.set(key, fresh)
            else:
                self._memory_store.delete(key)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def is_rate_limited(
        self, ip: str, action: str, max_attempts: int, window: int
    ) -> bool:
        """Check whether *ip* has exceeded *max_attempts* for *action* within *window* seconds.

        Returns ``True`` when the request should be rejected.
        """
        if self.redis is not None:
            count = self.redis.get(self._redis_key(ip, action))
            return count is not None and int(count) >= max_attempts

        # ---- in-memory fallback ----
        key = self._mem_key(ip, action)
        self._prune(key, window)
        entries = self._memory_store.get(key)
        return entries is not None and len(entries) >= max_attempts

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
        entries = self._memory_store.get(key)
        if entries is None:
            entries = []
        entries.append(time.time())
        self._memory_store.set(key, entries)

    def reset(self, ip: str, action: str) -> None:
        """Clear all recorded attempts for *ip* under *action*."""
        if self.redis is not None:
            self.redis.delete(self._redis_key(ip, action))
            return

        # ---- in-memory fallback ----
        self._memory_store.delete(self._mem_key(ip, action))


# Singleton — reused across the application
auth_limiter = AuthRateLimiter()

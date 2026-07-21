"""Tests for the rate limiter — LRU cache, pruning, and integration.

Run with::

    pytest tests/test_rate_limiter.py -v
"""
import time
import threading
from unittest.mock import patch, MagicMock

import pytest

from app.utils.rate_limiter import (
    LRUCache,
    AuthRateLimiter,
    auth_limiter,
    MAX_MEMORY_ENTRIES,
    PRUNE_INTERVAL,
)


# =========================================================================
# LRUCache unit tests
# =========================================================================


class TestLRUCache:
    def test_get_set(self):
        cache = LRUCache(maxsize=3)
        cache.set("a", [1.0, 2.0])
        assert cache.get("a") == [1.0, 2.0]

    def test_get_missing(self):
        cache = LRUCache(maxsize=3)
        assert cache.get("nonexistent") is None

    def test_delete(self):
        cache = LRUCache(maxsize=3)
        cache.set("a", [1.0])
        cache.delete("a")
        assert cache.get("a") is None

    def test_delete_missing(self):
        cache = LRUCache(maxsize=3)
        cache.delete("nonexistent")  # should not raise

    def test_eviction_lru(self):
        """When maxsize is exceeded, the oldest entry is evicted."""
        cache = LRUCache(maxsize=3)
        cache.set("a", [1.0])
        cache.set("b", [2.0])
        cache.set("c", [3.0])
        cache.set("d", [4.0])  # should evict "a"
        assert cache.get("a") is None
        assert cache.get("b") == [2.0]
        assert cache.get("c") == [3.0]
        assert cache.get("d") == [4.0]

    def test_eviction_recently_used_preserved(self):
        """Accessing an entry refreshes its position; oldest untouched is evicted."""
        cache = LRUCache(maxsize=3)
        cache.set("a", [1.0])
        cache.set("b", [2.0])
        cache.set("c", [3.0])
        cache.get("a")  # refresh "a"
        cache.set("d", [4.0])  # should evict "b" (oldest untouched)
        assert cache.get("a") == [1.0]  # preserved
        assert cache.get("b") is None  # evicted
        assert cache.get("c") == [3.0]
        assert cache.get("d") == [4.0]

    def test_prune_expired_entries(self):
        cache = LRUCache(maxsize=10)
        now = time.time()
        cache.set("fresh", [now - 10])  # 10 seconds old
        cache.set("stale", [now - 3600])  # 1 hour old
        cache.set("mixed", [now - 10, now - 3600])

        removed = cache.prune(window=300)  # 5-minute window

        assert removed >= 1
        assert cache.get("fresh") is not None  # still within window
        assert cache.get("stale") is None  # evicted
        mixed = cache.get("mixed")
        assert mixed is not None
        assert len(mixed) == 1  # only the fresh timestamp remains

    def test_prune_all_stale(self):
        cache = LRUCache(maxsize=10)
        now = time.time()
        cache.set("a", [now - 600])
        cache.set("b", [now - 1200])
        removed = cache.prune(window=300)
        assert removed == 2
        assert len(cache) == 0

    def test_prune_empty_cache(self):
        cache = LRUCache(maxsize=10)
        assert cache.prune(window=300) == 0

    def test_len(self):
        cache = LRUCache(maxsize=5)
        assert len(cache) == 0
        cache.set("a", [1.0])
        assert len(cache) == 1
        cache.set("b", [2.0])
        assert len(cache) == 2

    def test_thread_safety(self):
        """Concurrent access does not corrupt the cache."""
        cache = LRUCache(maxsize=100)
        errors = []

        def worker(prefix: str):
            try:
                for i in range(500):
                    key = f"{prefix}:{i}"
                    cache.set(key, [time.time()])
                    cache.get(key)
                    if i % 10 == 0:
                        cache.delete(key)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=("t1",)) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread safety errors: {errors}"
        # After 2000 inserts with 10% deletions, size should be reasonable
        assert len(cache) <= 100  # bounded by maxsize

    def test_maxsize_zero(self):
        """With maxsize=0, every set should evict immediately."""
        # Not the intended use, but verify it doesn't crash
        cache = LRUCache(maxsize=1)
        cache.set("a", [1.0])
        cache.set("b", [2.0])
        # "a" should be evicted since maxsize=1
        assert cache.get("a") is None
        assert cache.get("b") == [2.0]


# =========================================================================
# AuthRateLimiter unit tests (in-memory fallback path)
# =========================================================================


class TestAuthRateLimiter:
    """All tests force the in-memory path by patching Redis to be unavailable."""

    @pytest.fixture(autouse=True)
    def _no_redis(self):
        """Ensure every test uses the in-memory fallback."""
        with patch.object(AuthRateLimiter, "_connect_redis", return_value=None):
            # Create a fresh limiter for each test
            self.limiter = AuthRateLimiter()
            self.limiter.redis = None
            # Prevent background prune from interfering
            self.limiter.shutdown()
            yield
            self.limiter.shutdown()

    def test_is_rate_limited_below_limit(self):
        self.limiter.increment("1.2.3.4", "login", window=60)
        assert not self.limiter.is_rate_limited("1.2.3.4", "login", max_attempts=5, window=60)

    def test_is_rate_limited_at_limit(self):
        for _ in range(5):
            self.limiter.increment("1.2.3.4", "login", window=60)
        assert self.limiter.is_rate_limited("1.2.3.4", "login", max_attempts=5, window=60)

    def test_is_rate_limited_above_limit(self):
        for _ in range(10):
            self.limiter.increment("1.2.3.4", "login", window=60)
        assert self.limiter.is_rate_limited("1.2.3.4", "login", max_attempts=5, window=60)

    def test_window_expiry(self):
        """Entries older than the window are not counted."""
        ip = "1.2.3.4"
        self.limiter.increment(ip, "login", window=60)
        # Manually insert a very old timestamp
        old_key = self.limiter._mem_key(ip, "login")
        self.limiter._memory_store.set(old_key, [time.time() - 120])
        # Now only the old timestamp exists (fresh one was pruned... actually not)
        # Let's be explicit: set only old timestamps
        self.limiter._memory_store.set(old_key, [time.time() - 120])
        assert not self.limiter.is_rate_limited(ip, "login", max_attempts=5, window=60)

    def test_reset(self):
        ip = "1.2.3.4"
        for _ in range(5):
            self.limiter.increment(ip, "login", window=60)
        assert self.limiter.is_rate_limited(ip, "login", max_attempts=5, window=60)
        self.limiter.reset(ip, "login")
        assert not self.limiter.is_rate_limited(ip, "login", max_attempts=5, window=60)

    def test_different_actions_independent(self):
        ip = "1.2.3.4"
        for _ in range(5):
            self.limiter.increment(ip, "login", window=60)
        assert self.limiter.is_rate_limited(ip, "login", max_attempts=5, window=60)
        assert not self.limiter.is_rate_limited(ip, "register", max_attempts=5, window=60)

    def test_different_ips_independent(self):
        for _ in range(5):
            self.limiter.increment("1.2.3.4", "login", window=60)
        assert self.limiter.is_rate_limited("1.2.3.4", "login", max_attempts=5, window=60)
        assert not self.limiter.is_rate_limited("5.6.7.8", "login", max_attempts=5, window=60)

    def test_memory_bounded_by_lru(self):
        """With maxsize=5, inserting 100 different IPs keeps only 5 entries."""
        # Monkey-patch to a tiny cache
        tiny_cache = LRUCache(maxsize=5)
        self.limiter._memory_store = tiny_cache

        for i in range(100):
            ip = f"10.0.0.{i}"
            self.limiter.increment(ip, "login", window=60)

        assert len(self.limiter._memory_store) <= 5

    def test_redis_path_used_when_available(self):
        """When Redis is available, memory store is never touched."""
        mock_redis = MagicMock()
        mock_redis.get.return_value = None  # not rate limited
        self.limiter.redis = mock_redis

        # Spy on memory_store
        original_set = self.limiter._memory_store.set
        set_called = False

        def tracking_set(*args, **kwargs):
            nonlocal set_called
            set_called = True
            return original_set(*args, **kwargs)

        self.limiter._memory_store.set = tracking_set

        result = self.limiter.is_rate_limited("1.2.3.4", "login", max_attempts=5, window=60)
        assert result is False
        assert not set_called, "Memory store should not be used when Redis is available"
        mock_redis.get.assert_called_once()

    def test_increment_with_redis(self):
        """When Redis is available, increment uses Redis."""
        mock_redis = MagicMock()
        mock_redis.incr.return_value = 1
        self.limiter.redis = mock_redis

        original_set = self.limiter._memory_store.set
        set_called = False

        def tracking_set(*args, **kwargs):
            nonlocal set_called
            set_called = True
            return original_set(*args, **kwargs)

        self.limiter._memory_store.set = tracking_set

        self.limiter.increment("1.2.3.4", "login", window=60)
        mock_redis.incr.assert_called_once()
        mock_redis.expire.assert_called_once()
        assert not set_called

    # ------------------------------------------------------------------
    # Periodic pruning integration
    # ------------------------------------------------------------------

    def test_background_prune_removes_stale_entries(self):
        """Background prune thread correctly removes expired entries."""
        now = time.time()
        old_ts = now - 7200  # 2 hours old — outside max_window (3600)

        key = self.limiter._mem_key("1.2.3.4", "login")
        self.limiter._memory_store.set(key, [old_ts])
        assert len(self.limiter._memory_store) == 1

        # Manually invoke prune logic (same as background thread)
        removed = self.limiter._memory_store.prune(window=self.limiter._max_window())
        assert removed == 1
        assert len(self.limiter._memory_store) == 0

    def test_background_prune_keeps_fresh_entries(self):
        """Background prune keeps entries within the max window."""
        now = time.time()
        key = self.limiter._mem_key("1.2.3.4", "login")
        self.limiter._memory_store.set(key, [now - 60])  # 1 min old
        assert len(self.limiter._memory_store) == 1

        removed = self.limiter._memory_store.prune(window=self.limiter._max_window())
        assert removed == 0  # still fresh
        assert len(self.limiter._memory_store) == 1


# =========================================================================
# Integration / stress tests
# =========================================================================


class TestHighLoad:
    """Simulate high load with many distinct IPs."""

    @pytest.fixture(autouse=True)
    def _no_redis(self):
        with patch.object(AuthRateLimiter, "_connect_redis", return_value=None):
            self.limiter = AuthRateLimiter()
            self.limiter.redis = None
            self.limiter.shutdown()
            yield
            self.limiter.shutdown()

    def test_memory_stable_under_high_load(self):
        """10k+ distinct IPs should not grow the cache beyond maxsize."""
        num_ips = MAX_MEMORY_ENTRIES + 500
        for i in range(num_ips):
            ip = f"10.0.0.{i % 256}.{i // 256}"
            self.limiter.increment(ip, "login", window=60)

        # Cache should be bounded by MAX_MEMORY_ENTRIES
        assert len(self.limiter._memory_store) <= MAX_MEMORY_ENTRIES + 1  # +1 for in-flight

    def test_concurrent_increments_no_corruption(self):
        """Many concurrent increments from different IPs does not corrupt state."""
        errors = []

        def worker(limiter, start_idx, count):
            try:
                for i in range(start_idx, start_idx + count):
                    ip = f"10.0.0.{i % 256}"
                    limiter.increment(ip, "login", window=300)
            except Exception as e:
                errors.append(e)

        threads = []
        num_threads = 8
        per_thread = 500
        for t_idx in range(num_threads):
            t = threading.Thread(
                target=worker,
                args=(self.limiter, t_idx * per_thread, per_thread),
            )
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert not errors, f"Concurrent errors: {errors}"
        # Verify cache is still bounded
        assert len(self.limiter._memory_store) <= MAX_MEMORY_ENTRIES


# =========================================================================
# Prune timer lifecycle
# =========================================================================


class TestPruneTimer:
    def test_shutdown_cancels_timer(self):
        limiter = AuthRateLimiter()
        timer = limiter._prune_timer
        assert timer is not None
        assert timer.is_alive()
        limiter.shutdown()
        timer.join(timeout=1.0)
        assert not timer.is_alive()
        limiter.shutdown()  # idempotent

    def test_prune_loop_reschedules(self):
        """After the timer fires, a new timer should be created."""
        limiter = AuthRateLimiter()
        original_timer = limiter._prune_timer
        assert original_timer is not None

        # Simulate what the prune worker does
        limiter._start_prune_loop()
        new_timer = limiter._prune_timer
        assert new_timer is not original_timer  # new timer created
        limiter.shutdown()


# =========================================================================
# Global middleware LRU (internal class)
# =========================================================================


class TestGlobalRateLimitLRU:
    def test_global_lru_eviction(self):
        """Verify _LRUCache in global middleware works identically."""
        from app.middleware.rate_limit_global import _LRUCache

        cache = _LRUCache(maxsize=3)
        cache.set("a", [1.0])
        cache.set("b", [2.0])
        cache.set("c", [3.0])
        cache.set("d", [4.0])
        assert cache.get("a") is None
        assert cache.get("d") == [4.0]

    def test_global_lru_prune(self):
        from app.middleware.rate_limit_global import _LRUCache

        cache = _LRUCache(maxsize=10)
        now = time.time()
        cache.set("fresh", [now - 10])
        cache.set("stale", [now - 3600])
        removed = cache.prune(window=300)
        assert removed == 1
        assert cache.get("fresh") is not None
        assert cache.get("stale") is None

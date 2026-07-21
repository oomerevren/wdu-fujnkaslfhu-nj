"""
Redis-backed token blacklist and refresh-token tracker.

Provides:
- ``blacklist_token(jti, expires_in)`` — immediately invalidate a token.
- ``is_token_blacklisted(jti)`` → bool — check blacklist status.
- ``store_refresh_token(jti, user_id, ttl)`` — record a refresh token as *active*.
- ``get_refresh_token_status(jti)`` → str | None — returns ``"active"``, ``"used"``,
  ``"revoked"``, or ``None`` if unknown.
- ``mark_refresh_token_used(jti)`` — rotate: mark old token as *used*.
- ``revoke_all_user_tokens(user_id)`` — invalidate every refresh token for a user.

Falls back to an in-memory dict when Redis is unavailable so the application
can still work during development or when Redis is down.
"""

import time
import uuid
from typing import Optional

from app.cache.redis_pool import redis_pool

from app.config import settings

# ── Redis key patterns ────────────────────────────────────────────────────────
_RT_KEY = "refresh_token:{jti}"          # hash → {status, user_id, exp}
_BL_KEY = "blacklist:{jti}"              # key exists → blacklisted
_USER_RT_SET = "user_rt:{user_id}"       # set of jti's for a user


class TokenBlacklist:
    """Redis-backed blacklist + refresh-token tracker with in-memory fallback."""

    def __init__(self) -> None:
        self.redis: Optional["redis.Redis"] = None  # type: ignore[name-defined]
        self._mem_blacklist: dict[str, float] = {}     # jti → expiry timestamp
        self._mem_refresh: dict[str, dict] = {}         # jti → {status, user_id, exp}
        self._mem_user_rt: dict[str, set[str]] = {}     # user_id → set of jti
        self._connect_redis()

    # ── connection ──────────────────────────────────────────────────────────

    def _connect_redis(self) -> None:
        """Try connecting to Redis; fall back to in-memory on failure."""
        try:
            self.redis = redis_pool.get_client()
            self.redis.ping()
        except Exception:
            self.redis = None

    def _is_redis_up(self) -> bool:
        """Quick health-check — returns False if Redis was never connected."""
        if self.redis is None:
            return False
        try:
            self.redis.ping()
            return True
        except Exception:
            self.redis = None
            return False

    # ── blacklist API ───────────────────────────────────────────────────────

    def blacklist_token(self, jti: str, expires_in: int) -> None:
        """Add *jti* to the blacklist for *expires_in* seconds.

        Once added, ``is_token_blacklisted(jti)`` will return ``True``.
        Used for access-token logout.
        """
        if self._is_redis_up():
            self.redis.setex(f"blacklist:{jti}", expires_in, "1")
            return
        # In-memory fallback
        self._mem_blacklist[jti] = time.time() + expires_in

    def is_token_blacklisted(self, jti: str) -> bool:
        """Check whether *jti* has been blacklisted."""
        if self._is_redis_up():
            return bool(self.redis.exists(f"blacklist:{jti}"))
        # In-memory fallback — also prune expired entries
        exp = self._mem_blacklist.get(jti)
        if exp is None:
            return False
        if time.time() > exp:
            del self._mem_blacklist[jti]
            return False
        return True

    # ── refresh-token lifecycle ─────────────────────────────────────────────

    def store_refresh_token(self, jti: str, user_id: str, ttl: int) -> None:
        """Store a refresh token as *active*.

        Args:
            jti: Unique JWT ID for this token.
            user_id: The user this token belongs to.
            ttl: Time-to-live in seconds (typically 30 days = 2 592 000).
        """
        if self._is_redis_up():
            pipe = self.redis.pipeline()
            pipe.hset(
                f"refresh_token:{jti}",
                mapping={"status": "active", "user_id": user_id},
            )
            pipe.expire(f"refresh_token:{jti}", ttl)
            pipe.sadd(f"user_rt:{user_id}", jti)
            pipe.expire(f"user_rt:{user_id}", ttl)
            pipe.execute()
            return
        # In-memory fallback
        self._mem_refresh[jti] = {
            "status": "active",
            "user_id": user_id,
            "exp": time.time() + ttl,
        }
        self._mem_user_rt.setdefault(user_id, set()).add(jti)

    def get_refresh_token_status(self, jti: str) -> Optional[str]:
        """Return the status of a refresh token (``"active"``, ``"used"``,
        ``"revoked"``) or ``None`` if the token is unknown / expired."""
        if self._is_redis_up():
            data = self.redis.hgetall(f"refresh_token:{jti}")
            return data.get("status") if data else None
        # In-memory fallback
        entry = self._mem_refresh.get(jti)
        if entry is None:
            return None
        # Prune expired
        if time.time() > entry["exp"]:
            del self._mem_refresh[jti]
            uid = entry["user_id"]
            self._mem_user_rt.get(uid, set()).discard(jti)
            return None
        return entry["status"]

    def mark_refresh_token_used(self, jti: str) -> None:
        """Mark a refresh token as *used* (after rotation).

        A "used" token is rejected on subsequent refresh attempts.
        """
        if self._is_redis_up():
            self.redis.hset(f"refresh_token:{jti}", "status", "used")
            return
        entry = self._mem_refresh.get(jti)
        if entry is not None:
            entry["status"] = "used"

    def revoke_all_user_tokens(self, user_id: str) -> int:
        """Revoke every refresh token belonging to *user_id*.

        Returns the number of tokens revoked.
        """
        if self._is_redis_up():
            jtis = self.redis.smembers(f"user_rt:{user_id}")
            if not jtis:
                return 0
            pipe = self.redis.pipeline()
            for jti in jtis:
                pipe.hset(f"refresh_token:{jti}", "status", "revoked")
            pipe.delete(f"user_rt:{user_id}")
            pipe.execute()
            return len(jtis)
        # In-memory fallback
        jtis = list(self._mem_user_rt.get(user_id, set()))
        for jti in jtis:
            entry = self._mem_refresh.get(jti)
            if entry is not None:
                entry["status"] = "revoked"
        if jtis:
            del self._mem_user_rt[user_id]
        return len(jtis)


# Singleton — reused across the application
token_blacklist = TokenBlacklist()

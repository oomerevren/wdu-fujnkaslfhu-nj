"""
JWT key rotation manager — HS256→HS512 upgrade enabler.

Provides:
- ``generate_jwt_key()`` — create a cryptographically secure 64-byte (512-bit) key
- ``KeyManager`` — manages active + previous keys with Redis-backed storage

Usage::

    from app.utils.key_rotation import key_manager

    # Sign with the current active key
    signing_key = key_manager.get_signing_key()

    # Verify against any valid key (active + previous)
    for key in key_manager.get_verification_keys():
        try:
            payload = jwt.decode(token, key, algorithms=["HS256", "HS512"])
            break
        except JWTError:
            continue

    # Rotate keys (generates new key, pushes old one to previous)
    key_manager.rotate_key()
"""

import base64
import hashlib
import secrets
import time
from typing import Optional

from app.cache.redis_pool import redis_pool
from app.config import settings


def generate_jwt_key() -> str:
    """Generate a 64-byte (512-bit) cryptographically random key.

    Returns a base64-encoded string for easy storage and transport.
    The key is suitable for HS512 signing.
    """
    key_bytes = secrets.token_bytes(64)
    return base64.b64encode(key_bytes).decode("utf-8")


def _key_id(key: str) -> str:
    """Derive a short, URL-safe key ID from a full key.

    Uses the first 8 bytes of SHA-256(key) → base64 → first 11 chars.
    This is NOT a secret — it's just a label for tracking key versions.
    """
    digest = hashlib.sha256(key.encode()).digest()[:8]
    return base64.urlsafe_b64encode(digest).decode().rstrip("=")


class KeyManager:
    """Manages JWT signing and verification keys with rotation support.

    *Active key* is used for signing new tokens.
    *Previous keys* are retained so tokens signed before rotation can
    still be verified.

    Keys are stored in Redis when available, falling back to an in-memory
    store during development or when Redis is down.

    The initial active key is ``settings.JWT_SECRET_KEY``, ensuring backward
    compatibility with existing deployments.
    """

    # Redis key names
    _ACTIVE_KEY_KEY = "jwt:active_key"
    _PREVIOUS_KEYS_KEY = "jwt:previous_keys"

    def __init__(self) -> None:
        self.redis: Optional["redis.Redis"] = None  # type: ignore[name-defined]
        self._mem_active_key: Optional[str] = None
        self._mem_previous_keys: list[str] = []
        self._mem_last_rotation_time: Optional[float] = None
        self._initialised = False
        self._connect_redis()
        self._ensure_active_key()

    # ── Connection management ────────────────────────────────────────────────

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

    # ── Key lifecycle ────────────────────────────────────────────────────────

    def _ensure_active_key(self) -> None:
        """Ensure an active signing key exists.

        Priority:
        1. Redis ``jwt:active_key``
        2. In-memory ``_mem_active_key``
        3. ``settings.JWT_SECRET_KEY`` (initial key for backward compat)
        4. Generate a fresh key (last resort)
        """
        if self._initialised:
            return

        import time
        now = time.time()

        if self._is_redis_up():
            stored = self.redis.get(self._ACTIVE_KEY_KEY)
            if stored:
                self._mem_active_key = stored
            else:
                # First run — seed with the configured secret key
                self._mem_active_key = settings.JWT_SECRET_KEY
                self.redis.set(self._ACTIVE_KEY_KEY, self._mem_active_key)
                self.redis.set("jwt:last_rotation_time", str(now))

            # Retrieve or seed last rotation time
            rot_time = self.redis.get("jwt:last_rotation_time")
            if not rot_time:
                self.redis.set("jwt:last_rotation_time", str(now))
                self._mem_last_rotation_time = now
            else:
                try:
                    self._mem_last_rotation_time = float(rot_time)
                except ValueError:
                    self._mem_last_rotation_time = now
                    self.redis.set("jwt:last_rotation_time", str(now))
        else:
            if self._mem_active_key is None:
                self._mem_active_key = settings.JWT_SECRET_KEY
            if self._mem_last_rotation_time is None:
                self._mem_last_rotation_time = now

        self._initialised = True

    def get_signing_key(self) -> str:
        """Return the active signing key.

        This key should be used to sign *new* JWT tokens.
        """
        if self._is_redis_up():
            stored = self.redis.get(self._ACTIVE_KEY_KEY)
            if stored:
                self._mem_active_key = stored
                return stored
        if self._mem_active_key is None:
            self._mem_active_key = settings.JWT_SECRET_KEY
        return self._mem_active_key

    def get_verification_keys(self) -> list[str]:
        """Return all keys that can verify existing tokens.

        The first element is the active (current) signing key.
        Subsequent elements are previous keys that are still valid.

        During verification, **all** keys should be tried with both
        ``HS256`` and ``HS512`` algorithms to ensure backward compatibility
        with tokens signed before the HS256→HS512 migration.
        """
        active = self.get_signing_key()
        keys = [active]

        if self._is_redis_up():
            previous = self.redis.smembers(self._PREVIOUS_KEYS_KEY)
            for prev_key in previous:
                if prev_key != active and prev_key not in keys:
                    keys.append(prev_key)
        else:
            for prev_key in self._mem_previous_keys:
                if prev_key != active and prev_key not in keys:
                    keys.append(prev_key)

        return keys

    def get_key_by_id(self, kid: str) -> Optional[str]:
        """Retrieve a specific key by its key ID.

        Useful when you want to verify a token that carries a ``kid`` header.
        """
        for key in self.get_verification_keys():
            if _key_id(key) == kid:
                return key
        return None

    def rotate_key(self) -> str:
        """Generate a new signing key and demote the old one to *previous*.

        The old key remains in the ``previous_keys`` set so that tokens
        signed before rotation can still be verified.

        Returns the **new** active key.
        """
        import time
        old_key = self.get_signing_key()
        new_key = generate_jwt_key()
        now = time.time()

        if self._is_redis_up():
            pipe = self.redis.pipeline()
            pipe.set(self._ACTIVE_KEY_KEY, new_key)
            pipe.set("jwt:last_rotation_time", str(now))
            pipe.sadd(self._PREVIOUS_KEYS_KEY, old_key)
            # Keep previous keys for 90 days (should outlast any token lifetime)
            pipe.expire(self._PREVIOUS_KEYS_KEY, 90 * 24 * 3600)
            pipe.execute()
        else:
            self._mem_previous_keys.append(old_key)
            # Cap in-memory storage to prevent unbounded growth
            if len(self._mem_previous_keys) > 10:
                self._mem_previous_keys = self._mem_previous_keys[-10:]

        self._mem_active_key = new_key
        self._mem_last_rotation_time = now
        return new_key

    def check_and_rotate_key(self, max_age_seconds: int = 30 * 24 * 3600) -> bool:
        """Check the age of the active key and rotate it if it exceeds max_age_seconds.

        Returns True if the key was rotated.
        """
        import time
        now = time.time()
        last_rotation = None

        if self._is_redis_up():
            stored_time = self.redis.get("jwt:last_rotation_time")
            if stored_time:
                try:
                    last_rotation = float(stored_time)
                except ValueError:
                    pass
        else:
            last_rotation = self._mem_last_rotation_time

        if last_rotation is None:
            # If no rotation time exists, seed it now (don't rotate yet)
            if self._is_redis_up():
                self.redis.set("jwt:last_rotation_time", str(now))
            self._mem_last_rotation_time = now
            return False

        if now - last_rotation >= max_age_seconds:
            self.rotate_key()
            return True

        return False


# Module-level singleton — import this everywhere
key_manager = KeyManager()

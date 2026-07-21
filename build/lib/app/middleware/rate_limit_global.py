import time
import re
from typing import Optional
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response, JSONResponse
from app.cache.redis_pool import redis_pool


SLIDING_WINDOW = 60

USER_LIMIT = 100
IP_LIMIT = 10
SCAN_CREATE_LIMIT = 5
REPORT_LIMIT = 3

SCAN_PATH_PATTERN = re.compile(r"^/api/v1/scans/?$")
REPORT_PATH_PATTERN = re.compile(r"^/api/v1/reports/?$")


class GlobalRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app):
        super().__init__(app)
        self._redis: Optional["redis.Redis"] = None  # type: ignore[name-defined]
        self._memory_store: dict[str, list[float]] = {}
        self._connect_redis()

    def _connect_redis(self):
        try:
            self._redis = redis_pool.get_client()
            self._redis.ping()
        except Exception:
            self._redis = None

    def _mem_key(self, key: str) -> str:
        return f"rate_limit:{key}"

    def _redis_key(self, key: str) -> str:
        return f"global_rate_limit:{key}"

    def _prune(self, key: str):
        now = time.time()
        if key in self._memory_store:
            self._memory_store[key] = [t for t in self._memory_store[key] if now - t < SLIDING_WINDOW]

    def _count_and_append(self, key: str, window: int) -> tuple[int, float]:
        now = time.time()
        reset_at = now + window
        if self._redis is not None:
            rkey = self._redis_key(key)
            count = self._redis.incr(rkey)
            if count == 1:
                self._redis.expire(rkey, window)
            ttl = self._redis.ttl(rkey)
            if ttl > 0:
                reset_at = now + ttl
            return count, reset_at
        mkey = self._mem_key(key)
        self._prune(mkey)
        if mkey not in self._memory_store:
            self._memory_store[mkey] = []
        self._memory_store[mkey].append(now)
        return len(self._memory_store[mkey]), reset_at

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        path = request.url.path
        method = request.method

        user_id: Optional[str] = None
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
            if token and not self._is_jwt(token):
                user_id = self._resolve_user_from_path(request)

        ip = request.client.host if request.client else "unknown"

        limits = []

        if user_id:
            limits.append((f"user:{user_id}", USER_LIMIT))
        else:
            limits.append((f"ip:{ip}", IP_LIMIT))

        if method in ("POST", "PUT") and SCAN_PATH_PATTERN.match(path):
            limits.append((f"scan_create:{user_id or ip}", SCAN_CREATE_LIMIT))
        if REPORT_PATH_PATTERN.match(path):
            limits.append((f"report:{user_id or ip}", REPORT_LIMIT))

        for key, max_count in limits:
            count, reset_at = self._count_and_append(key, SLIDING_WINDOW)
            remaining = max(0, max_count - count)

            if count > max_count:
                retry_after = int(reset_at - time.time())
                if retry_after < 0:
                    retry_after = 1
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": {
                            "code": 429,
                            "message": "Too many requests. Please slow down.",
                            "type": "rate_limit",
                        }
                    },
                    headers={
                        "Retry-After": str(retry_after),
                        "X-RateLimit-Limit": str(max_count),
                        "X-RateLimit-Remaining": "0",
                        "X-RateLimit-Reset": str(int(reset_at)),
                    },
                )

        response = await call_next(request)

        response.headers["X-RateLimit-Limit"] = str(max_count)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(int(reset_at))

        return response

    @staticmethod
    def _is_jwt(token: str) -> bool:
        return len(token.split(".")) == 3

    @staticmethod
    def _resolve_user_from_path(request: Request) -> Optional[str]:
        return None

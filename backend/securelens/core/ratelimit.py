"""In-process sliding-window rate limiting.

Suitable for a single API instance. Behind several instances, put a shared
limiter (reverse proxy or gateway) in front; account lockout for login is
stored in the database and therefore already shared.
"""

from __future__ import annotations

import threading
import time
from collections import deque

from starlette.requests import Request

from securelens.core.config import get_settings


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: float = 60.0, max_keys: int = 50_000) -> None:
        self.limit = limit
        self.window = window_seconds
        self.max_keys = max_keys
        self._hits: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def hit(self, key: str) -> tuple[bool, float]:
        """Record a hit. Returns (allowed, retry_after_seconds)."""
        now = time.monotonic()
        with self._lock:
            if len(self._hits) > self.max_keys:
                self._evict(now)
            bucket = self._hits.setdefault(key, deque())
            while bucket and now - bucket[0] > self.window:
                bucket.popleft()
            if len(bucket) >= self.limit:
                return False, max(0.0, self.window - (now - bucket[0]))
            bucket.append(now)
            return True, 0.0

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()

    def _evict(self, now: float) -> None:
        stale = [k for k, b in self._hits.items() if not b or now - b[-1] > self.window]
        for key in stale:
            del self._hits[key]


def client_ip(request: Request) -> str:
    hops = get_settings().trusted_proxy_hops
    if hops:
        forwarded = request.headers.get("x-forwarded-for", "")
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if len(parts) >= hops:
            return parts[-hops][:64]
    return (request.client.host if request.client else "unknown")[:64]


_general: SlidingWindowLimiter | None = None
_login: SlidingWindowLimiter | None = None


def general_limiter() -> SlidingWindowLimiter:
    global _general
    if _general is None:
        _general = SlidingWindowLimiter(get_settings().rate_limit_per_minute)
    return _general


def login_limiter() -> SlidingWindowLimiter:
    global _login
    if _login is None:
        _login = SlidingWindowLimiter(get_settings().login_rate_limit_per_minute)
    return _login


def reset_limiters() -> None:
    global _general, _login
    _general = None
    _login = None

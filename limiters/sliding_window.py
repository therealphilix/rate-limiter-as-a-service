"""
limiters/sliding_window.py
--------------------------
Sliding window counter algorithm.

How it works:
  - Every request is stored as an entry in a Redis sorted set.
  - The score is the request's timestamp in milliseconds.
  - On each check, entries older than (now - window) are evicted first,
    then we count what's left. If count < limit, the request is allowed.

Tradeoff to know:
  Memory grows with request volume — each request is one sorted set entry.
  Under a DDoS this gets expensive. Fine for normal traffic; in M5 you'd
  add a circuit breaker or cap the sorted set size.
"""

import pathlib
import time

from .base import RateLimiter, RateLimitConfig, RateLimitResult


class SlidingWindowLimiter(RateLimiter):

    def _load_script(self):
        path = pathlib.Path(__file__).parent.parent / "scripts" / "sliding_window.lua"
        return self.redis.register_script(path.read_text())

    async def check(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        now_ms    = int(time.time() * 1000)
        window_ms = config.window_seconds * 1000

        result = await self.script(
            keys=[key],
            args=[now_ms, window_ms, config.limit],
        )

        # Script returns: [allowed (0|1), remaining, retry_after_seconds]
        allowed     = bool(result[0])
        remaining   = int(result[1])
        retry_after = int(result[2])

        return RateLimitResult(
            allowed=allowed,
            limit=config.limit,
            remaining=remaining,
            retry_after=retry_after,
        )
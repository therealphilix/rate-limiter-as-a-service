"""
limiters/token_bucket.py
------------------------
Token bucket algorithm.

How it works:
  - A bucket holds up to `capacity` tokens.
  - Tokens refill at `refill_rate` per second (continuously, not in batches).
  - Each request consumes one token.
  - If the bucket is empty, the request is denied.

Why this is different from sliding window:
  - Sliding window is strict — it enforces an exact count per time window.
  - Token bucket allows bursts — a user who's been idle can fire `capacity`
    requests instantly, then is throttled to `refill_rate` requests/second.
  - Use sliding window when you want hard per-window limits (e.g. "100 API
    calls per minute, no exceptions").
  - Use token bucket when you want to allow legitimate bursts (e.g. a mobile
    app that batches requests after the user comes back online).
"""

import pathlib
import time

from .base import RateLimiter, RateLimitConfig, RateLimitResult


class TokenBucketLimiter(RateLimiter):

    def _load_script(self):
        path = pathlib.Path(__file__).parent.parent / "scripts" / "token_bucket.lua"
        return self.redis.register_script(path.read_text())

    async def check(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        # Token bucket uses fractional seconds for finer-grained refill math.
        # e.g. refill_rate=0.5 means one token every 2 seconds — you need
        # sub-second precision to calculate that correctly.
        now = time.time()

        result = await self.script(
            keys=[key],
            args=[config.capacity, config.refill_rate, now],
        )

        # Script returns: [allowed (0|1), remaining_tokens, retry_after_seconds]
        allowed     = bool(result[0])
        remaining   = int(result[1])
        retry_after = int(result[2])

        return RateLimitResult(
            allowed=allowed,
            limit=config.capacity,      # "limit" = bucket capacity for token bucket
            remaining=remaining,
            retry_after=retry_after,
        )
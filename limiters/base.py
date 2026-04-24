"""
limiters/base.py
----------------
The Strategy pattern lives here.

A "strategy" is just a swappable algorithm behind a fixed interface.
The route handler only ever calls  limiter.check(key, config)  — it
has no idea whether sliding window or token bucket is underneath.

Adding a third algorithm later (leaky bucket, fixed window, etc.) means:
  1. Write a new class that inherits RateLimiter
  2. Implement check()
  3. Register it in ALGORITHM_MAP in __init__.py
  4. Touch nothing else

That's the payoff of the pattern.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class RateLimitConfig:
    """
    Everything an algorithm needs to make a decision.

    Both algorithms share this config shape — they just use different fields.
    Sliding window uses: limit, window_seconds.
    Token bucket uses:   capacity, refill_rate.

    In M3 these values come from the database per-tenant. For now they're
    passed in from environment variables.
    """
    limit:          int    # sliding window: max requests per window
    window_seconds: int    # sliding window: window size in seconds
    capacity:       int    # token bucket: max tokens (burst ceiling)
    refill_rate:    float  # token bucket: tokens added per second


@dataclass
class RateLimitResult:
    """
    The single return type every algorithm produces.

    The route handler reads this and builds the HTTP response.
    It never needs to know which algorithm produced it.
    """
    allowed:     bool
    limit:       int    # the effective limit (requests or tokens)
    remaining:   int    # how many left before blocking
    retry_after: int    # seconds until a slot opens; 0 if allowed


class RateLimiter(ABC):
    """
    Abstract base class — defines the interface, nothing more.

    Every concrete algorithm must:
      - Accept a Redis client in __init__
      - Load its Lua script at construction time
      - Implement check() using that script
    """

    def __init__(self, redis_client):
        # Each algorithm loads its own Lua script and registers it
        # with Redis at construction time, not on every request.
        self.redis = redis_client
        self.script = self._load_script()

    @abstractmethod
    def _load_script(self):
        """
        Load and register the Lua script with Redis.
        Must return a Script object from redis-py's register_script().
        """
        ...

    @abstractmethod
    async def check(self, key: str, config: RateLimitConfig) -> RateLimitResult:
        """
        Ask: is this key allowed to make a request right now?
        Atomically checks and (if allowed) records the request.

        key    — the Redis key for this identifier, e.g. "rl:user:42"
        config — the rule governing this key
        """
        ...
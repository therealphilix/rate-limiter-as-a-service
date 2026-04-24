"""
limiters/__init__.py
--------------------
The algorithm registry — maps string names to concrete classes.

This is the only place in the codebase that knows both algorithm names
and their implementations. main.py reads ALGORITHM from .env, looks it
up here, and gets back a class. It never imports SlidingWindowLimiter
or TokenBucketLimiter directly.

To add a third algorithm:
  1. Write the class in its own file (limiters/leaky_bucket.py)
  2. Add one line to ALGORITHM_MAP below
  3. Done — nothing else changes
"""

from .base import RateLimiter, RateLimitConfig, RateLimitResult
from .sliding_window import SlidingWindowLimiter
from .token_bucket import TokenBucketLimiter

ALGORITHM_MAP: dict[str, type[RateLimiter]] = {
    "sliding_window": SlidingWindowLimiter,
    "token_bucket":   TokenBucketLimiter,
}

__all__ = [
    "RateLimiter",
    "RateLimitConfig",
    "RateLimitResult",
    "ALGORITHM_MAP",
]
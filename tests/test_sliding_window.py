"""
tests/test_sliding_window.py
-----------------------------
Tests for the sliding window algorithm in isolation — no HTTP layer,
no auth, no DB. Just the limiter class and fakeredis.

Testing the algorithm directly (not via HTTP) means:
  - Failures point at the algorithm, not the routing or auth layer
  - You can test edge cases (exact boundary, concurrent keys) cleanly
  - Tests run faster — no middleware overhead
"""

import time
import pytest
from limiters.base import RateLimitConfig


# Standard config used across most tests
LIMIT  = 5
WINDOW = 60


def make_config(limit=LIMIT, window=WINDOW) -> RateLimitConfig:
    return RateLimitConfig(
        limit=limit,
        window_seconds=window,
        capacity=limit,
        refill_rate=1.0,
    )


# ---------------------------------------------------------------------------
# Core behaviour
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_allows_requests_under_limit(sliding_window_limiter):
    """Requests 1 through LIMIT should all be allowed."""
    config = make_config()

    for i in range(LIMIT):
        result = await sliding_window_limiter.check("rl:user:1", config)
        assert result.allowed is True, f"Request {i+1} should be allowed"
        assert result.remaining == LIMIT - i - 1


@pytest.mark.asyncio
async def test_blocks_request_over_limit(sliding_window_limiter):
    """The (LIMIT + 1)th request must be denied."""
    config = make_config()

    for _ in range(LIMIT):
        await sliding_window_limiter.check("rl:user:2", config)

    result = await sliding_window_limiter.check("rl:user:2", config)

    assert result.allowed is False
    assert result.remaining == 0
    assert result.retry_after > 0


@pytest.mark.asyncio
async def test_remaining_decrements_correctly(sliding_window_limiter):
    """remaining should count down from (limit-1) to 0."""
    config = make_config(limit=3)

    r1 = await sliding_window_limiter.check("rl:user:3", config)
    r2 = await sliding_window_limiter.check("rl:user:3", config)
    r3 = await sliding_window_limiter.check("rl:user:3", config)

    assert r1.remaining == 2
    assert r2.remaining == 1
    assert r3.remaining == 0


@pytest.mark.asyncio
async def test_retry_after_is_positive_when_blocked(sliding_window_limiter):
    """retry_after must be > 0 when blocked, telling caller when to retry."""
    config = make_config(limit=1)

    await sliding_window_limiter.check("rl:user:4", config)
    result = await sliding_window_limiter.check("rl:user:4", config)

    assert result.allowed is False
    assert result.retry_after > 0
    assert result.retry_after <= WINDOW


# ---------------------------------------------------------------------------
# Key isolation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_different_keys_are_independent(sliding_window_limiter):
    """
    Exhausting the limit for user:A must not affect user:B.
    This verifies the Redis key namespacing is correct.
    """
    config = make_config(limit=2)

    # Exhaust user:A
    await sliding_window_limiter.check("rl:user:A", config)
    await sliding_window_limiter.check("rl:user:A", config)
    blocked = await sliding_window_limiter.check("rl:user:A", config)
    assert blocked.allowed is False

    # user:B should be completely unaffected
    result = await sliding_window_limiter.check("rl:user:B", config)
    assert result.allowed is True
    assert result.remaining == 1


# ---------------------------------------------------------------------------
# Limit values
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_limit_of_one(sliding_window_limiter):
    """Edge case: limit=1 means the first request is allowed, second blocked."""
    config = make_config(limit=1)

    first  = await sliding_window_limiter.check("rl:user:5", config)
    second = await sliding_window_limiter.check("rl:user:5", config)

    assert first.allowed is True
    assert first.remaining == 0
    assert second.allowed is False


@pytest.mark.asyncio
async def test_result_carries_correct_limit(sliding_window_limiter):
    """result.limit should always reflect the configured limit."""
    config = make_config(limit=10)
    result = await sliding_window_limiter.check("rl:user:6", config)
    assert result.limit == 10


# ---------------------------------------------------------------------------
# Window expiry (time-travel test)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_entries_outside_window_are_not_counted(sliding_window_limiter, fake_redis):
    """
    Manually inject old sorted set entries (outside the window) and verify
    they don't count toward the limit.

    This is a "time-travel" test — instead of actually waiting 60 seconds,
    we write entries with timestamps in the past directly to fakeredis.
    """
    config = make_config(limit=2, window=10)
    key    = "rl:user:7"
    now_ms = int(time.time() * 1000)

    # Write two entries that are 20 seconds old — outside the 10s window
    old_ts = now_ms - 20_000
    await fake_redis.zadd(key, {f"old-entry-1": old_ts})
    await fake_redis.zadd(key, {f"old-entry-2": old_ts})

    # Both requests should still be allowed because old entries are evicted
    r1 = await sliding_window_limiter.check(key, config)
    r2 = await sliding_window_limiter.check(key, config)

    assert r1.allowed is True
    assert r2.allowed is True
    # Third request should now be blocked (limit=2, two fresh entries exist)
    r3 = await sliding_window_limiter.check(key, config)
    assert r3.allowed is False
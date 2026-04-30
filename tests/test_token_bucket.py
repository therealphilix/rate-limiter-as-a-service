"""
tests/test_token_bucket.py
--------------------------
Tests for the token bucket algorithm in isolation.

Token bucket has one behaviour that sliding window doesn't: bursts.
The tests here specifically verify that burst tolerance works correctly —
a user can fire up to `capacity` requests instantly, then gets throttled
to `refill_rate` per second.

The time-travel pattern is used heavily here: instead of sleeping,
we write bucket state directly to fakeredis with timestamps in the past
to simulate time passing.
"""

import time
import pytest
from limiters.base import RateLimitConfig


def make_config(capacity=5, refill_rate=1.0) -> RateLimitConfig:
    return RateLimitConfig(
        limit=capacity,
        window_seconds=60,
        capacity=capacity,
        refill_rate=refill_rate,
    )


# ---------------------------------------------------------------------------
# Core behaviour
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_full_bucket_allows_burst(token_bucket_limiter):
    """A fresh bucket should allow `capacity` requests immediately."""
    config = make_config(capacity=5)

    for i in range(5):
        result = await token_bucket_limiter.check("rl:tb:user:1", config)
        assert result.allowed is True, f"Burst request {i+1} should be allowed"


@pytest.mark.asyncio
async def test_empty_bucket_blocks_request(token_bucket_limiter):
    """After the burst is exhausted, the next request is denied."""
    config = make_config(capacity=3)

    for _ in range(3):
        await token_bucket_limiter.check("rl:tb:user:2", config)

    result = await token_bucket_limiter.check("rl:tb:user:2", config)
    assert result.allowed is False
    assert result.retry_after > 0


@pytest.mark.asyncio
async def test_remaining_counts_down(token_bucket_limiter):
    """tokens_remaining should decrement with each request."""
    config = make_config(capacity=3)

    r1 = await token_bucket_limiter.check("rl:tb:user:3", config)
    r2 = await token_bucket_limiter.check("rl:tb:user:3", config)
    r3 = await token_bucket_limiter.check("rl:tb:user:3", config)

    assert r1.remaining == 2
    assert r2.remaining == 1
    assert r3.remaining == 0


# ---------------------------------------------------------------------------
# Refill behaviour (time-travel tests)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_tokens_refill_over_time(token_bucket_limiter, fake_redis):
    """
    Simulate an empty bucket that has had time to refill.

    We write a bucket state to fakeredis with last_refill set 3 seconds
    ago and tokens=0. With refill_rate=1.0, 3 seconds should have added
    3 tokens. The next request should be allowed with 2 remaining.
    """
    config = make_config(capacity=5, refill_rate=1.0)
    key    = "rl:tb:user:4"
    now    = time.time()

    # Manually write an empty bucket with a stale last_refill timestamp
    await fake_redis.hmset(key, {
        "tokens":      "0",
        "last_refill": str(now - 3.0),  # 3 seconds ago
    })

    result = await token_bucket_limiter.check(key, config)

    assert result.allowed is True
    # 3 tokens refilled, 1 consumed → 2 remaining
    assert result.remaining == 2


@pytest.mark.asyncio
async def test_tokens_capped_at_capacity(token_bucket_limiter, fake_redis):
    """
    Even if a lot of time has passed, the bucket can't exceed capacity.
    """
    config = make_config(capacity=5, refill_rate=1.0)
    key    = "rl:tb:user:5"
    now    = time.time()

    # Bucket empty, last refill was 1000 seconds ago
    await fake_redis.hmset(key, {
        "tokens":      "0",
        "last_refill": str(now - 1000),
    })

    result = await token_bucket_limiter.check(key, config)

    # Should have 5 tokens (capped at capacity), 1 consumed → 4 remaining
    assert result.allowed is True
    assert result.remaining == 4


@pytest.mark.asyncio
async def test_fractional_refill_rate(token_bucket_limiter, fake_redis):
    """
    refill_rate=0.5 means one token every 2 seconds.
    After 1 second, not enough tokens to allow a request.
    After 2 seconds, exactly one token — request allowed.
    """
    config = make_config(capacity=5, refill_rate=0.5)
    key    = "rl:tb:user:6"
    now    = time.time()

    # Empty bucket, 1 second elapsed — only 0.5 tokens refilled, not enough
    await fake_redis.hmset(key, {
        "tokens":      "0",
        "last_refill": str(now - 1.0),
    })
    result_insufficient = await token_bucket_limiter.check(key, config)
    assert result_insufficient.allowed is False

    # Empty bucket, 2 seconds elapsed — 1.0 tokens refilled, just enough
    await fake_redis.hmset(key, {
        "tokens":      "0",
        "last_refill": str(now - 2.0),
    })
    result_sufficient = await token_bucket_limiter.check(key, config)
    assert result_sufficient.allowed is True


# ---------------------------------------------------------------------------
# Key isolation
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_different_keys_independent(token_bucket_limiter):
    """Exhausting one key's bucket must not affect another key."""
    config = make_config(capacity=2)

    await token_bucket_limiter.check("rl:tb:A", config)
    await token_bucket_limiter.check("rl:tb:A", config)
    blocked = await token_bucket_limiter.check("rl:tb:A", config)
    assert blocked.allowed is False

    fresh = await token_bucket_limiter.check("rl:tb:B", config)
    assert fresh.allowed is True
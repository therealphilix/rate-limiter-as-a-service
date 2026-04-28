"""
routers/stats.py
----------------
Live stats for any rate limit key, read directly from Redis.

This endpoint is useful for:
  - Debugging: "why is user:42 getting blocked?"
  - Support: "how many requests does this tenant have left?"
  - Monitoring: feed into a dashboard or alerting rule

It reads the raw Redis state and returns it in a human-friendly shape.
No DB calls — purely Redis.
"""

import json
import time
import uuid

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel

from db.engine import get_db
from services.rules import _rule_cache_key
import os

log    = structlog.get_logger()
router = APIRouter(prefix="/v1", tags=["stats"])

ADMIN_SECRET = os.getenv("ADMIN_SECRET", "change-me-in-production")


def require_admin(x_admin_secret: str = Header(...)):
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Invalid admin secret.")


# ---------------------------------------------------------------------------
# Response schemas
# ---------------------------------------------------------------------------

class SlidingWindowStats(BaseModel):
    algorithm:         str = "sliding_window"
    key:               str
    limit:             int
    used:              int
    remaining:         int
    window_seconds:    int
    oldest_request_at: float | None  # unix timestamp
    reset_at:          float         # unix timestamp


class TokenBucketStats(BaseModel):
    algorithm:      str = "token_bucket"
    key:            str
    capacity:       int
    tokens_current: float
    refill_rate:    float
    last_refill_at: float | None  # unix timestamp


class KeyStats(BaseModel):
    key:       str
    found:     bool
    algorithm: str | None = None
    # One of the above will be populated depending on algorithm
    data:      dict | None = None


# ---------------------------------------------------------------------------
# Stats endpoint
# ---------------------------------------------------------------------------

@router.get("/stats/{tenant_id}/{resource}/{identifier}", response_model=KeyStats)
async def get_stats(
    tenant_id:  uuid.UUID,
    resource:   str,
    identifier: str,
    request:    Request,
    _: None = Depends(require_admin),
):
    """
    Get the current rate limit state for a specific key.

    The key is constructed from (tenant_id, resource, identifier) —
    the same way the check endpoint constructs it.

    Returns the raw Redis state: what's in the sorted set (sliding window)
    or the token count (token bucket).
    """
    redis        = request.app.state.redis
    redis_key    = f"rl:{tenant_id}:{resource}:{identifier}"
    now          = time.time()
    now_ms       = int(now * 1000)

    # First, look up what algorithm this tenant uses for this resource
    # so we know how to interpret the Redis data
    algorithm = await _get_algorithm(tenant_id, resource, redis)

    if algorithm is None:
        return KeyStats(key=redis_key, found=False)

    if algorithm == "sliding_window":
        stats = await _sliding_window_stats(redis, redis_key, now_ms)
    elif algorithm == "token_bucket":
        stats = await _token_bucket_stats(redis, redis_key)
    else:
        raise HTTPException(status_code=500, detail=f"Unknown algorithm: {algorithm}")

    if stats is None:
        # Key exists in rule config but hasn't been used yet (no Redis entry)
        return KeyStats(key=redis_key, found=False, algorithm=algorithm)

    return KeyStats(key=redis_key, found=True, algorithm=algorithm, data=stats)


@router.get("/stats/summary/{tenant_id}")
async def get_tenant_summary(
    tenant_id: uuid.UUID,
    request:   Request,
    _: None = Depends(require_admin),
):
    """
    Count all active rate limit keys for a tenant using Redis SCAN.

    SCAN iterates the keyspace without blocking Redis (unlike KEYS which
    blocks until it finishes — dangerous on large keyspaces).
    Returns the count and a sample of up to 20 active keys.

    Use this to detect runaway key cardinality: if a bug is creating keys
    with random identifiers, you'll see the count explode here.
    """
    redis   = request.app.state.redis
    pattern = f"rl:{tenant_id}:*"
    keys    = []

    # SCAN with COUNT is a hint to Redis about batch size, not a hard limit.
    # We iterate until the cursor returns to 0 (full scan complete).
    cursor = 0
    while True:
        cursor, batch = await redis.scan(cursor, match=pattern, count=100)
        keys.extend(batch)
        if cursor == 0:
            break

    # Decode bytes keys
    decoded = [k.decode() if isinstance(k, bytes) else k for k in keys]

    return {
        "tenant_id":  str(tenant_id),
        "total_keys": len(decoded),
        "sample":     decoded[:20],  # don't return thousands of keys
    }


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

async def _get_algorithm(
    tenant_id: uuid.UUID,
    resource:  str,
    redis,
) -> str | None:
    """
    Read the algorithm name from the rule cache.
    Returns None if no cached rule exists for this tenant/resource.
    """
    for res in [resource, "*"]:
        cached = await redis.get(_rule_cache_key(tenant_id, res))
        if cached:
            data = json.loads(cached)
            return data.get("algorithm")
    return None


async def _sliding_window_stats(redis, key: str, now_ms: int) -> dict | None:
    """Read the sorted set and return window stats."""
    # Check if key exists
    exists = await redis.exists(key)
    if not exists:
        return None

    # Get all entries in the sorted set with their scores (timestamps)
    entries = await redis.zrangebyscore(key, "-inf", "+inf", withscores=True)
    if not entries:
        return None

    count      = len(entries)
    oldest_ts  = float(entries[0][1]) / 1000   # convert ms → seconds
    now_s      = now_ms / 1000

    # Get the TTL to infer window_seconds
    ttl = await redis.ttl(key)

    return {
        "used":              count,
        "oldest_request_at": oldest_ts,
        "reset_at":          oldest_ts + ttl,
        "window_seconds":    ttl,
        "sampled_at":        now_s,
    }


async def _token_bucket_stats(redis, key: str) -> dict | None:
    """Read the hash fields and return bucket stats."""
    exists = await redis.exists(key)
    if not exists:
        return None

    bucket = await redis.hmget(key, "tokens", "last_refill")
    if not bucket[0]:
        return None

    tokens      = float(bucket[0])
    last_refill = float(bucket[1]) if bucket[1] else None

    return {
        "tokens_current": round(tokens, 4),
        "last_refill_at": last_refill,
    }
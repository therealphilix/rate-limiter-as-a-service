"""
services/rules.py
-----------------
Cache-aside rule loading — the pattern that makes M3 production-viable.

The problem:
  Every call to POST /v1/check needs to know: what algorithm? what limit?
  what window? That data lives in Postgres. If we hit Postgres on every
  single check request, we've just made the rate limiter slower than the
  service it's protecting — and we've coupled our availability to Postgres.

The solution — cache-aside:
  1. Check Redis first (cheap, ~0.5ms)
  2. On a cache miss, load from Postgres (~5ms) and write to Redis
  3. Serve from Redis for the next RULE_CACHE_TTL seconds

This means Postgres only sees traffic when:
  - A key hasn't been used in RULE_CACHE_TTL seconds
  - A rule is updated (we invalidate the cache entry)
  - The service restarts

Under steady traffic, nearly 100% of requests are served from Redis alone.

The pattern is called "cache-aside" (vs "write-through") because the
application manages the cache explicitly — it's not automatic. The tradeoff:
a rule change takes up to RULE_CACHE_TTL seconds to propagate. That's
acceptable here (a limit change from 100 to 50 req/min taking 30s to
propagate won't hurt anyone). If you needed instant propagation, you'd
publish a cache-invalidation event on rule update.
"""

import json
import uuid

import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import APIKey, RateLimitRule
from limiters import RateLimitConfig

# How long a cached rule stays fresh.
# 30 seconds is a reasonable default: low enough that config changes
# propagate quickly, high enough to absorb most DB load.
RULE_CACHE_TTL = 30  # seconds

# How long a cached tenant_id (from API key auth) stays fresh.
# 5 minutes: keys don't change often, and the savings vs bcrypt on every
# request are enormous.
AUTH_CACHE_TTL = 300  # seconds


def _rule_cache_key(tenant_id: uuid.UUID, resource: str) -> str:
    """Redis key for a cached rule. Example: rule_cache:abc-123:payments:create"""
    return f"rule_cache:{tenant_id}:{resource}"


def _auth_cache_key(key_prefix: str) -> str:
    """
    Redis key for a cached tenant_id lookup.
    We use the first 16 chars of the API key as the cache key — unique
    enough to avoid collisions, short enough to be safe to log/store.
    """
    return f"auth_cache:{key_prefix[:16]}"


# ---------------------------------------------------------------------------
# Auth caching
# ---------------------------------------------------------------------------

async def get_tenant_id_cached(
    plaintext_key: str,
    db: AsyncSession,
    redis_client: aioredis.Redis,
) -> uuid.UUID | None:
    """
    Get tenant_id for an API key, using Redis as a cache in front of bcrypt.

    Cache hit  → return tenant_id immediately (~0.5ms, no bcrypt)
    Cache miss → bcrypt verify against DB (~250ms), then cache the result
    """
    cache_key = _auth_cache_key(plaintext_key)

    # 1. Try the cache first
    cached = await redis_client.get(cache_key)
    if cached:
        # Cache hit — decode and return immediately
        tenant_str = cached.decode() if isinstance(cached, bytes) else cached
        return uuid.UUID(tenant_str)

    # 2. Cache miss — do the expensive bcrypt lookup
    from services.auth import get_tenant_from_key
    tenant_id = await get_tenant_from_key(plaintext_key, db)

    if tenant_id is None:
        # Don't cache failed lookups — we don't want to lock out a key
        # that was just activated, and failed lookups are cheap to repeat.
        return None

    # 3. Write to cache
    await redis_client.setex(cache_key, AUTH_CACHE_TTL, str(tenant_id))

    return tenant_id


async def invalidate_auth_cache(plaintext_key: str, redis_client: aioredis.Redis):
    """
    Call this when a key is revoked or deactivated.
    Ensures the revocation takes effect immediately, not after TTL expiry.
    """
    cache_key = _auth_cache_key(plaintext_key)
    await redis_client.delete(cache_key)


# ---------------------------------------------------------------------------
# Rule loading
# ---------------------------------------------------------------------------

async def get_rule_cached(
    tenant_id: uuid.UUID,
    resource: str,
    db: AsyncSession,
    redis_client: aioredis.Redis,
) -> RateLimitConfig | None:
    """
    Load the rate limit rule for (tenant_id, resource), cache-aside.

    Lookup order:
      1. Redis cache → exact resource match
      2. Redis cache → wildcard "*" rule
      3. Postgres    → exact resource match
      4. Postgres    → wildcard "*" rule
      5. None        → no rule found, caller decides what to do

    Caching both the specific rule and the wildcard separately means a
    tenant with 50 resources and one wildcard rule still gets cache hits
    for all 50 — we never load the wildcard from Postgres on a per-resource
    basis after the first hit.
    """

    # --- Step 1: Check Redis for an exact resource match ---
    exact_cache_key = _rule_cache_key(tenant_id, resource)
    cached_rule = await redis_client.get(exact_cache_key)

    if cached_rule:
        return _deserialize_rule(cached_rule)

    # --- Step 2: Check Redis for a wildcard rule ---
    wildcard_cache_key = _rule_cache_key(tenant_id, "*")
    cached_wildcard = await redis_client.get(wildcard_cache_key)

    if cached_wildcard:
        return _deserialize_rule(cached_wildcard)

    # --- Step 3: Cache miss — go to Postgres ---
    # Try exact match first
    result = await db.execute(
        select(RateLimitRule).where(
            RateLimitRule.tenant_id == tenant_id,
            RateLimitRule.resource == resource,
            RateLimitRule.is_active == True,  # noqa: E712
        )
    )
    rule = result.scalar_one_or_none()

    # --- Step 4: Fall back to wildcard if no exact match ---
    if rule is None and resource != "*":
        result = await db.execute(
            select(RateLimitRule).where(
                RateLimitRule.tenant_id == tenant_id,
                RateLimitRule.resource == "*",
                RateLimitRule.is_active == True,  # noqa: E712
            )
        )
        rule = result.scalar_one_or_none()

    # --- Step 5: No rule found ---
    if rule is None:
        return None

    # --- Write to cache ---
    config = _rule_to_config(rule)
    cache_key = _rule_cache_key(tenant_id, rule.resource)
    await redis_client.setex(
        cache_key,
        RULE_CACHE_TTL,
        _serialize_rule(config, rule.algorithm),
    )

    return config


async def invalidate_rule_cache(
    tenant_id: uuid.UUID,
    resource: str,
    redis_client: aioredis.Redis,
):
    """
    Evict a rule from the cache immediately.
    Call this from the admin API (M4) after updating or deleting a rule.
    """
    await redis_client.delete(_rule_cache_key(tenant_id, resource))


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------
# Rules are stored in Redis as JSON strings. These helpers convert between
# the DB model, the JSON cache, and the RateLimitConfig the limiter needs.

def _rule_to_config(rule: RateLimitRule) -> RateLimitConfig:
    return RateLimitConfig(
        limit=rule.limit,
        window_seconds=rule.window_seconds,
        capacity=rule.capacity,
        refill_rate=rule.refill_rate,
    )


def _serialize_rule(config: RateLimitConfig, algorithm: str) -> str:
    """Pack a RateLimitConfig + algorithm name into a JSON string for Redis."""
    return json.dumps({
        "limit":          config.limit,
        "window_seconds": config.window_seconds,
        "capacity":       config.capacity,
        "refill_rate":    config.refill_rate,
        "algorithm":      algorithm,
    })


def _deserialize_rule(raw: bytes | str) -> RateLimitConfig:
    """Unpack a cached JSON string back into a RateLimitConfig."""
    data = json.loads(raw)
    return RateLimitConfig(
        limit=data["limit"],
        window_seconds=data["window_seconds"],
        capacity=data["capacity"],
        refill_rate=data["refill_rate"],
    )
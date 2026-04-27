"""
Rate Limiter — Milestone 3
--------------------------
The check endpoint now:
  1. Reads X-API-Key from the request header
  2. Resolves it to a tenant_id (Redis cache → bcrypt → Postgres)
  3. Loads the rule for (tenant_id, resource) (Redis cache → Postgres)
  4. Picks the right algorithm from the rule
  5. Runs the check against Redis
  6. Returns the result

Steps 2 and 3 almost always hit Redis only. Postgres is the fallback.
"""

import time
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from dotenv import load_dotenv
import os

from db.engine import engine, get_db
from db.models import Base
from limiters import ALGORITHM_MAP, RateLimitConfig
from services.rules import get_rule_cached, get_tenant_id_cached

load_dotenv()

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/1")

# Fallback config — used if a tenant has no matching rule.
# "fail open" (allow the request) is the safe default here: better to let
# a request through than to block a paying customer because they forgot to
# create a rule. Make this configurable in M5.
FALLBACK_ALLOW = os.getenv("FALLBACK_ALLOW", "true").lower() == "true"


# ---------------------------------------------------------------------------
# Startup / shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all tables if they don't exist.
    # In production you'd use Alembic migrations instead — but for local
    # development this gets you running without a migration step.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    redis_client = aioredis.from_url(REDIS_URL, decode_responses=False)

    # Pre-instantiate all algorithm classes so their Lua scripts are
    # registered with Redis at startup, not on the first request.
    limiters = {
        name: cls(redis_client)
        for name, cls in ALGORITHM_MAP.items()
    }

    app.state.redis   = redis_client
    app.state.limiters = limiters

    print(f"Redis     : {REDIS_URL}")
    print(f"Algorithms: {list(limiters.keys())}")
    print("Tables    : created (if not exists)")

    yield

    await redis_client.aclose()
    await engine.dispose()


app = FastAPI(title="Rate Limiter — M3", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Auth dependency
# ---------------------------------------------------------------------------

async def get_current_tenant(
    request: Request,
    x_api_key: str = Header(..., description="Your API key (rl_live_...)"),
    db: AsyncSession = Depends(get_db),
):
    """
    FastAPI dependency that resolves X-API-Key → tenant_id.

    Raises 401 if the key is missing, invalid, or inactive.
    Inject this into any route that requires authentication.

    Usage:
        @app.post("/v1/check")
        async def check(tenant_id = Depends(get_current_tenant)):
            ...
    """
    tenant_id = await get_tenant_id_cached(
        plaintext_key=x_api_key,
        db=db,
        redis_client=request.app.state.redis,
    )

    if tenant_id is None:
        raise HTTPException(
            status_code=401,
            detail="Invalid or inactive API key.",
            headers={"WWW-Authenticate": "ApiKey"},
        )

    return tenant_id


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class CheckRequest(BaseModel):
    identifier: str   # e.g. "user:42" or "ip:1.2.3.4"
    resource:   str   # e.g. "payments:create" or "users:list"


class CheckResponse(BaseModel):
    allowed:     bool
    limit:       int
    remaining:   int
    retry_after: int | None
    algorithm:   str   # now exposed so clients know which rule matched


# ---------------------------------------------------------------------------
# Check endpoint
# ---------------------------------------------------------------------------

@app.post("/v1/check", response_model=CheckResponse)
async def check(
    body: CheckRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    tenant_id=Depends(get_current_tenant),
):
    # --- Load rule (cache-aside) ---
    rule = await get_rule_cached(
        tenant_id=tenant_id,
        resource=body.resource,
        db=db,
        redis_client=request.app.state.redis,
    )

    if rule is None:
        if FALLBACK_ALLOW:
            # No rule configured — allow the request and return a synthetic response.
            # The client can detect this via "algorithm": "none".
            return CheckResponse(
                allowed=True, limit=0, remaining=0,
                retry_after=None, algorithm="none"
            )
        else:
            raise HTTPException(
                status_code=403,
                detail=f"No rate limit rule found for resource {body.resource!r}."
            )

    # --- Pick algorithm from the cached rule ---
    # The rule serialization in rules.py stores the algorithm name alongside
    # the config. We need to re-derive it here. In M4 we'll clean this up
    # by including algorithm in RateLimitConfig directly.
    #
    # For now: try to load from cache, fall back to a DB read.
    # Quick workaround: store algorithm in config (we'll refactor in M4)
    algorithm_name = await _get_algorithm_for_rule(
        tenant_id, body.resource, request.app.state.redis, db
    )
    limiter = request.app.state.limiters.get(algorithm_name)
    if limiter is None:
        raise HTTPException(status_code=500, detail=f"Unknown algorithm: {algorithm_name}")

    # --- Build the Redis key ---
    # Namespace: rl:{tenant_id}:{resource}:{identifier}
    # This ensures tenants never share counters even for the same resource + identifier.
    redis_key = f"rl:{tenant_id}:{body.resource}:{body.identifier}"

    # --- Run the check ---
    try:
        result = await limiter.check(redis_key, rule)
    except aioredis.RedisError as exc:
        raise HTTPException(status_code=503, detail=f"Redis error: {exc}")

    # --- Build response headers ---
    headers = {
        "X-RateLimit-Limit":     str(result.limit),
        "X-RateLimit-Remaining": str(result.remaining),
        "X-RateLimit-Reset":     str(int(time.time()) + rule.window_seconds),
        "X-Tenant-Id":           str(tenant_id),
    }
    if result.retry_after:
        headers["Retry-After"] = str(result.retry_after)

    return JSONResponse(
        status_code=200 if result.allowed else 429,
        content=CheckResponse(
            allowed=result.allowed,
            limit=result.limit,
            remaining=result.remaining,
            retry_after=result.retry_after if not result.allowed else None,
            algorithm=algorithm_name,
        ).model_dump(),
        headers=headers,
    )


async def _get_algorithm_for_rule(tenant_id, resource, redis_client, db) -> str:
    """
    Read the algorithm name for a (tenant, resource) pair.
    Checks the Redis cache first (it's stored in the JSON blob), then DB.

    This is a temporary helper — in M4 we'll include algorithm directly
    in RateLimitConfig and remove this extra lookup.
    """
    import json
    from services.rules import _rule_cache_key

    # Try to get it from the Redis cache (it's already there from get_rule_cached)
    for res in [resource, "*"]:
        cached = await redis_client.get(_rule_cache_key(tenant_id, res))
        if cached:
            data = json.loads(cached)
            return data.get("algorithm", "sliding_window")

    # Fallback to DB
    from sqlalchemy import select
    from db.models import RateLimitRule
    result = await db.execute(
        select(RateLimitRule.algorithm).where(
            RateLimitRule.tenant_id == tenant_id,
            RateLimitRule.resource.in_([resource, "*"]),
            RateLimitRule.is_active == True,  # noqa: E712
        ).order_by(
            # Prefer exact match over wildcard
            (RateLimitRule.resource == resource).desc()
        ).limit(1)
    )
    row = result.scalar_one_or_none()
    return row or "sliding_window"


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
async def health(request: Request):
    try:
        await request.app.state.redis.ping()
        return {
            "status":     "ok",
            "redis":      "connected",
            "algorithms": list(request.app.state.limiters.keys()),
        }
    except aioredis.RedisError:
        raise HTTPException(status_code=503, detail="Redis unavailable")
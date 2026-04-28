"""
Rate Limiter — Milestone 4
--------------------------
New in this milestone:
  - structlog configured at startup
  - RequestLoggingMiddleware logs every HTTP request
  - /v1/check emits a rich structured log line per decision
  - /admin router for key + rule management
  - /v1/stats router for live Redis state
"""

import time
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
import structlog
from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from dotenv import load_dotenv
import os

from db.engine import engine, get_db
from db.models import Base
from limiters import ALGORITHM_MAP
from logging_config import RequestLoggingMiddleware, setup_logging
from routers.admin import router as admin_router
from routers.stats import router as stats_router
from services.rules import get_rule_cached, get_tenant_id_cached

load_dotenv()

# Set up logging FIRST — before any other imports that might log
setup_logging()
log = structlog.get_logger()

REDIS_URL    = os.getenv("REDIS_URL", "redis://localhost:6379")
FALLBACK_ALLOW = os.getenv("FALLBACK_ALLOW", "true").lower() == "true"
ADMIN_SECRET = os.getenv("ADMIN_SECRET", "change-me-in-production")


# ---------------------------------------------------------------------------
# Startup / shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    redis_client = aioredis.from_url(REDIS_URL, decode_responses=False)

    limiters = {
        name: cls(redis_client)
        for name, cls in ALGORITHM_MAP.items()
    }

    app.state.redis    = redis_client
    app.state.limiters = limiters

    log.info("startup_complete", redis=REDIS_URL, algorithms=list(limiters.keys()))

    yield

    await redis_client.aclose()
    await engine.dispose()
    log.info("shutdown_complete")


app = FastAPI(title="Rate Limiter — M4", lifespan=lifespan)

# Middleware runs on every request — register before routes
app.add_middleware(RequestLoggingMiddleware)

# Mount routers
app.include_router(admin_router)
app.include_router(stats_router)


# ---------------------------------------------------------------------------
# Auth dependency (same as M3)
# ---------------------------------------------------------------------------

async def get_current_tenant(
    request: Request,
    x_api_key: str = Header(...),
    db: AsyncSession = Depends(get_db),
):
    tenant_id = await get_tenant_id_cached(
        plaintext_key=x_api_key,
        db=db,
        redis_client=request.app.state.redis,
    )
    if tenant_id is None:
        raise HTTPException(status_code=401, detail="Invalid or inactive API key.")
    return tenant_id


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class CheckRequest(BaseModel):
    identifier: str
    resource:   str


class CheckResponse(BaseModel):
    allowed:     bool
    limit:       int
    remaining:   int
    retry_after: int | None
    algorithm:   str


# ---------------------------------------------------------------------------
# Check endpoint — now with structured logging
# ---------------------------------------------------------------------------

@app.post("/v1/check", response_model=CheckResponse)
async def check(
    body: CheckRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
    tenant_id=Depends(get_current_tenant),
):
    start = time.perf_counter()

    # --- Load rule ---
    rule = await get_rule_cached(
        tenant_id=tenant_id,
        resource=body.resource,
        db=db,
        redis_client=request.app.state.redis,
    )

    if rule is None:
        log.warning(
            "rate_limit_check",
            tenant_id=str(tenant_id),
            resource=body.resource,
            identifier=body.identifier,
            outcome="no_rule",
            allowed=FALLBACK_ALLOW,
        )
        if FALLBACK_ALLOW:
            return CheckResponse(
                allowed=True, limit=0, remaining=0,
                retry_after=None, algorithm="none"
            )
        raise HTTPException(status_code=403, detail="No rule found.")

    # --- Get algorithm ---
    algorithm_name = await _get_algorithm_for_rule(
        tenant_id, body.resource, request.app.state.redis, db
    )
    limiter = request.app.state.limiters.get(algorithm_name)
    if not limiter:
        raise HTTPException(status_code=500, detail=f"Unknown algorithm: {algorithm_name}")

    redis_key = f"rl:{tenant_id}:{body.resource}:{body.identifier}"

    # --- Run check ---
    try:
        result = await limiter.check(redis_key, rule)
    except aioredis.RedisError as exc:
        log.error("redis_error", error=str(exc))
        raise HTTPException(status_code=503, detail=f"Redis error: {exc}")

    latency_ms = round((time.perf_counter() - start) * 1000, 2)

    # --- The money log line ---
    # Every check emits exactly one structured event. This is what you'd
    # query in Datadog/Loki to answer operational questions:
    #   - "Which tenants are being blocked most?" → filter allowed=false, group by tenant_id
    #   - "What's p99 check latency?"             → percentile on latency_ms
    #   - "Which resources hit limits most?"      → group by resource, filter allowed=false
    log.info(
        "rate_limit_check",
        tenant_id=str(tenant_id),
        resource=body.resource,
        identifier=body.identifier,
        algorithm=algorithm_name,
        allowed=result.allowed,
        limit=result.limit,
        remaining=result.remaining,
        retry_after=result.retry_after,
        latency_ms=latency_ms,
        # outcome is redundant with allowed but makes filtering easier
        outcome="allowed" if result.allowed else "denied",
    )

    headers = {
        "X-RateLimit-Limit":     str(result.limit),
        "X-RateLimit-Remaining": str(result.remaining),
        "X-RateLimit-Reset":     str(int(time.time()) + rule.window_seconds),
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
    import json
    from services.rules import _rule_cache_key
    for res in [resource, "*"]:
        cached = await redis_client.get(_rule_cache_key(tenant_id, res))
        if cached:
            return json.loads(cached).get("algorithm", "sliding_window")
    from sqlalchemy import select
    from db.models import RateLimitRule
    result = await db.execute(
        select(RateLimitRule.algorithm).where(
            RateLimitRule.tenant_id == tenant_id,
            RateLimitRule.resource.in_([resource, "*"]),
            RateLimitRule.is_active == True,  # noqa: E712
        ).limit(1)
    )
    return result.scalar_one_or_none() or "sliding_window"


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
async def health(request: Request):
    try:
        await request.app.state.redis.ping()
        return {"status": "ok", "redis": "connected"}
    except aioredis.RedisError:
        raise HTTPException(status_code=503, detail="Redis unavailable")
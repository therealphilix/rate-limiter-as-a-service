"""
Rate Limiter — Milestone 2
--------------------------
The route handler no longer knows or cares which algorithm runs.
It calls limiter.check(key, config) and gets a RateLimitResult back.
Swapping algorithms is now a one-line .env change.
"""

import time
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import os

from limiters import ALGORITHM_MAP, RateLimitConfig

load_dotenv()

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

REDIS_URL      = os.getenv("REDIS_URL", "redis://localhost:6379/1")
ALGORITHM      = os.getenv("ALGORITHM", "sliding_window")  # or "token_bucket"

# Sliding window config
RATE_LIMIT     = int(os.getenv("RATE_LIMIT", "10"))
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "60"))

# Token bucket config
CAPACITY       = int(os.getenv("CAPACITY", "10"))
REFILL_RATE    = float(os.getenv("REFILL_RATE", "1.0"))  # tokens per second


# ---------------------------------------------------------------------------
# Startup / shutdown
# ---------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Validate the algorithm name early — fail loud at startup, not on first request
    if ALGORITHM not in ALGORITHM_MAP:
        raise ValueError(
            f"Unknown ALGORITHM={ALGORITHM!r}. "
            f"Valid options: {list(ALGORITHM_MAP.keys())}"
        )

    client = aioredis.from_url(REDIS_URL, decode_responses=False)

    # Instantiate the chosen algorithm class.
    # The class loads and registers its Lua script here, once, at startup.
    limiter_class  = ALGORITHM_MAP[ALGORITHM]
    app.state.limiter = limiter_class(client)
    app.state.redis   = client

    print(f"Algorithm : {ALGORITHM}")
    print(f"Redis     : {REDIS_URL}")

    yield

    await client.aclose()


app = FastAPI(title="Rate Limiter — M2", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Shared config builder
# ---------------------------------------------------------------------------
# In M3 this will be replaced by a DB lookup per tenant+resource.
# For now it just reads from environment variables.

def get_config() -> RateLimitConfig:
    return RateLimitConfig(
        limit=RATE_LIMIT,
        window_seconds=WINDOW_SECONDS,
        capacity=CAPACITY,
        refill_rate=REFILL_RATE,
    )


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class CheckRequest(BaseModel):
    identifier: str


class CheckResponse(BaseModel):
    allowed:     bool
    limit:       int
    remaining:   int
    window:      int | None   # only meaningful for sliding window
    retry_after: int | None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.post("/v1/check", response_model=CheckResponse)
async def check(body: CheckRequest, request: Request):
    redis_key = f"rl:{body.identifier}"
    config    = get_config() 

    try:
        # This is the entire route handler's knowledge of the algorithm: none.
        # It calls check(), gets a result, builds a response.
        result = await request.app.state.limiter.check(redis_key, config)
    except aioredis.RedisError as exc:
        raise HTTPException(status_code=503, detail=f"Redis error: {exc}")

    headers = {
        "X-RateLimit-Limit":     str(result.limit),
        "X-RateLimit-Remaining": str(result.remaining),
        "X-RateLimit-Reset":     str(int(time.time()) + WINDOW_SECONDS),
    }
    if result.retry_after:
        headers["Retry-After"] = str(result.retry_after)

    return JSONResponse(
        status_code=200 if result.allowed else 429,
        content=CheckResponse(
            allowed=result.allowed,
            limit=result.limit,
            remaining=result.remaining,
            window=WINDOW_SECONDS if ALGORITHM == "sliding_window" else None,
            retry_after=result.retry_after if not result.allowed else None,
        ).model_dump(),
        headers=headers,
    )


@app.get("/health")
async def health(request: Request):
    try:
        await request.app.state.redis.ping()
        return {"status": "ok", "redis": "connected", "algorithm": ALGORITHM}
    except aioredis.RedisError:
        raise HTTPException(status_code=503, detail="Redis unavailable")
"""
Rate Limiter — Milestone 1
--------------------------
One endpoint. One algorithm. Everything hardcoded from .env.
Goal: prove the Lua script runs atomically and the response shape is correct.
"""

import time
import pathlib
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from dotenv import load_dotenv
import os

load_dotenv()

# ---------------------------------------------------------------------------
# Config — all from .env, no magic
# ---------------------------------------------------------------------------

REDIS_URL      = os.getenv("REDIS_URL", "redis://localhost:6379/1")
RATE_LIMIT     = int(os.getenv("RATE_LIMIT", "10"))
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "60"))

# ---------------------------------------------------------------------------
# Redis setup
# ---------------------------------------------------------------------------
# We store the client and the compiled Lua script on app.state so they're
# created once at startup and shared across all requests. Creating a new
# Redis connection per request would be extremely wasteful.

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Run on startup: connect to Redis and register the Lua script."""

    # decode_responses=False because our Lua script returns a list of ints,
    # not strings. If decode_responses=True, redis-py tries to decode bytes
    # as UTF-8 and integer returns become strings — confusing.
    client = aioredis.from_url(REDIS_URL, decode_responses=False)

    # Load the Lua script from disk and register it with Redis.
    # register_script() sends the script to Redis using SCRIPT LOAD, which
    # returns a SHA hash. On each call, Redis executes the cached script by
    # SHA instead of re-parsing the Lua source — faster and bandwidth-efficient.
    lua_path = pathlib.Path(__file__).parent / "scripts" / "sliding_window.lua"
    script_source = lua_path.read_text()
    app.state.redis  = client
    app.state.script = client.register_script(script_source)

    print(f"Connected to Redis at {REDIS_URL}")
    print(f"Config: limit={RATE_LIMIT} requests / {WINDOW_SECONDS}s window")

    yield  # <-- app runs here

    # Shutdown: close the Redis connection pool cleanly.
    await client.aclose()
    print("Redis connection closed")


app = FastAPI(title="Rate Limiter — M1", lifespan=lifespan)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class CheckRequest(BaseModel):
    identifier: str  # e.g. "user:42" or "ip:192.168.1.1"


class CheckResponse(BaseModel):
    allowed:     bool
    limit:       int
    remaining:   int
    window:      int   # seconds
    retry_after: int | None  # seconds until a slot opens; null if allowed


# ---------------------------------------------------------------------------
# Core check endpoint
# ---------------------------------------------------------------------------

@app.post("/v1/check", response_model=CheckResponse)
async def check(body: CheckRequest, request: Request):
    """
    Ask: is this identifier allowed to make a request right now?

    The Redis key is namespaced as  rl:{identifier}  so different identifiers
    never interfere. In M3 we'll add a tenant prefix: rl:{tenant}:{resource}:{id}
    """

    redis_key  = f"rl:{body.identifier}"
    now_ms     = int(time.time() * 1000)   # milliseconds — higher resolution
    window_ms  = WINDOW_SECONDS * 1000

    try:
        # Execute the Lua script atomically.
        # KEYS and ARGV map directly to KEYS[] and ARGV[] inside the script.
        result = await request.app.state.script(
            keys=[redis_key],
            args=[now_ms, window_ms, RATE_LIMIT],
        )
    except aioredis.RedisError as exc:
        # In M5 we'll handle this with fail-open/fail-closed policy.
        # For now, surface it as a 503 so we know something's wrong.
        raise HTTPException(status_code=503, detail=f"Redis error: {exc}")

    # result is a list: [allowed (0|1), remaining (int), retry_after (int)]
    allowed     = bool(result[0])
    remaining   = int(result[1])
    retry_after = int(result[2]) if not allowed else None

    # Standard headers — most rate-limited APIs return these.
    # Clients can read them without parsing the body.
    headers = {
        "X-RateLimit-Limit":     str(RATE_LIMIT),
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Reset":     str(int(time.time()) + WINDOW_SECONDS),
    }
    if retry_after:
        headers["Retry-After"] = str(retry_after)

    status_code = 200 if allowed else 429  # 429 = Too Many Requests

    return JSONResponse(
        status_code=status_code,
        content=CheckResponse(
            allowed=allowed,
            limit=RATE_LIMIT,
            remaining=remaining,
            window=WINDOW_SECONDS,
            retry_after=retry_after,
        ).model_dump(),
        headers=headers,
    )


# ---------------------------------------------------------------------------
# Health check — always useful to have
# ---------------------------------------------------------------------------

@app.get("/health")
async def health(request: Request):
    """Ping Redis and confirm the service is alive."""
    try:
        await request.app.state.redis.ping()
        return {"status": "ok", "redis": "connected"}
    except aioredis.RedisError:
        raise HTTPException(status_code=503, detail="Redis unavailable")


# ---------------------------------------------------------------------------
# Debug endpoint — only useful in development
# ---------------------------------------------------------------------------

@app.get("/v1/debug/{identifier}")
async def debug(identifier: str, request: Request):
    """
    Peek at the raw sorted set for an identifier.
    Shows you exactly what's stored in Redis right now.
    Delete this before M3 — it exposes internals.
    """
    redis_key  = f"rl:{identifier}"
    now_ms     = int(time.time() * 1000)
    window_ms  = WINDOW_SECONDS * 1000
    window_start = now_ms - window_ms

    # Read the sorted set without modifying it
    entries = await request.app.state.redis.zrangebyscore(
        redis_key, window_start, "+inf", withscores=True
    )

    return {
        "key":          redis_key,
        "count":        len(entries),
        "limit":        RATE_LIMIT,
        "window_start": window_start,
        "now":          now_ms,
        "entries":      [
            {"member": e[0].decode(), "score_ms": int(e[1])}
            for e in entries
        ],
    }
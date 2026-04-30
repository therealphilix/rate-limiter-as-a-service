"""
tests/conftest.py
-----------------
Shared fixtures for every test module.

Key tools:
  fakeredis  — an in-memory Redis implementation that runs in the same
               process as your tests. No Docker needed. Supports sorted
               sets, hashes, TTLs, Lua scripts — everything we use.

  SQLite     — an in-memory SQLite database replaces Postgres for tests.
               SQLAlchemy async works with aiosqlite just as it does with
               asyncpg, so the ORM code is tested identically.

  httpx      — AsyncClient lets you send real HTTP requests to the FastAPI
               app without spinning up a server. Requests go through the
               full middleware stack, auth, routing — everything.

Why not mock Redis calls with unittest.mock?
  Mocking redis.get() and redis.set() individually tests nothing useful —
  you're just verifying that your code calls the mocks you set up.
  fakeredis actually executes the Lua scripts, enforces TTLs, and behaves
  like a real Redis. You catch real bugs: wrong key names, wrong script
  arguments, off-by-one errors in the Lua logic.
"""

import asyncio
import uuid
from typing import AsyncGenerator

import fakeredis.aioredis as fakeredis
import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from db.engine import get_db
from db.models import Base
from limiters import ALGORITHM_MAP
from services.auth import generate_api_key, hash_key

# ---------------------------------------------------------------------------
# Pytest-asyncio config
# ---------------------------------------------------------------------------
# "auto" mode means every async test function is automatically treated as
# a coroutine — no need to decorate each one with @pytest.mark.asyncio

pytest_plugins = ("pytest_asyncio",)


# ---------------------------------------------------------------------------
# Event loop
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def event_loop():
    """Single event loop shared across the entire test session."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


# ---------------------------------------------------------------------------
# In-memory SQLite database
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(scope="function")
async def db_engine():
    """
    Fresh in-memory SQLite database per test function.
    Creates all tables, yields the engine, drops everything after.
    """
    engine = create_async_engine(
        "sqlite+aiosqlite:///:memory:",
        echo=False,
    )
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def db_session(db_engine) -> AsyncGenerator[AsyncSession, None]:
    """One DB session per test, rolled back after each test."""
    session_factory = async_sessionmaker(
        bind=db_engine, expire_on_commit=False
    )
    async with session_factory() as session:
        yield session


# ---------------------------------------------------------------------------
# Fake Redis
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(scope="function")
async def fake_redis():
    """
    Fresh fakeredis instance per test.
    fakeredis.aioredis is a drop-in async replacement for redis.asyncio.
    It supports everything we use: ZADD, ZRANGEBYSCORE, HMSET, EVAL, EXPIRE.
    """
    client = fakeredis.FakeRedis(decode_responses=False)
    yield client
    await client.flushall()
    await client.aclose()


# ---------------------------------------------------------------------------
# Pre-built algorithm instances
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(scope="function")
async def sliding_window_limiter(fake_redis):
    """SlidingWindowLimiter wired to fake Redis."""
    from limiters.sliding_window import SlidingWindowLimiter
    return SlidingWindowLimiter(fake_redis)


@pytest_asyncio.fixture(scope="function")
async def token_bucket_limiter(fake_redis):
    """TokenBucketLimiter wired to fake Redis."""
    from limiters.token_bucket import TokenBucketLimiter
    return TokenBucketLimiter(fake_redis)


# ---------------------------------------------------------------------------
# Test data helpers
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(scope="function")
async def test_tenant(db_session) -> dict:
    """
    Create one API key + one sliding window rule and return their details.
    Most tests use this as a baseline tenant.
    """
    from db.models import APIKey, RateLimitRule

    tenant_id = uuid.uuid4()
    plaintext = generate_api_key()

    key = APIKey(
        key_hash=hash_key(plaintext),
        label="test",
        tenant_id=tenant_id,
    )
    rule = RateLimitRule(
        tenant_id=tenant_id,
        resource="test:resource",
        algorithm="sliding_window",
        limit=5,
        window_seconds=60,
        capacity=5,
        refill_rate=1.0,
    )
    db_session.add(key)
    db_session.add(rule)
    await db_session.commit()

    return {
        "tenant_id":    tenant_id,
        "plaintext_key": plaintext,
        "resource":     "test:resource",
        "limit":        5,
    }


# ---------------------------------------------------------------------------
# Full app client — wires everything together
# ---------------------------------------------------------------------------

@pytest_asyncio.fixture(scope="function")
async def client(fake_redis, db_engine) -> AsyncGenerator[AsyncClient, None]:
    """
    AsyncClient that sends requests through the full FastAPI app.

    We override two dependencies:
      get_db    → uses our in-memory SQLite session
      app.state.redis → uses our fake Redis instance

    This means requests go through:
      - Real auth middleware
      - Real route handlers
      - Real algorithm logic
      - Fake Redis (no network)
      - Fake Postgres (no network)

    It's as close to a real integration test as you can get without
    actual infrastructure.
    """
    from main import app

    # Override the DB dependency to use our test SQLite engine
    session_factory = async_sessionmaker(bind=db_engine, expire_on_commit=False)

    async def override_get_db():
        async with session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise

    app.dependency_overrides[get_db] = override_get_db

    # Override app state to use fake Redis
    # We do this via lifespan by patching state directly after startup
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        # Inject fake Redis into app state after lifespan startup
        app.state.redis = fake_redis
        app.state.limiters = {
            name: cls(fake_redis)
            for name, cls in ALGORITHM_MAP.items()
        }
        yield ac

    app.dependency_overrides.clear()
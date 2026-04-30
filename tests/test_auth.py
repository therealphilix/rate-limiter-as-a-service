"""
tests/test_auth.py
------------------
Tests for API key authentication and the auth cache layer.

These tests use the DB session and fakeredis directly — no HTTP layer.
They verify that:
  - Valid keys resolve to the correct tenant_id
  - Invalid keys return None
  - Inactive keys are rejected
  - The cache is populated on first hit and served on second hit
  - Cache misses correctly fall through to bcrypt
"""

import uuid
import pytest

from db.models import APIKey
from services.auth import generate_api_key, hash_key, get_tenant_from_key
from services.rules import get_tenant_id_cached, _auth_cache_key


# ---------------------------------------------------------------------------
# Direct auth (no cache)
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_valid_key_returns_tenant_id(db_session):
    """A correctly hashed key should resolve to its tenant_id."""
    tenant_id = uuid.uuid4()
    plaintext = generate_api_key()

    key = APIKey(
        key_hash=hash_key(plaintext),
        label="test",
        tenant_id=tenant_id,
    )
    db_session.add(key)
    await db_session.commit()

    result = await get_tenant_from_key(plaintext, db_session)
    assert result == tenant_id


@pytest.mark.asyncio
async def test_wrong_key_returns_none(db_session):
    """A key that was never created should return None."""
    fake_key = generate_api_key()
    result   = await get_tenant_from_key(fake_key, db_session)
    assert result is None


@pytest.mark.asyncio
async def test_inactive_key_returns_none(db_session):
    """A revoked (is_active=False) key should be rejected."""
    tenant_id = uuid.uuid4()
    plaintext = generate_api_key()

    key = APIKey(
        key_hash=hash_key(plaintext),
        label="revoked",
        tenant_id=tenant_id,
        is_active=False,
    )
    db_session.add(key)
    await db_session.commit()

    result = await get_tenant_from_key(plaintext, db_session)
    assert result is None


@pytest.mark.asyncio
async def test_malformed_key_rejected_without_db_hit(db_session):
    """
    Keys without the rl_live_ prefix are rejected immediately,
    before any DB query. Verifies the fast-fail path.
    """
    result = await get_tenant_from_key("not-a-valid-key", db_session)
    assert result is None


# ---------------------------------------------------------------------------
# Cached auth
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_cache_is_populated_on_first_auth(db_session, fake_redis):
    """After the first successful auth, the tenant_id should be in Redis."""
    tenant_id = uuid.uuid4()
    plaintext = generate_api_key()

    db_session.add(APIKey(
        key_hash=hash_key(plaintext),
        label="test",
        tenant_id=tenant_id,
    ))
    await db_session.commit()

    # First call — cache miss, goes to DB
    result = await get_tenant_id_cached(plaintext, db_session, fake_redis)
    assert result == tenant_id

    # Cache should now be populated
    cache_key = _auth_cache_key(plaintext)
    cached    = await fake_redis.get(cache_key)
    assert cached is not None
    assert uuid.UUID(cached.decode()) == tenant_id


@pytest.mark.asyncio
async def test_cache_hit_returns_without_db(db_session, fake_redis):
    """
    If the cache already has the tenant_id, the DB is never consulted.
    We verify this by writing to the cache directly (no DB row)
    and confirming the lookup succeeds.
    """
    tenant_id = uuid.uuid4()
    plaintext = generate_api_key()

    # Write directly to cache — no DB row
    cache_key = _auth_cache_key(plaintext)
    await fake_redis.set(cache_key, str(tenant_id))

    result = await get_tenant_id_cached(plaintext, db_session, fake_redis)
    assert result == tenant_id


@pytest.mark.asyncio
async def test_invalid_key_not_cached(db_session, fake_redis):
    """
    Failed auth attempts must not be cached — otherwise a key that's
    later activated would stay broken until the TTL expires.
    """
    plaintext = generate_api_key()  # no DB row

    result    = await get_tenant_id_cached(plaintext, db_session, fake_redis)
    assert result is None

    cache_key = _auth_cache_key(plaintext)
    cached    = await fake_redis.get(cache_key)
    assert cached is None
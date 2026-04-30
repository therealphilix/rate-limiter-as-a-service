"""
tests/test_admin.py
-------------------
HTTP-level tests for the admin API.

These go through the full stack: AsyncClient → FastAPI routing →
auth middleware → DB → response. They test the contract the admin
API exposes, not implementation details.
"""

import uuid
import pytest

ADMIN_SECRET = "change-me-in-production"
HEADERS      = {"x-admin-secret": ADMIN_SECRET}


# ---------------------------------------------------------------------------
# API Key management
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_key_returns_plaintext_once(client):
    """
    Creating a key should return the plaintext exactly once.
    The response must include the rl_live_ prefix.
    """
    response = await client.post(
        "/admin/keys",
        json={"label": "production"},
        headers=HEADERS,
    )
    assert response.status_code == 201

    data = response.json()
    assert data["plaintext_key"].startswith("rl_live_")
    assert data["label"] == "production"
    assert data["is_active"] is True
    assert "tenant_id" in data


@pytest.mark.asyncio
async def test_create_key_with_existing_tenant(client):
    """Providing an existing tenant_id should associate the new key with it."""
    tenant_id = str(uuid.uuid4())

    r1 = await client.post(
        "/admin/keys",
        json={"label": "key-1", "tenant_id": tenant_id},
        headers=HEADERS,
    )
    r2 = await client.post(
        "/admin/keys",
        json={"label": "key-2", "tenant_id": tenant_id},
        headers=HEADERS,
    )

    assert r1.status_code == 201
    assert r2.status_code == 201
    assert r1.json()["tenant_id"] == r2.json()["tenant_id"] == tenant_id


@pytest.mark.asyncio
async def test_list_keys(client):
    """GET /admin/keys should return all created keys."""
    await client.post("/admin/keys", json={"label": "a"}, headers=HEADERS)
    await client.post("/admin/keys", json={"label": "b"}, headers=HEADERS)

    response = await client.get("/admin/keys", headers=HEADERS)
    assert response.status_code == 200
    assert len(response.json()) >= 2


@pytest.mark.asyncio
async def test_revoke_key(client):
    """Revoking a key should set is_active=False."""
    create = await client.post(
        "/admin/keys", json={"label": "to-revoke"}, headers=HEADERS
    )
    key_id = create.json()["id"]

    revoke = await client.delete(f"/admin/keys/{key_id}", headers=HEADERS)
    assert revoke.status_code == 204

    # Confirm it appears inactive in the list
    keys = await client.get("/admin/keys", headers=HEADERS)
    match = next(k for k in keys.json() if k["id"] == key_id)
    assert match["is_active"] is False


@pytest.mark.asyncio
async def test_revoke_nonexistent_key_returns_404(client):
    response = await client.delete(
        f"/admin/keys/{uuid.uuid4()}", headers=HEADERS
    )
    assert response.status_code == 404


@pytest.mark.asyncio
async def test_admin_requires_secret(client):
    """Missing or wrong admin secret must return 403."""
    r1 = await client.post("/admin/keys", json={"label": "x"})
    r2 = await client.post(
        "/admin/keys",
        json={"label": "x"},
        headers={"x-admin-secret": "wrong"},
    )
    assert r1.status_code == 403
    assert r2.status_code == 403


# ---------------------------------------------------------------------------
# Rule management
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_create_rule(client):
    """Creating a rule should persist it and return the full object."""
    tenant_id = str(uuid.uuid4())

    response = await client.post(
        "/admin/rules",
        json={
            "tenant_id":      tenant_id,
            "resource":       "payments:create",
            "algorithm":      "sliding_window",
            "limit":          100,
            "window_seconds": 60,
            "capacity":       100,
            "refill_rate":    1.0,
        },
        headers=HEADERS,
    )
    assert response.status_code == 201

    data = response.json()
    assert data["resource"]  == "payments:create"
    assert data["algorithm"] == "sliding_window"
    assert data["limit"]     == 100
    assert data["is_active"] is True


@pytest.mark.asyncio
async def test_duplicate_rule_returns_409(client):
    """Creating two rules for the same tenant + resource should fail."""
    tenant_id = str(uuid.uuid4())
    payload   = {
        "tenant_id": tenant_id, "resource": "dupe:resource",
        "algorithm": "sliding_window", "limit": 10,
        "window_seconds": 60, "capacity": 10, "refill_rate": 1.0,
    }

    r1 = await client.post("/admin/rules", json=payload, headers=HEADERS)
    r2 = await client.post("/admin/rules", json=payload, headers=HEADERS)

    assert r1.status_code == 201
    assert r2.status_code == 409


@pytest.mark.asyncio
async def test_update_rule(client):
    """Updating a rule's limit should persist and return the new value."""
    tenant_id = str(uuid.uuid4())

    create = await client.post(
        "/admin/rules",
        json={
            "tenant_id": tenant_id, "resource": "update:test",
            "algorithm": "sliding_window", "limit": 10,
            "window_seconds": 60, "capacity": 10, "refill_rate": 1.0,
        },
        headers=HEADERS,
    )
    rule_id = create.json()["id"]

    update = await client.put(
        f"/admin/rules/{rule_id}",
        json={"limit": 50},
        headers=HEADERS,
    )
    assert update.status_code == 200
    assert update.json()["limit"] == 50


@pytest.mark.asyncio
async def test_update_rule_invalidates_cache(client, fake_redis):
    """
    After updating a rule, the Redis cache for that rule should be gone.
    The next check request will re-populate it with the new values.
    """
    from services.rules import _rule_cache_key
    import json

    tenant_id = uuid.uuid4()

    # Create rule
    create = await client.post(
        "/admin/rules",
        json={
            "tenant_id": str(tenant_id), "resource": "cache:test",
            "algorithm": "sliding_window", "limit": 10,
            "window_seconds": 60, "capacity": 10, "refill_rate": 1.0,
        },
        headers=HEADERS,
    )
    rule_id = create.json()["id"]

    # Manually plant a stale cache entry
    cache_key = _rule_cache_key(tenant_id, "cache:test")
    await fake_redis.setex(cache_key, 30, json.dumps({
        "limit": 10, "window_seconds": 60,
        "capacity": 10, "refill_rate": 1.0, "algorithm": "sliding_window"
    }))

    # Update the rule — should evict the cache
    await client.put(
        f"/admin/rules/{rule_id}",
        json={"limit": 999},
        headers=HEADERS,
    )

    # Cache entry should be gone
    cached = await fake_redis.get(cache_key)
    assert cached is None


@pytest.mark.asyncio
async def test_delete_rule_deactivates_it(client):
    """Deleting a rule should set is_active=False, not remove the row."""
    tenant_id = str(uuid.uuid4())

    create = await client.post(
        "/admin/rules",
        json={
            "tenant_id": tenant_id, "resource": "delete:test",
            "algorithm": "sliding_window", "limit": 5,
            "window_seconds": 60, "capacity": 5, "refill_rate": 1.0,
        },
        headers=HEADERS,
    )
    rule_id = create.json()["id"]

    delete = await client.delete(f"/admin/rules/{rule_id}", headers=HEADERS)
    assert delete.status_code == 204

    # Should appear inactive in list
    rules = await client.get(
        f"/admin/rules?tenant_id={tenant_id}", headers=HEADERS
    )
    match = next(r for r in rules.json() if r["id"] == rule_id)
    assert match["is_active"] is False
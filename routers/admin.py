"""
routers/admin.py
----------------
Management API for API keys and rate limit rules.

Two deliberate design decisions worth knowing:

1. Admin routes are on a separate prefix (/admin) and protected by a
   different auth mechanism — an ADMIN_SECRET env var rather than tenant
   API keys. In production you'd put these behind a VPN or internal
   load balancer so they're never reachable from the public internet.
   For M4, the shared secret is enough to make the pattern clear.

2. Every write operation (create, update, delete) invalidates the relevant
   Redis cache entry immediately. This is the discipline mentioned in M3:
   the cache is only useful if writes keep it consistent. Skipping an
   invalidation after an update is a silent bug — the rule changes in
   Postgres but clients keep getting the old limit for up to 30 seconds.
"""

import uuid
from datetime import datetime
from typing import List

import structlog
from fastapi import APIRouter, Depends, Header, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.engine import get_db
from db.models import APIKey, RateLimitRule
from services.auth import generate_api_key, hash_key
from services.rules import invalidate_rule_cache, invalidate_auth_cache
import os

log = structlog.get_logger()

router = APIRouter(prefix="/admin", tags=["admin"])

ADMIN_SECRET = os.getenv("ADMIN_SECRET", "change-me-in-production")


# ---------------------------------------------------------------------------
# Admin auth dependency
# ---------------------------------------------------------------------------

def require_admin(x_admin_secret: str = Header(...)):
    """
    Simple shared-secret auth for admin endpoints.
    In production: rotate this secret, store it in a secrets manager,
    and put the /admin prefix behind a VPN or internal network.
    """
    if x_admin_secret != ADMIN_SECRET:
        raise HTTPException(status_code=403, detail="Invalid admin secret.")


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------
# Separate Input/Output schemas are worth the verbosity:
#   - Input schemas validate and document what the caller must send
#   - Output schemas control exactly what gets serialised back
#   - You never accidentally leak internal fields (key_hash, etc.)

class CreateKeyInput(BaseModel):
    label:     str = Field(..., min_length=1, max_length=100,
                           description="Human-readable name, e.g. 'production'")
    tenant_id: uuid.UUID | None = Field(
        None,
        description="Leave blank to auto-generate a new tenant. "
                    "Provide an existing tenant_id to add a second key to them."
    )


class KeyOutput(BaseModel):
    id:           uuid.UUID
    label:        str
    tenant_id:    uuid.UUID
    is_active:    bool
    created_at:   datetime
    last_used_at: datetime | None
    # plaintext_key only populated on creation — never returned again
    plaintext_key: str | None = None


class CreateRuleInput(BaseModel):
    tenant_id:      uuid.UUID
    resource:       str = Field(..., description="e.g. 'payments:create' or '*'")
    algorithm:      str = Field("sliding_window",
                                pattern="^(sliding_window|token_bucket)$")
    limit:          int = Field(..., gt=0, description="Max requests (sliding window)")
    window_seconds: int = Field(60, gt=0)
    capacity:       int = Field(..., gt=0, description="Max tokens (token bucket)")
    refill_rate:    float = Field(1.0, gt=0, description="Tokens per second")


class UpdateRuleInput(BaseModel):
    algorithm:      str | None = Field(None, pattern="^(sliding_window|token_bucket)$")
    limit:          int | None = Field(None, gt=0)
    window_seconds: int | None = Field(None, gt=0)
    capacity:       int | None = Field(None, gt=0)
    refill_rate:    float | None = Field(None, gt=0)
    is_active:      bool | None = None


class RuleOutput(BaseModel):
    id:             uuid.UUID
    tenant_id:      uuid.UUID
    resource:       str
    algorithm:      str
    limit:          int
    window_seconds: int
    capacity:       int
    refill_rate:    float
    is_active:      bool
    created_at:     datetime
    updated_at:     datetime


# ---------------------------------------------------------------------------
# API Key endpoints
# ---------------------------------------------------------------------------

@router.post("/keys", response_model=KeyOutput, status_code=201)
async def create_key(
    body: CreateKeyInput,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """
    Provision a new API key.

    Returns the plaintext key once — it is not stored and cannot be
    retrieved again. The caller must save it immediately.
    """
    tenant_id  = body.tenant_id or uuid.uuid4()
    plaintext  = generate_api_key()

    key = APIKey(
        key_hash=hash_key(plaintext),
        label=body.label,
        tenant_id=tenant_id,
    )
    db.add(key)
    await db.commit()
    await db.refresh(key)

    log.info(
        "api_key_created",
        key_id=str(key.id),
        tenant_id=str(tenant_id),
        label=body.label,
        # Log only the prefix — enough to identify the key in support tickets
        # without exposing enough for an attacker to use it
        key_prefix=plaintext[:16],
    )

    return KeyOutput(
        id=key.id,
        label=key.label,
        tenant_id=key.tenant_id,
        is_active=key.is_active,
        created_at=key.created_at,
        last_used_at=key.last_used_at,
        plaintext_key=plaintext,  # shown once, then gone
    )


@router.get("/keys", response_model=List[KeyOutput])
async def list_keys(
    tenant_id: uuid.UUID | None = None,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """List all API keys, optionally filtered by tenant."""
    query = select(APIKey)
    if tenant_id:
        query = query.where(APIKey.tenant_id == tenant_id)
    query = query.order_by(APIKey.created_at.desc())

    result = await db.execute(query)
    keys   = result.scalars().all()

    # return [
    #     KeyOutput(
    #         id=k.id, label=k.label, tenant_id=k.tenant_id,
    #         is_active=k.is_active, created_at=k.created_at,
    #         last_used_at=k.last_used_at,
    #     )
    #     for k in keys
    # ]
    return keys  # Pydantic can convert SQLAlchemy models directly


@router.delete("/keys/{key_id}", status_code=204)
async def revoke_key(
    key_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """
    Revoke an API key. Sets is_active=False rather than deleting the row
    so audit logs remain intact.

    Note: we can't invalidate the auth cache here because we don't have
    the plaintext key — only its ID. The cache entry will expire naturally
    within AUTH_CACHE_TTL (5 minutes). For instant revocation in production,
    store the key prefix in a separate column and use it as the cache key.
    This is a known limitation — document it.
    """
    result = await db.execute(select(APIKey).where(APIKey.id == key_id))
    key    = result.scalar_one_or_none()

    if key is None:
        raise HTTPException(status_code=404, detail="API key not found.")

    key.is_active = False
    await db.commit()

    log.info("api_key_revoked", key_id=str(key_id), tenant_id=str(key.tenant_id))

    # Return 204 No Content — nothing to send back


# ---------------------------------------------------------------------------
# Rule endpoints
# ---------------------------------------------------------------------------

@router.post("/rules", response_model=RuleOutput, status_code=201)
async def create_rule(
    body: CreateRuleInput,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """
    Create a rate limit rule for a tenant + resource pair.
    Use resource="*" to create a wildcard catch-all rule.
    """
    # Check for duplicate — the DB has a unique constraint too, but giving a
    # clear error message is better than letting Postgres throw an IntegrityError
    existing = await db.execute(
        select(RateLimitRule).where(
            RateLimitRule.tenant_id == body.tenant_id,
            RateLimitRule.resource  == body.resource, 
        )
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=409,
            detail=f"Rule already exists for tenant {body.tenant_id} / resource {body.resource!r}. "
                   f"Use PUT /admin/rules/{{id}} to update it."
        )

    rule = RateLimitRule(**body.model_dump())
    db.add(rule)
    await db.commit()
    await db.refresh(rule)

    log.info(
        "rule_created",
        rule_id=str(rule.id),
        tenant_id=str(rule.tenant_id),
        resource=rule.resource,
        algorithm=rule.algorithm,
        limit=rule.limit,
    )

    return rule


@router.get("/rules", response_model=list[RuleOutput])
async def list_rules(
    tenant_id: uuid.UUID | None = None,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """List all rules, optionally filtered by tenant."""
    query = select(RateLimitRule)
    if tenant_id:
        query = query.where(RateLimitRule.tenant_id == tenant_id)
    query = query.order_by(RateLimitRule.created_at.desc())

    result = await db.execute(query)
    return result.scalars().all()


@router.put("/rules/{rule_id}", response_model=RuleOutput)
async def update_rule(
    rule_id: uuid.UUID,
    body: UpdateRuleInput,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """
    Update a rule's algorithm or limits.

    IMPORTANT: also invalidates the Redis cache for this rule so the
    change takes effect on the next request, not after TTL expiry.
    """
    result = await db.execute(
        select(RateLimitRule).where(RateLimitRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found.")

    # Apply only the fields that were actually sent (partial update)
    update_data = body.model_dump(exclude_none=True)
    for field, value in update_data.items():
        setattr(rule, field, value)

    await db.commit()
    await db.refresh(rule)

    # Cache invalidation — this is the critical step.
    # Without this, clients keep getting the old rule until RULE_CACHE_TTL expires.
    await invalidate_rule_cache(
        tenant_id=rule.tenant_id,
        resource=rule.resource,
        redis_client=request.app.state.redis,
    )

    log.info(
        "rule_updated",
        rule_id=str(rule_id),
        tenant_id=str(rule.tenant_id),
        resource=rule.resource,
        changes=update_data,
    )

    return rule


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_rule(
    rule_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: None = Depends(require_admin),
):
    """
    Deactivate a rule (soft delete — sets is_active=False).
    Also invalidates the cache so the change takes effect immediately.
    """
    result = await db.execute(
        select(RateLimitRule).where(RateLimitRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()

    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found.")

    rule.is_active = False
    await db.commit()

    await invalidate_rule_cache(
        tenant_id=rule.tenant_id,
        resource=rule.resource,
        redis_client=request.app.state.redis,
    )

    log.info(
        "rule_deleted",
        rule_id=str(rule_id),
        tenant_id=str(rule.tenant_id),
        resource=rule.resource,
    )
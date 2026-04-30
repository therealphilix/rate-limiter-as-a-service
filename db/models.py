"""
db/models.py
------------
Two tables drive the whole service:

  APIKey       — authenticates a caller and ties them to a tenant
  RateLimitRule — one row per (tenant, resource) pair, defines the algorithm
                  and its parameters

Why UUID primary keys instead of integers?
  Tenants will eventually see their own IDs in logs, API responses, and
  error messages. Sequential integers leak information ("I'm tenant 3,
  so there are probably only a handful of customers"). UUIDs don't.

Why store key_hash instead of the plaintext key?
  If your database is ever dumped — breach, misconfigured backup, rogue
  employee — hashed keys are useless to an attacker. The plaintext key
  is shown to the tenant exactly once at creation time, then discarded.
  This is how Stripe, GitHub, and every serious API handles it.
"""

import uuid
from datetime import datetime

from sqlalchemy import (
    Boolean, DateTime, Float, Integer,
    String, ForeignKey, UniqueConstraint, func,
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class APIKey(Base):
    __tablename__ = "api_keys"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # The key the tenant sends in the X-API-Key header.
    # We store only the bcrypt hash — never the plaintext.
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)

    # Human-readable label so tenants can tell their keys apart
    # ("production", "staging", "ci-pipeline").
    label: Mapped[str] = mapped_column(String(100), nullable=False)

    # tenant_id groups keys and rules together. In a real product this would
    # be a FK to a tenants table. For M3 it's just a UUID we generate and
    # hand to the tenant — every rule they create is scoped to this ID.
    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationship — one key → many rules (via tenant_id, not a direct FK,
    # because multiple keys can belong to the same tenant).
    # We'll use this in the admin API (M4) for eager loading.
    rules: Mapped[list["RateLimitRule"]] = relationship(
        "RateLimitRule",
        primaryjoin="foreign(RateLimitRule.tenant_id) == APIKey.tenant_id",
        viewonly=True,
    )

    def __repr__(self) -> str:
        return f"<APIKey label={self.label!r} tenant={self.tenant_id} active={self.is_active}>"


class RateLimitRule(Base):
    __tablename__ = "rate_limit_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    tenant_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), nullable=False, index=True
    )

    # The resource this rule applies to.
    # Use "*" as a catch-all wildcard for any resource not matched by a
    # specific rule. Lookup order: exact match first, then "*".
    # Examples: "payments:create", "users:list", "*"
    resource: Mapped[str] = mapped_column(String(200), nullable=False)

    algorithm: Mapped[str] = mapped_column(
        String(50), nullable=False, default="sliding_window" 
        # Valid values: "sliding_window" | "token_bucket"
        # In M4 we'll add a DB-level check constraint to enforce this.
    )

    # --- Sliding window fields ---
    limit: Mapped[int] = mapped_column(Integer, nullable=False)
    window_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=60)

    # --- Token bucket fields ---
    # capacity mirrors `limit` for token bucket — stored separately so
    # the intent is explicit in the schema even if values happen to match.
    capacity: Mapped[int] = mapped_column(Integer, nullable=False, default=10)
    refill_rate: Mapped[float] = mapped_column(Float, nullable=False, default=1.0)

    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )

    # A tenant can have only one rule per resource.
    # The unique constraint enforces this at the DB level — not just in code.
    __table_args__ = (
        UniqueConstraint("tenant_id", "resource", name="uq_tenant_resource"),
    )

    def __repr__(self) -> str:
        return (
            f"<RateLimitRule tenant={self.tenant_id} resource={self.resource!r} "
            f"algo={self.algorithm} limit={self.limit}>"
        )
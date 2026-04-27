"""
services/auth.py
----------------
Two responsibilities:
  1. Generate and hash new API keys (used by the admin API in M4)
  2. Verify an incoming key and return the associated tenant_id

Why bcrypt for API keys?
  bcrypt is slow by design — it's meant to make brute-force attacks
  expensive. But "slow" is relative: bcrypt at cost=12 takes ~250ms.
  For a rate limiter that runs on every single request, 250ms per auth
  check is unacceptable.

  The solution is in rules.py: after the first successful auth, we cache
  the tenant_id in Redis for 5 minutes. Subsequent requests skip bcrypt
  entirely and pay only a Redis GET (~0.5ms). Bcrypt only fires on a
  cache miss — roughly once every 5 minutes per active API key.

  This is a deliberate tradeoff: you get bcrypt's brute-force resistance
  at Redis's latency cost. Document this decision — it's a great
  interview talking point.
"""

import secrets
import uuid

from passlib.context import CryptContext
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from db.models import APIKey

# CryptContext handles algorithm selection and future migrations.
# If you ever need to upgrade from bcrypt to argon2, you add it here
# and existing hashes keep working until they're re-hashed on next login.
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# API key format: "rl_live_<32 random hex chars>"
# The prefix makes keys identifiable in logs and easy to grep for in
# accidentally committed code (GitHub's secret scanning looks for patterns
# like this). Never log the full key — log only the first 12 chars.
KEY_PREFIX = "rl_live_"


def generate_api_key() -> str:
    """
    Generate a new plaintext API key.
    Called once at creation time — the plaintext is shown to the tenant
    and then discarded. Only the hash is stored.
    """
    return KEY_PREFIX + secrets.token_hex(32)


def hash_key(plaintext_key: str) -> str:
    """Hash a plaintext key for storage."""
    return pwd_context.hash(plaintext_key)


def verify_key(plaintext_key: str, hashed_key: str) -> bool:
    """Compare an incoming key against a stored hash."""
    return pwd_context.verify(plaintext_key, hashed_key)


async def get_tenant_from_key(
    plaintext_key: str,
    db: AsyncSession,
) -> uuid.UUID | None:
    """
    Look up a tenant_id from a plaintext API key.

    Returns the tenant_id if the key is valid and active, None otherwise.

    This does a full table scan across all active keys to find a bcrypt
    match — which is why caching in rules.py is essential. In a system
    with thousands of API keys, you'd add a key prefix index to narrow
    the scan (store the first 8 chars of the key as a plaintext lookup
    column, use it to find candidates, then bcrypt only those).

    For M3 with a handful of keys, the full scan is fine.
    """
    if not plaintext_key.startswith(KEY_PREFIX):
        # Fail fast — malformed key, don't bother hitting the DB
        return None

    # Load all active keys. We have to check each hash individually
    # because bcrypt hashes are not comparable without the plaintext.
    result = await db.execute(
        select(APIKey).where(APIKey.is_active == True)  # noqa: E712
    )
    keys = result.scalars().all()

    for api_key in keys:
        if verify_key(plaintext_key, api_key.key_hash):
            return api_key.tenant_id

    return None
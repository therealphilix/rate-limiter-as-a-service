# seed.py — run once to create a test API key and rule
import asyncio
import uuid
from db.engine import AsyncSessionLocal
from db.models import APIKey, RateLimitRule
from services.auth import generate_api_key, hash_key

async def seed():
    tenant_id = uuid.uuid4()
    plaintext = generate_api_key()

    async with AsyncSessionLocal() as db:
        key = APIKey(
            key_hash=hash_key(plaintext),
            label="test-key",
            tenant_id=tenant_id,
        )
        rule = RateLimitRule(
            tenant_id=tenant_id,
            resource="payments:create",
            algorithm="sliding_window",
            limit=5,
            window_seconds=60,
            capacity=5,
            refill_rate=1.0,
        )
        db.add(key)
        db.add(rule)
        await db.commit()

    print(f"Tenant ID : {tenant_id}")
    print(f"API Key   : {plaintext}")   # save this — shown once only
    print("Rule      : 5 req / 60s on payments:create")

asyncio.run(seed())
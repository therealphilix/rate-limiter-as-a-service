"""
db/engine.py
------------
One engine. One session factory. Both shared across the entire app.

Why async SQLAlchemy?
  FastAPI is async. If your DB calls are synchronous, every query blocks
  the event loop — your entire server stalls waiting for Postgres while
  other requests queue up behind it. asyncpg + async SQLAlchemy lets the
  event loop handle other requests while Postgres thinks.

Why not create a new engine per request?
  Each engine manages a connection pool. Creating one per request throws
  that away — you'd open and close a raw TCP connection to Postgres on
  every single request. Expensive. The engine lives for the lifetime of
  the app and hands out pooled connections as needed.
"""

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from dotenv import load_dotenv
import os

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is not set in .env")

# asyncpg is the async Postgres driver. SQLAlchemy uses it under the hood
# when the URL scheme is postgresql+asyncpg://
engine = create_async_engine(
    DATABASE_URL,
    echo=False,        # set True to log every SQL statement — useful for debugging
    pool_size=10,      # keep 10 connections warm in the pool
    max_overflow=20,   # allow up to 20 extra connections under load
    pool_pre_ping=True # test connections before handing them out (detects stale connections)
)

# Session factory — call AsyncSessionLocal() to get a session for one request.
# expire_on_commit=False means loaded objects stay usable after a commit,
# which matters in async code where you might access attributes after the
# transaction closes.
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_db():
    """
    FastAPI dependency — yields one DB session per request, then closes it.

    Usage in a route:
        @app.get("/something")
        async def handler(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
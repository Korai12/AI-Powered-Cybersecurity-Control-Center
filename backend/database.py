"""
ACCC Database Configuration — backend/database.py
Phase 2.1 Update: Ensures async_session_factory is exported for WebSocket auth.

Provides:
    - engine: AsyncEngine for raw operations
    - async_session_factory: sessionmaker for creating sessions directly
    - get_db: FastAPI dependency for route handlers
"""

import asyncio
import logging
import os

from sqlalchemy.ext.asyncio import (
    create_async_engine,
    AsyncSession,
    async_sessionmaker,
)
from sqlalchemy import text

from config import settings

logger = logging.getLogger("accc.database")

# ──────────────────────────────────────────────────────────
# Engine with connection retry
# ──────────────────────────────────────────────────────────

engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.is_development,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

# ──────────────────────────────────────────────────────────
# Session Factory
# ──────────────────────────────────────────────────────────

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


# ──────────────────────────────────────────────────────────
# FastAPI Dependency
# ──────────────────────────────────────────────────────────

async def get_db():
    """
    FastAPI dependency that provides a database session.
    Usage:
        @router.get('/endpoint')
        async def handler(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with async_session_factory() as session:
        try:
            yield session
        except Exception:
            await session.rollback()
            raise


# ──────────────────────────────────────────────────────────
# Connection retry (used during startup)
# ──────────────────────────────────────────────────────────

async def wait_for_database(max_retries: int = 30, delay: float = 2.0) -> bool:
    """
    Exponential backoff retry on connection (attempts every 2s for 60s).
    Called during application startup.
    """
    for attempt in range(1, max_retries + 1):
        try:
            async with engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            logger.info(f"Database connected (attempt {attempt})")
            return True
        except Exception as e:
            logger.warning(f"Database connection attempt {attempt}/{max_retries} failed: {e}")
            if attempt < max_retries:
                await asyncio.sleep(delay)

    logger.error("Could not connect to database after maximum retries")
    return False
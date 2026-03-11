"""
database.py — Async SQLAlchemy engine, session factory, and connection retry logic.
Backend retries every 2 seconds for up to 60 seconds before failing.
"""
import asyncio
import logging
from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy import text

from config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class Base(DeclarativeBase):
    pass


# Create async engine (pool size tuned for hackathon scale)
engine = create_async_engine(
    settings.database_url,
    pool_size=10,
    max_overflow=20,
    pool_pre_ping=True,       # Re-validates connections before use
    pool_recycle=3600,        # Recycle connections every hour
    echo=settings.is_development,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency — yields a database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def wait_for_database(max_attempts: int = 30, delay: float = 2.0) -> None:
    """
    Retry loop — attempts DB connection every `delay` seconds.
    Logs attempt number clearly so container logs are readable.
    Raises RuntimeError if all attempts are exhausted.
    """
    for attempt in range(1, max_attempts + 1):
        try:
            async with engine.begin() as conn:
                await conn.execute(text("SELECT 1"))
            logger.info("Database connection established ✓")
            return
        except Exception as exc:
            if attempt < max_attempts:
                logger.info(
                    "Waiting for postgres... attempt %d/%d (%s)",
                    attempt, max_attempts, str(exc)[:60],
                )
                await asyncio.sleep(delay)
            else:
                logger.error("Database unreachable after %d attempts — giving up", max_attempts)
                raise RuntimeError(f"Cannot connect to database: {exc}") from exc


async def check_database_health() -> dict:
    """Returns health status dict for /health endpoint."""
    try:
        async with AsyncSessionLocal() as session:
            await session.execute(text("SELECT 1"))
        return {"status": "healthy"}
    except Exception as exc:
        return {"status": "unhealthy", "error": str(exc)}

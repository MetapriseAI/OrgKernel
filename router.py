"""
Database configuration for OrgKernel.

Provides async SQLAlchemy engine, session factory, and table initialization.
Supports PostgreSQL and MySQL out of the box.

Usage::

    from orgkernel.database import async_engine, init_db, get_session_factory

    # At application startup
    async_engine.url = "postgresql+asyncpg://user:pass@localhost:5432/orgkernel"
    await init_db(async_engine)

    # Per-request session
    factory = get_session_factory(async_engine)
    async with factory() as session:
        ...

PostgreSQL note: Enable the pgcrypto extension before first run::

    CREATE EXTENSION IF NOT EXISTS pgcrypto;

MySQL note: Ensure InnoDB is used for transaction support.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_engine_from_config,
    create_async_engine,
)

from orgkernel.models import BaseModel


# Global engine instance. Set url before calling init_db().
async_engine: AsyncEngine | None = None


def get_engine(url: str, **kwargs: Any) -> AsyncEngine:
    """
    Create an async SQLAlchemy engine from a database URL.

    Args:
        url: Database connection URL.
            Examples:
                - postgresql+asyncpg://user:pass@localhost:5432/orgkernel
                - mysql+aiomysql://user:pass@localhost:3306/orgkernel
            For SQLite (dev/testing): sqlite+aiosqlite:///./orgkernel.db
        **kwargs: Additional arguments passed to create_async_engine.

    Returns:
        Configured AsyncEngine instance.
    """
    return create_async_engine(url, echo=False, **kwargs)


def get_session_factory(engine: AsyncEngine) -> type[AsyncSession]:
    """
    Return a session factory bound to the given engine.

    Usage::

        factory = get_session_factory(engine)
        async with factory() as session:
            await session.execute(...)
    """
    from sqlalchemy.orm import sessionmaker
    return sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)


async def init_db(engine: AsyncEngine | None = None) -> None:
    """
    Create all OrgKernel tables in the database.

    Call this once at application startup (after setting the engine URL).

    Args:
        engine: AsyncEngine to use. Defaults to the global async_engine.

    Note:
        On PostgreSQL, run ``CREATE EXTENSION IF NOT EXISTS pgcrypto;`` first
        to enable SHA-256 hashing functions.
    """
    global async_engine
    target_engine = engine or async_engine
    if target_engine is None:
        raise RuntimeError(
            "No engine set. Pass an engine argument or set orgkernel.database.async_engine.url first."
        )
    async with target_engine.begin() as conn:
        await conn.run_sync(BaseModel.metadata.create_all)


async def close_db() -> None:
    """Close the global async engine. Call at application shutdown."""
    global async_engine
    if async_engine is not None:
        await async_engine.dispose()
        async_engine = None


# ── Type alias for session injection ──────────────────────────────────────────


if TYPE_CHECKING:
    SessionFactory = type[AsyncSession]
else:
    SessionFactory = object  # runtime placeholder

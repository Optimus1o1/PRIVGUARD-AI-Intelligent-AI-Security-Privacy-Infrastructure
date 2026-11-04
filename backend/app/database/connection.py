"""Async database connection and session management."""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy import event
from app.core.config import settings

Base = declarative_base()

# Async SQLite engine
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True,
    connect_args={"check_same_thread": False},
)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def init_db() -> None:
    """Initializes tables and WAL mode for SQLite."""
    async with engine.begin() as conn:
        # Enable WAL mode and foreign key constraints on SQLite
        await conn.execute(
            # Raw text execute for PRAGMA
            sqlalchemy_text_pragma()
        )
        await conn.run_sync(Base.metadata.create_all)


def sqlalchemy_text_pragma():
    from sqlalchemy import text
    return text("PRAGMA journal_mode=WAL;")


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency that yields an async database session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise

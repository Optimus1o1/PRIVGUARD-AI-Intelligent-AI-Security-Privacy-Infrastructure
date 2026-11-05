"""Async database connection and session management."""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy import event, text
from app.core.config import settings

Base = declarative_base()

# Async DB engine
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=settings.DEBUG,
    future=True,
    connect_args={"check_same_thread": False, "timeout": 60.0} if "sqlite" in settings.DATABASE_URL else {},
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
        if "sqlite" in engine.dialect.name:
            await conn.execute(text("PRAGMA journal_mode=WAL;"))
            await conn.execute(text("PRAGMA foreign_keys=ON;"))
        await conn.run_sync(Base.metadata.create_all)


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency that yields an async database session configured with active tenant context."""
    async with AsyncSessionLocal() as session:
        try:
            from app.core.tenant import get_current_tenant_id
            from app.database.rls import set_db_tenant_context
            tenant_id = get_current_tenant_id()
            if tenant_id:
                await set_db_tenant_context(session, tenant_id)
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise

"""Async database connection and session management."""

from typing import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy import event, text
from app.core.config import settings

Base = declarative_base()

# Async DB engine
is_postgres = "postgres" in settings.DATABASE_URL
engine_kwargs = {
    "echo": settings.DEBUG,
    "future": True,
}
if is_postgres:
    engine_kwargs.update({
        "pool_size": 20,
        "max_overflow": 10,
        "pool_timeout": 30.0,
        "pool_recycle": 1800,
        "pool_pre_ping": True,
    })
else:
    engine_kwargs.update({
        "connect_args": {"check_same_thread": False, "timeout": 60.0}
    })

engine = create_async_engine(settings.DATABASE_URL, **engine_kwargs)

# Async session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


def get_pool_status() -> dict:
    """Returns the current connection pool status and metrics."""
    pool = engine.pool
    # NullPool or StaticPool (used in tests or SQLite) may not have checkedin/checkedout
    status = {
        "pool_type": pool.__class__.__name__,
        "is_postgres": is_postgres,
    }
    if hasattr(pool, "size"):
        status["pool_size"] = pool.size()
    if hasattr(pool, "checkedin"):
        status["checked_in"] = pool.checkedin()
    if hasattr(pool, "checkedout"):
        status["checked_out"] = pool.checkedout()
    if hasattr(pool, "overflow"):
        status["overflow"] = pool.overflow()
    return status


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
        tenant_set = False
        try:
            from app.core.tenant import get_current_tenant_id
            from app.database.rls import set_db_tenant_context, reset_db_tenant_context
            tenant_id = get_current_tenant_id()
            if tenant_id:
                await set_db_tenant_context(session, tenant_id)
                tenant_set = True
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            if tenant_set:
                try:
                    await reset_db_tenant_context(session)
                except Exception:
                    pass


# Alias for database dependency
get_db = get_db_session

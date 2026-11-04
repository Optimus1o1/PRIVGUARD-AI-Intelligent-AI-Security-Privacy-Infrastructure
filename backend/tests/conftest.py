"""Pytest fixtures and test configuration."""

import os
import sys
import uuid
import pytest
import pytest_asyncio
import httpx
from httpx import ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.core.config import settings
from app.core.security import hash_api_key
from app.database.connection import Base, get_db_session
from app.database.models import Application
from app.main import app

TEST_DB_URL = "sqlite+aiosqlite:///./test_privguard.db"
test_engine = create_async_engine(TEST_DB_URL, echo=False, poolclass=NullPool)
TestSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

TEST_API_KEY = "pg_live_test_api_key_valid_99999"


@pytest_asyncio.fixture(scope="function", autouse=True)
async def setup_test_database():
    """Sets up a clean test SQLite database schema per test."""
    async with test_engine.begin() as conn:
        from sqlalchemy import text
        await conn.execute(text("PRAGMA journal_mode=WAL;"))
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def override_get_db_session():
    """Overrides default database session with test session."""
    async with TestSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


app.dependency_overrides[get_db_session] = override_get_db_session


@pytest_asyncio.fixture(scope="function")
async def db_session():
    """Yields a database session for test verification."""
    async with TestSessionLocal() as session:
        yield session


@pytest_asyncio.fixture(scope="function")
async def test_app_record(db_session: AsyncSession):
    """Creates or retrieves a registered test application in the database."""
    from sqlalchemy import select
    hashed = hash_api_key(TEST_API_KEY)
    stmt = select(Application).where(Application.api_key_hash == hashed)
    res = await db_session.execute(stmt)
    existing = res.scalar_one_or_none()
    if existing:
        return existing

    app_id = f"test_app_{uuid.uuid4().hex[:8]}"
    app_record = Application(
        id=app_id,
        name="Automated Test Application",
        api_key_hash=hashed,
        is_active=True,
    )
    db_session.add(app_record)
    await db_session.commit()
    await db_session.refresh(app_record)
    return app_record


@pytest_asyncio.fixture(scope="function")
async def client():
    """Provides an async HTTP test client."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest_asyncio.fixture(scope="function")
def auth_headers():
    """Returns valid authentication headers for test calls."""
    return {"X-API-Key": TEST_API_KEY}

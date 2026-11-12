"""
Multi-Tenant Test Fixture Helpers for Stage 6 Red Teaming.
Provides registered tenant applications (Alpha Enterprise vs Bravo Adversary).
"""

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.security import hash_api_key
from app.database.models import Application
from tests.fixtures.redteam_dataset import (
    TENANT_ALPHA_APP_ID,
    TENANT_ALPHA_API_KEY,
    TENANT_BRAVO_APP_ID,
    TENANT_BRAVO_API_KEY,
)


async def get_or_create_tenant(
    db: AsyncSession,
    app_id: str,
    api_key: str,
    name: str,
) -> Application:
    """Creates or retrieves a tenant application record with a known API key."""
    hashed = hash_api_key(api_key)
    stmt = select(Application).where(Application.id == app_id)
    res = await db.execute(stmt)
    app = res.scalar_one_or_none()
    if app:
        return app

    app = Application(
        id=app_id,
        name=name,
        api_key_hash=hashed,
        is_active=True,
    )
    db.add(app)
    await db.commit()
    await db.refresh(app)
    return app


async def setup_multi_tenant_staging(db: AsyncSession):
    """Sets up Tenant Alpha (Target Enterprise) and Tenant Bravo (Adversary)."""
    alpha = await get_or_create_tenant(
        db,
        TENANT_ALPHA_APP_ID,
        TENANT_ALPHA_API_KEY,
        "Tenant Alpha Enterprise Corp",
    )
    bravo = await get_or_create_tenant(
        db,
        TENANT_BRAVO_APP_ID,
        TENANT_BRAVO_API_KEY,
        "Tenant Bravo Adversary Lab",
    )
    return alpha, bravo


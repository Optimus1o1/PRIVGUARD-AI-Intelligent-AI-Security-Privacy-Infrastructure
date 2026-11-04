"""Application authentication and API key verification."""

from typing import Optional
from fastapi import Depends, Header, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.config import settings
from app.core.exceptions import AuthenticationError
from app.core.security import hash_api_key
from app.database.connection import get_db_session
from app.database.models import Application


async def get_current_app(
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
    authorization: Optional[str] = Header(None),
    db: AsyncSession = Depends(get_db_session),
) -> Application:
    """Validates the application API key from either X-API-Key or Bearer token header."""
    api_key: Optional[str] = None

    if x_api_key:
        api_key = x_api_key.strip()
    elif authorization and authorization.startswith("Bearer "):
        api_key = authorization.split("Bearer ", 1)[1].strip()

    if not api_key:
        raise AuthenticationError("API key required. Provide 'X-API-Key' or 'Authorization: Bearer <key>'.")

    # Master development key check
    if settings.DEBUG and api_key == settings.PRIVGUARD_MASTER_KEY:
        # Return a transient root admin application representation
        return Application(
            id="app_master_admin",
            name="Master Admin App (Dev)",
            api_key_hash=hash_api_key(api_key),
            is_active=True,
        )

    # Hash incoming key and lookup in database
    hashed_key = hash_api_key(api_key)
    query = select(Application).where(Application.api_key_hash == hashed_key)
    result = await db.execute(query)
    app = result.scalar_one_or_none()

    if not app:
        raise AuthenticationError("Invalid API key.")

    if not app.is_active:
        raise AuthenticationError("Application account is disabled.")

    return app

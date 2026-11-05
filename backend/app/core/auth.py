"""Authentication and tenant context resolution helpers for PRIVGUARD API."""

from typing import Any, Dict
from fastapi import Depends

from app.core.tenant import TenantContext, resolve_tenant_context
from app.core.authentication import get_current_app
from app.database.connection import get_db_session, get_db


async def get_current_user_tenant(
    ctx: TenantContext = Depends(resolve_tenant_context),
) -> Dict[str, Any]:
    """Returns the authenticated tenant context as a dictionary."""
    return {
        "tenant_id": ctx.tenant_id,
        "organization_id": ctx.organization_id,
        "workspace_id": ctx.workspace_id,
        "user_id": ctx.user_id,
        "role": ctx.role,
        "app_id": ctx.app_id,
    }

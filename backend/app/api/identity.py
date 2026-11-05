"""SCIM 2.0 Enterprise User Provisioning Endpoints."""

from typing import Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Header
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.tenant import TenantContext, resolve_tenant_context
from app.database.connection import get_db_session
from app.enterprise.scim import SCIMService, SCIMUserPayload
from app.enterprise.rbac import RBACAuthorizer, Permission

router = APIRouter(prefix="/v1/scim/v2", tags=["SCIM 2.0 Enterprise Provisioning"])


@router.get("/Users")
async def list_scim_users(
    startIndex: int = 1,
    count: int = 50,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Lists provisioned enterprise users for the tenant via SCIM 2.0."""
    RBACAuthorizer.enforce_permission(ctx, Permission.ORG_MEMBERS_MANAGE.value)
    return await SCIMService.list_users(db, ctx.organization_id, startIndex, count)


@router.post("/Users", status_code=status.HTTP_201_CREATED)
async def create_scim_user(
    payload: SCIMUserPayload,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Provisions a new user into the enterprise organization via SCIM 2.0."""
    RBACAuthorizer.enforce_permission(ctx, Permission.ORG_MEMBERS_MANAGE.value)
    return await SCIMService.provision_user(db, ctx.organization_id, payload)


@router.get("/Users/{user_id}")
async def get_scim_user(
    user_id: str,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Retrieves an enterprise user via SCIM 2.0."""
    RBACAuthorizer.enforce_permission(ctx, Permission.ORG_READ.value)
    return await SCIMService.get_user(db, ctx.organization_id, user_id)


@router.patch("/Users/{user_id}")
@router.put("/Users/{user_id}")
async def update_scim_user(
    user_id: str,
    payload: Dict[str, Any],
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Updates attributes or activates/deactivates an enterprise user via SCIM 2.0."""
    RBACAuthorizer.enforce_permission(ctx, Permission.ORG_MEMBERS_MANAGE.value)
    return await SCIMService.update_user(db, ctx.organization_id, user_id, payload)


@router.delete("/Users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scim_user(
    user_id: str,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Deprovisions an enterprise user with immediate session and grant revocation via SCIM 2.0."""
    RBACAuthorizer.enforce_permission(ctx, Permission.ORG_MEMBERS_MANAGE.value)
    await SCIMService.deprovision_user(db, ctx.organization_id, user_id)
    return None


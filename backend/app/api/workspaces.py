"""Enterprise Departmental Workspaces REST APIs."""

from typing import List, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.tenant import TenantContext, resolve_tenant_context
from app.database.connection import get_db_session
from app.database.models import Workspace
from app.enterprise.rbac import RBACAuthorizer, Permission
from app.enterprise.workspaces import WorkspaceManager

router = APIRouter(prefix="/v1/organizations/{org_id}/workspaces", tags=["Enterprise Workspaces"])


class WorkspaceCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    slug: Optional[str] = None
    description: Optional[str] = None
    is_default: bool = False


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_workspace(
    org_id: str,
    payload: WorkspaceCreateRequest,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Creates a new workspace within an organization."""
    if ctx.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")
    RBACAuthorizer.enforce_permission(ctx, Permission.WORKSPACE_MANAGE.value)

    ws = await WorkspaceManager.create_workspace(
        db=db,
        organization_id=org_id,
        name=payload.name,
        slug=payload.slug,
        description=payload.description,
        is_default=payload.is_default,
    )
    return {
        "id": ws.id,
        "name": ws.name,
        "slug": ws.slug,
        "description": ws.description,
        "is_default": ws.is_default,
        "created_at": ws.created_at.isoformat(),
    }


@router.get("")
async def list_workspaces(
    org_id: str,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Lists workspaces in the organization."""
    if ctx.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")
    RBACAuthorizer.enforce_permission(ctx, Permission.WORKSPACE_READ.value)

    workspaces = await WorkspaceManager.list_workspaces(db, org_id)
    return [
        {
            "id": ws.id,
            "name": ws.name,
            "slug": ws.slug,
            "description": ws.description,
            "is_default": ws.is_default,
            "created_at": ws.created_at.isoformat(),
        }
        for ws in workspaces
    ]

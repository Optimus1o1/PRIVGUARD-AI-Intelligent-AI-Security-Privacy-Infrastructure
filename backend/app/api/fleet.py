"""Enterprise AI Fleet Management and Synchronization REST APIs."""

import json
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AuthorizationError, SecurityPolicyViolationError
from app.core.tenant import TenantContext, resolve_tenant_context
from app.database.connection import get_db_session
from app.enterprise.rbac import RBACAuthorizer, Permission
from app.enterprise.fleet import FleetManager
from app.enterprise.sync import PolicySyncEngine

router = APIRouter(prefix="/v1/organizations/{org_id}", tags=["Enterprise Fleet Management"])


class FleetRegisterRequest(BaseModel):
    resource_type: str = Field(..., description="AGENT, MCP_SERVER, GATEWAY_INSTANCE, SDK_CLIENT")
    resource_id: str
    name: str
    workspace_id: Optional[str] = None
    environment: str = "production"
    current_policy_version: Optional[int] = None
    current_policy_hash: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class FleetHeartbeatRequest(BaseModel):
    resource_id: str
    reported_policy_version: Optional[int] = None
    reported_policy_hash: Optional[str] = None


class RevokeResourceRequest(BaseModel):
    reason: str = "Administrative revocation"


@router.get("/fleet")
async def list_fleet(
    org_id: str,
    workspace_id: Optional[str] = None,
    resource_type: Optional[str] = None,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Lists fleet inventory and real-time status."""
    if ctx.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")
    RBACAuthorizer.enforce_permission(ctx, Permission.FLEET_READ.value)

    resources = await FleetManager.list_fleet(db, org_id, workspace_id, resource_type)
    return [
        {
            "id": r.id,
            "resource_id": r.resource_id,
            "resource_type": r.resource_type,
            "name": r.name,
            "workspace_id": r.workspace_id,
            "environment": r.environment,
            "status": r.status,
            "active_policy_version": r.active_policy_version,
            "active_policy_hash": r.active_policy_hash,
            "drift_status": r.drift_status,
            "last_heartbeat_at": r.last_heartbeat_at.isoformat(),
            "registered_at": r.registered_at.isoformat(),
        }
        for r in resources
    ]


@router.post("/fleet/register", status_code=status.HTTP_201_CREATED)
async def register_fleet_resource(
    org_id: str,
    payload: FleetRegisterRequest,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Registers a fleet agent, MCP server, or gateway instance."""
    if ctx.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")
    RBACAuthorizer.enforce_permission(ctx, Permission.FLEET_REGISTER.value)

    res = await FleetManager.register_resource(
        db=db,
        tenant_id=org_id,
        resource_type=payload.resource_type,
        resource_id=payload.resource_id,
        name=payload.name,
        workspace_id=payload.workspace_id,
        environment=payload.environment,
        current_policy_version=payload.current_policy_version,
        current_policy_hash=payload.current_policy_hash,
        metadata=payload.metadata,
    )
    return {
        "id": res.id,
        "resource_id": res.resource_id,
        "status": res.status,
        "drift_status": res.drift_status,
    }


@router.post("/fleet/heartbeat")
async def fleet_heartbeat(
    org_id: str,
    payload: FleetHeartbeatRequest,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Processes resource heartbeat and drift check."""
    if ctx.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")

    res = await FleetManager.record_heartbeat(
        db=db,
        tenant_id=org_id,
        resource_id=payload.resource_id,
        reported_policy_version=payload.reported_policy_version,
        reported_policy_hash=payload.reported_policy_hash,
    )
    return {
        "resource_id": res.resource_id,
        "status": res.status,
        "drift_status": res.drift_status,
        "last_heartbeat_at": res.last_heartbeat_at.isoformat(),
    }


@router.post("/fleet/{resource_id}/revoke")
async def revoke_resource(
    org_id: str,
    resource_id: str,
    payload: RevokeResourceRequest,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Authoritatively revokes an agent or MCP server centrally."""
    if ctx.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")
    RBACAuthorizer.enforce_permission(ctx, Permission.FLEET_REVOKE.value)

    res = await FleetManager.revoke_resource(
        db=db,
        tenant_id=org_id,
        resource_id=resource_id,
        reason=payload.reason,
    )
    return {"resource_id": resource_id, "status": "REVOKED", "reason": payload.reason}


@router.get("/policy-sync")
async def get_policy_sync_status(
    org_id: str,
    workspace_id: Optional[str] = None,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Returns compliance and drift statistics for the fleet."""
    if ctx.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")
    RBACAuthorizer.enforce_permission(ctx, Permission.FLEET_READ.value)

    metrics = await PolicySyncEngine.get_sync_status(db, org_id, workspace_id)
    return metrics


@router.get("/fleet/{resource_id}/policy")
async def get_resource_policy_bundle(
    org_id: str,
    resource_id: str,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Fetches the active signed policy bundle assigned to a specific fleet resource."""
    if ctx.organization_id != org_id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")

    bundle = await PolicySyncEngine.get_active_bundle_for_resource(db, org_id, resource_id)
    if not bundle:
        raise HTTPException(status_code=404, detail="No active policy bundle configured.")

    return {
        "bundle_id": bundle.id,
        "version": bundle.version,
        "policy_hash": bundle.policy_hash,
        "signature_ed25519": bundle.signature_ed25519,
        "signing_key_id": bundle.signing_key_id,
        "bundle": json.loads(bundle.bundle_json),
    }

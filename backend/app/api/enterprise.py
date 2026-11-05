"""Enterprise Organizations, Memberships, Invitations, SSO, Audit, and Governance APIs."""

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.exceptions import AuthorizationError, SecurityPolicyViolationError
from app.core.tenant import TenantContext, resolve_tenant_context, get_current_tenant_id
from app.database.connection import get_db_session
from app.database.models import (
    Organization,
    OrganizationMembership,
    PolicyBundle,
    FleetResource,
    EnterpriseAuditEvent,
    AuditExportJob,
    utcnow,
)
from app.enterprise.rbac import require_permission, Permission, RBACAuthorizer
from app.enterprise.identity import EnterpriseIdentityManager, SSOConfig
from app.enterprise.audit import EnterpriseAuditLedger
from app.enterprise.fleet import FleetManager
from app.policies.governance import PolicyGovernanceManager

router = APIRouter(prefix="/v1/organizations", tags=["Enterprise Organizations & Governance"])


class OrganizationCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=128)
    slug: str = Field(..., min_length=2, max_length=64)
    domain: Optional[str] = None
    retention_days: int = 90


class InviteMemberRequest(BaseModel):
    email: str
    role: str = "VIEWER"


class UpdateMemberRequest(BaseModel):
    role: Optional[str] = None
    status: Optional[str] = None  # ACTIVE, SUSPENDED, DEPROVISIONED


class AcceptInviteRequest(BaseModel):
    invitation_token: str
    user_id: str


class DomainVerifyRequest(BaseModel):
    domain: str
    verification_token: str


class CreatePolicyBundleRequest(BaseModel):
    rules: List[Dict[str, Any]]
    workspace_id: Optional[str] = None


class DeployPolicyRequest(BaseModel):
    rollout_stage: str = "ORG_WIDE"


class SIEMExportRequest(BaseModel):
    destination_url: str
    destination_type: str = "SIEM_WEBHOOK"


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_organization(
    payload: OrganizationCreateRequest,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Creates a new enterprise organization boundary."""
    # Check if slug exists
    q = select(Organization).where(Organization.slug == payload.slug.lower())
    res = await db.execute(q)
    if res.scalar_one_or_none():
        raise HTTPException(status_code=400, detail=f"Organization slug '{payload.slug}' already exists.")

    org = Organization(
        name=payload.name,
        slug=payload.slug.lower(),
        domain=payload.domain.lower() if payload.domain else None,
        retention_days=payload.retention_days,
        status="ACTIVE",
    )
    db.add(org)
    await db.flush()

    # Add creator as ORGANIZATION_OWNER
    owner_user_id = ctx.user_id or "usr_creator"
    owner_email = ctx.email or f"{owner_user_id}@privguard.internal"
    mem = OrganizationMembership(
        organization_id=org.id,
        user_id=owner_user_id,
        email=owner_email,
        role="ORGANIZATION_OWNER",
        status="ACTIVE",
    )
    db.add(mem)

    # Record audit event
    await EnterpriseAuditLedger.record_event(
        db=db,
        tenant_id=org.id,
        action="ORG_CREATED",
        actor_type="USER",
        actor_id=owner_user_id,
        resource_type="ORGANIZATION",
        resource_id=org.id,
        details={"name": org.name, "slug": org.slug},
    )

    await db.commit()
    await db.refresh(org)
    return {"id": org.id, "name": org.name, "slug": org.slug, "status": org.status}


@router.get("")
async def list_organizations(
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Lists organizations accessible to the authenticated context."""
    if ctx.role == "ORGANIZATION_OWNER" and ctx.organization_id == "default_tenant":
        q = select(Organization)
    else:
        q = select(Organization).where(Organization.id == ctx.organization_id)
    res = await db.execute(q)
    orgs = res.scalars().all()
    return [{"id": o.id, "name": o.name, "slug": o.slug, "status": o.status, "domain": o.domain} for o in orgs]


@router.get("/{id}")
async def get_organization(
    id: str,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Retrieves an organization's details after verifying tenant access."""
    if ctx.organization_id != id and ctx.organization_id != "default_tenant":
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")

    q = select(Organization).where(Organization.id == id)
    res = await db.execute(q)
    org = res.scalar_one_or_none()
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found.")

    return {
        "id": org.id,
        "name": org.name,
        "slug": org.slug,
        "status": org.status,
        "domain": org.domain,
        "domain_verified": org.domain_verified,
        "retention_days": org.retention_days,
        "created_at": org.created_at.isoformat(),
    }


# ==========================================
# MEMBERSHIP & INVITATIONS
# ==========================================

@router.post("/{id}/members/invite", status_code=status.HTTP_201_CREATED)
async def invite_member(
    id: str,
    payload: InviteMemberRequest,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Invites a user to join the enterprise organization."""
    if ctx.organization_id != id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")
    RBACAuthorizer.enforce_permission(ctx, Permission.ORG_MEMBERS_MANAGE.value)

    inv = await EnterpriseIdentityManager.create_invitation(
        db=db,
        organization_id=id,
        email=payload.email,
        role=payload.role,
        invited_by_user_id=ctx.user_id or "admin",
    )

    await EnterpriseAuditLedger.record_event(
        db=db,
        tenant_id=id,
        action="MEMBER_INVITED",
        actor_type="USER",
        actor_id=ctx.user_id or "admin",
        resource_type="INVITATION",
        resource_id=inv["invitation_id"],
        details={"email": payload.email, "role": payload.role},
    )

    return inv


@router.get("/{id}/members")
async def list_members(
    id: str,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Lists all enterprise members within the organization."""
    if ctx.organization_id != id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")
    RBACAuthorizer.enforce_permission(ctx, Permission.ORG_READ.value)

    q = select(OrganizationMembership).where(OrganizationMembership.organization_id == id)
    res = await db.execute(q)
    members = res.scalars().all()
    return [
        {
            "id": m.id,
            "user_id": m.user_id,
            "email": m.email,
            "role": m.role,
            "status": m.status,
            "mfa_enabled": m.mfa_enabled,
            "created_at": m.created_at.isoformat(),
        }
        for m in members
    ]


@router.patch("/{id}/members/{user_id}")
async def update_member(
    id: str,
    user_id: str,
    payload: UpdateMemberRequest,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Updates member role or status."""
    if ctx.organization_id != id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")
    RBACAuthorizer.enforce_permission(ctx, Permission.ORG_MEMBERS_MANAGE.value)

    q = select(OrganizationMembership).where(
        OrganizationMembership.organization_id == id,
        OrganizationMembership.user_id == user_id,
    )
    res = await db.execute(q)
    mem = res.scalar_one_or_none()
    if not mem:
        raise HTTPException(status_code=404, detail="Member not found.")

    if payload.role:
        mem.role = payload.role
    if payload.status:
        mem.status = payload.status
    mem.updated_at = utcnow()

    await EnterpriseAuditLedger.record_event(
        db=db,
        tenant_id=id,
        action="MEMBER_UPDATED",
        actor_type="USER",
        actor_id=ctx.user_id or "admin",
        resource_type="MEMBER",
        resource_id=user_id,
        details={"role": mem.role, "status": mem.status},
    )

    await db.commit()
    await db.refresh(mem)
    return {"user_id": mem.user_id, "role": mem.role, "status": mem.status}


@router.delete("/{id}/members/{user_id}")
async def remove_member(
    id: str,
    user_id: str,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Removes or deprovisions a member from the organization."""
    if ctx.organization_id != id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")
    RBACAuthorizer.enforce_permission(ctx, Permission.ORG_MEMBERS_MANAGE.value)

    from app.enterprise.scim import SCIMService
    await SCIMService.deprovision_user(db, id, user_id)

    await EnterpriseAuditLedger.record_event(
        db=db,
        tenant_id=id,
        action="MEMBER_REMOVED",
        actor_type="USER",
        actor_id=ctx.user_id or "admin",
        resource_type="MEMBER",
        resource_id=user_id,
        details={"deprovisioned": True},
    )

    return {"status": "DEPROVISIONED", "user_id": user_id}


@router.post("/invitations/accept")
async def accept_invitation_route(
    payload: AcceptInviteRequest,
    db: AsyncSession = Depends(get_db_session),
):
    """Consumes an invitation token to activate enterprise membership."""
    mem = await EnterpriseIdentityManager.accept_invitation(
        db=db,
        invitation_token=payload.invitation_token,
        user_id=payload.user_id,
    )
    return {
        "status": "ACCEPTED",
        "organization_id": mem.organization_id,
        "user_id": mem.user_id,
        "role": mem.role,
    }


# ==========================================
# DOMAIN VERIFICATION & SSO
# ==========================================

@router.post("/{id}/domain/verify")
async def verify_domain(
    id: str,
    payload: DomainVerifyRequest,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Verifies domain ownership for enterprise SSO."""
    if ctx.organization_id != id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")
    RBACAuthorizer.enforce_permission(ctx, Permission.ORG_SSO_MANAGE.value)

    verified = await EnterpriseIdentityManager.verify_domain(
        db=db,
        organization_id=id,
        domain=payload.domain,
        provided_token=payload.verification_token,
    )

    await EnterpriseAuditLedger.record_event(
        db=db,
        tenant_id=id,
        action="DOMAIN_VERIFIED",
        actor_type="USER",
        actor_id=ctx.user_id or "admin",
        resource_type="DOMAIN",
        resource_id=payload.domain,
        details={"verified": True},
    )

    return {"domain": payload.domain, "verified": verified}


# ==========================================
# POLICY GOVERNANCE & BUNDLES
# ==========================================

@router.get("/{id}/policies")
async def list_policies(
    id: str,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Lists policy bundle history for an organization."""
    if ctx.organization_id != id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")
    RBACAuthorizer.enforce_permission(ctx, Permission.POLICY_READ.value)

    q = select(PolicyBundle).where(PolicyBundle.organization_id == id).order_by(PolicyBundle.version.desc())
    res = await db.execute(q)
    bundles = res.scalars().all()
    return [
        {
            "id": b.id,
            "version": b.version,
            "status": b.status,
            "policy_hash": b.policy_hash,
            "rollout_stage": b.rollout_stage,
            "signing_key_id": b.signing_key_id,
            "created_at": b.created_at.isoformat(),
            "activated_at": b.activated_at.isoformat() if b.activated_at else None,
        }
        for b in bundles
    ]


@router.post("/{id}/policies", status_code=status.HTTP_201_CREATED)
async def create_policy_bundle(
    id: str,
    payload: CreatePolicyBundleRequest,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Creates, validates, and signs a new policy bundle with Ed25519."""
    if ctx.organization_id != id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")
    RBACAuthorizer.enforce_permission(ctx, Permission.POLICY_DRAFT.value)

    bundle = await PolicyGovernanceManager.create_policy_bundle(
        db=db,
        organization_id=id,
        workspace_id=payload.workspace_id,
        rules=payload.rules,
        created_by=ctx.user_id or "admin",
    )

    await EnterpriseAuditLedger.record_event(
        db=db,
        tenant_id=id,
        action="POLICY_BUNDLE_CREATED",
        actor_type="USER",
        actor_id=ctx.user_id or "admin",
        resource_type="POLICY_BUNDLE",
        resource_id=bundle.id,
        details={"version": bundle.version, "hash": bundle.policy_hash},
    )

    return {
        "id": bundle.id,
        "version": bundle.version,
        "status": bundle.status,
        "policy_hash": bundle.policy_hash,
        "signature_ed25519": bundle.signature_ed25519,
    }


@router.post("/{id}/policies/{bundle_id}/deploy")
async def deploy_policy(
    id: str,
    bundle_id: str,
    payload: DeployPolicyRequest,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Deploys a signed policy bundle across the fleet with anti-downgrade checks."""
    if ctx.organization_id != id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")
    RBACAuthorizer.enforce_permission(ctx, Permission.POLICY_DEPLOY.value)

    bundle = await PolicyGovernanceManager.deploy_policy_bundle(
        db=db,
        bundle_id=bundle_id,
        deployed_by=ctx.user_id or "admin",
        rollout_stage=payload.rollout_stage,
    )

    await EnterpriseAuditLedger.record_event(
        db=db,
        tenant_id=id,
        action="POLICY_DEPLOYED",
        actor_type="USER",
        actor_id=ctx.user_id or "admin",
        resource_type="POLICY_BUNDLE",
        resource_id=bundle.id,
        details={"version": bundle.version, "rollout_stage": payload.rollout_stage},
    )

    return {"id": bundle.id, "version": bundle.version, "status": bundle.status}


@router.post("/{id}/policies/{bundle_id}/rollback")
async def rollback_policy(
    id: str,
    bundle_id: str,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Rolls back the active policy to a previous verified version."""
    if ctx.organization_id != id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")
    RBACAuthorizer.enforce_permission(ctx, Permission.POLICY_DEPLOY.value)

    bundle = await PolicyGovernanceManager.rollback_policy(
        db=db,
        target_bundle_id=bundle_id,
        deployed_by=ctx.user_id or "admin",
    )

    await EnterpriseAuditLedger.record_event(
        db=db,
        tenant_id=id,
        action="POLICY_ROLLED_BACK",
        actor_type="USER",
        actor_id=ctx.user_id or "admin",
        resource_type="POLICY_BUNDLE",
        resource_id=bundle.id,
        details={"version": bundle.version},
    )

    return {"id": bundle.id, "version": bundle.version, "status": bundle.status}


# ==========================================
# AUDIT & SIEM
# ==========================================

@router.get("/{id}/audit")
async def get_audit_trail(
    id: str,
    limit: int = 50,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Fetches tenant-scoped hash-chained audit events."""
    if ctx.organization_id != id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")
    RBACAuthorizer.enforce_permission(ctx, Permission.AUDIT_READ.value)

    q = select(EnterpriseAuditEvent).where(
        EnterpriseAuditEvent.tenant_id == id
    ).order_by(EnterpriseAuditEvent.sequence_number.desc()).limit(limit)
    res = await db.execute(q)
    events = res.scalars().all()

    return [
        {
            "id": e.id,
            "sequence": e.sequence_number,
            "action": e.action,
            "actor": f"{e.actor_type}:{e.actor_id}",
            "resource": f"{e.resource_type}:{e.resource_id}",
            "previous_hash": e.previous_event_hash,
            "hash": e.event_hash,
            "timestamp": e.created_at.isoformat(),
        }
        for e in events
    ]


@router.get("/{id}/audit/verify-integrity")
async def verify_audit_integrity(
    id: str,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Cryptographically verifies that the audit ledger has not been tampered with."""
    if ctx.organization_id != id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")
    RBACAuthorizer.enforce_permission(ctx, Permission.AUDIT_READ.value)

    is_valid, violations = await EnterpriseAuditLedger.verify_chain_integrity(db, id)
    return {"is_valid": is_valid, "violations_detected": len(violations), "details": violations}


@router.post("/{id}/audit/export")
async def export_audit_to_siem(
    id: str,
    payload: SIEMExportRequest,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Initiates an asynchronous, verified SIEM export job."""
    if ctx.organization_id != id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")
    RBACAuthorizer.enforce_permission(ctx, Permission.AUDIT_EXPORT.value)

    job = await EnterpriseAuditLedger.create_export_job(
        db=db,
        tenant_id=id,
        destination_url=payload.destination_url,
        destination_type=payload.destination_type,
    )
    return {"job_id": job.id, "status": job.status, "records_count": job.records_count}


# ==========================================
# GOVERNANCE SUMMARY
# ==========================================

@router.get("/{id}/governance-summary")
async def get_governance_summary(
    id: str,
    ctx: TenantContext = Depends(resolve_tenant_context),
    db: AsyncSession = Depends(get_db_session),
):
    """Returns top-level governance, fleet, and policy compliance metrics for the organization."""
    if ctx.organization_id != id:
        raise HTTPException(status_code=403, detail="Forbidden: Tenant isolation mismatch.")

    from app.enterprise.sync import PolicySyncEngine
    sync_status = await PolicySyncEngine.get_sync_status(db, id)

    # Count members
    mem_q = select(OrganizationMembership).where(OrganizationMembership.organization_id == id)
    mem_res = await db.execute(mem_q)
    members_count = len(mem_res.scalars().all())

    # Fetch active policy version
    pol_q = select(PolicyBundle).where(
        PolicyBundle.organization_id == id,
        PolicyBundle.status == "ACTIVE"
    )
    pol_res = await db.execute(pol_q)
    active_bundle = pol_res.scalars().first()

    return {
        "organization_id": id,
        "members_count": members_count,
        "active_policy_version": active_bundle.version if active_bundle else None,
        "active_policy_hash": active_bundle.policy_hash if active_bundle else None,
        "fleet_sync": sync_status,
        "timestamp": utcnow().isoformat(),
    }


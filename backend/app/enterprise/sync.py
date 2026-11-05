"""Fleet policy distribution, staged rollout, and drift reconciliation."""

from typing import Dict, Any, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.core.exceptions import SecurityPolicyViolationError
from app.database.models import FleetResource, PolicyBundle, utcnow, ensure_utc
from app.enterprise.fleet import MAX_STALENESS_SECONDS


class PolicySyncEngine:
    """Orchestrates policy bundle synchronization and detects fleet configuration drift."""

    @staticmethod
    async def get_sync_status(
        db: AsyncSession, tenant_id: str, workspace_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Calculates fleet-wide policy compliance and drift metrics."""
        q = select(FleetResource).where(FleetResource.tenant_id == tenant_id)
        if workspace_id:
            q = q.where(FleetResource.workspace_id == workspace_id)

        res = await db.execute(q)
        fleet = res.scalars().all()

        total = len(fleet)
        synced = 0
        drifted = 0
        disconnected = 0
        revoked = 0

        now = utcnow()
        for item in fleet:
            if item.status == "REVOKED":
                revoked += 1
                continue

            last_hb = ensure_utc(item.last_heartbeat_at)
            staleness = (now - last_hb).total_seconds()
            if staleness > MAX_STALENESS_SECONDS:
                disconnected += 1
            elif item.drift_status == "DRIFTED":
                drifted += 1
            else:
                synced += 1

        compliance_rate = (synced / (total - revoked) * 100.0) if (total - revoked) > 0 else 100.0

        return {
            "total_resources": total,
            "synced_count": synced,
            "drifted_count": drifted,
            "disconnected_count": disconnected,
            "revoked_count": revoked,
            "compliance_percentage": round(compliance_rate, 1),
        }

    @staticmethod
    async def get_active_bundle_for_resource(
        db: AsyncSession,
        tenant_id: str,
        resource_id: str
    ) -> Optional[PolicyBundle]:
        """Fetches the authoritative active signed policy bundle for an individual fleet resource."""
        q = select(FleetResource).where(
            FleetResource.tenant_id == tenant_id,
            FleetResource.resource_id == resource_id,
        )
        res = await db.execute(q)
        resource = res.scalar_one_or_none()
        if not resource:
            return None

        if resource.status in ("REVOKED", "DISABLED", "QUARANTINED"):
            raise SecurityPolicyViolationError(
                f"Policy sync refused: Resource '{resource_id}' is {resource.status}."
            )

        # Look for workspace-specific active bundle first
        if resource.workspace_id:
            ws_q = select(PolicyBundle).where(
                PolicyBundle.organization_id == tenant_id,
                PolicyBundle.workspace_id == resource.workspace_id,
                PolicyBundle.status == "ACTIVE",
            )
            ws_res = await db.execute(ws_q)
            ws_bundle = ws_res.scalar_one_or_none()
            if ws_bundle:
                return ws_bundle

        # Fallback to org-wide baseline active bundle
        org_q = select(PolicyBundle).where(
            PolicyBundle.organization_id == tenant_id,
            PolicyBundle.workspace_id.is_(None),
            PolicyBundle.status == "ACTIVE",
        )
        org_res = await db.execute(org_q)
        return org_res.scalar_one_or_none()


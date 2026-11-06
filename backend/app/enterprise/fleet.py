"""Centralized AI Fleet Management, Inventory, and Authoritative Revocation."""

import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.core.exceptions import AuthorizationError, SecurityPolicyViolationError
from app.database.models import (
    FleetResource,
    Agent,
    MCPServer,
    CapabilityGrant,
    PolicyBundle,
    utcnow,
    ensure_utc,
)

MAX_STALENESS_SECONDS = 3600  # 1 hour before an agent is classified as DISCONNECTED


class FleetManager:
    """Manages the enterprise inventory of AI agents, MCP servers, and gateways."""

    @staticmethod
    async def register_resource(
        db: AsyncSession,
        tenant_id: str,
        resource_type: str,
        resource_id: str,
        name: str,
        workspace_id: Optional[str] = None,
        environment: str = "production",
        current_policy_version: Optional[int] = None,
        current_policy_hash: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> FleetResource:
        """Registers a new fleet resource or updates an existing inventory record."""
        valid_types = ("AGENT", "MCP_SERVER", "GATEWAY_INSTANCE", "SDK_CLIENT")
        if resource_type.upper() not in valid_types:
            raise ValueError(f"Invalid resource type '{resource_type}'. Must be one of {valid_types}.")

        q = select(FleetResource).where(
            FleetResource.tenant_id == tenant_id,
            FleetResource.resource_id == resource_id,
        )
        res = await db.execute(q)
        existing = res.scalar_one_or_none()

        now = utcnow()
        meta_str = json.dumps(metadata or {})

        if existing:
            existing.name = name
            existing.workspace_id = workspace_id or existing.workspace_id
            existing.environment = environment
            existing.last_heartbeat_at = now
            existing.metadata_json = meta_str
            if current_policy_version:
                existing.active_policy_version = current_policy_version
            if current_policy_hash:
                existing.active_policy_hash = current_policy_hash
            await db.commit()
            await db.refresh(existing)
            return existing

        resource = FleetResource(
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            resource_type=resource_type.upper(),
            resource_id=resource_id,
            name=name,
            environment=environment,
            status="ACTIVE",
            active_policy_version=current_policy_version,
            active_policy_hash=current_policy_hash,
            drift_status="SYNCED",
            last_heartbeat_at=now,
            registered_at=now,
            metadata_json=meta_str,
        )
        db.add(resource)
        await db.commit()
        await db.refresh(resource)
        return resource

    @staticmethod
    async def record_heartbeat(
        db: AsyncSession,
        tenant_id: str,
        resource_id: str,
        reported_policy_version: Optional[int] = None,
        reported_policy_hash: Optional[str] = None,
    ) -> FleetResource:
        """
        Processes an agent heartbeat, evaluates policy drift against the active signed policy,
        and enforces fail-safe disconnected boundaries.
        """
        q = select(FleetResource).where(
            FleetResource.tenant_id == tenant_id,
            FleetResource.resource_id == resource_id,
        )
        res = await db.execute(q)
        resource = res.scalar_one_or_none()
        if not resource:
            raise AuthorizationError(f"Fleet resource '{resource_id}' is not registered under tenant '{tenant_id}'.")

        if resource.status in ("REVOKED", "DISABLED", "QUARANTINED"):
            raise SecurityPolicyViolationError(
                f"Fleet operation rejected: Resource '{resource_id}' is in status '{resource.status}'."
            )

        now = utcnow()
        resource.last_heartbeat_at = now

        # Fetch current active policy bundle for this tenant/workspace
        pol_q = select(PolicyBundle).where(
            PolicyBundle.organization_id == tenant_id,
            PolicyBundle.workspace_id == resource.workspace_id,
            PolicyBundle.status == "ACTIVE",
        )
        pol_res = await db.execute(pol_q)
        active_bundle = pol_res.scalar_one_or_none()

        if active_bundle:
            target_hash = active_bundle.policy_hash
            if reported_policy_hash and reported_policy_hash != target_hash:
                resource.drift_status = "DRIFTED"
            else:
                resource.drift_status = "SYNCED"
        else:
            resource.drift_status = "SYNCED"

        if reported_policy_version:
            resource.active_policy_version = reported_policy_version
        if reported_policy_hash:
            resource.active_policy_hash = reported_policy_hash

        await db.commit()
        await db.refresh(resource)
        return resource

    @staticmethod
    async def revoke_resource(
        db: AsyncSession,
        tenant_id: str,
        resource_id: str,
        reason: str = "Administrative revocation",
    ) -> FleetResource:
        """
        Authoritatively revokes an AI agent or MCP server centrally.
        Core Decision: When an administrator disables an agent, the backend immediately
        rejects subsequent protected operations, even if the agent is offline.
        """
        q = select(FleetResource).where(
            FleetResource.tenant_id == tenant_id,
            FleetResource.resource_id == resource_id,
        )
        res = await db.execute(q)
        resource = res.scalar_one_or_none()

        if resource:
            resource.status = "REVOKED"
            resource.metadata_json = json.dumps(
                {
                    **json.loads(resource.metadata_json or "{}"),
                    "revoked_at": utcnow().isoformat(),
                    "revocation_reason": reason,
                }
            )

        # Propagate to underlying Agent model if resource is an agent
        agent_q = select(Agent).where(
            Agent.tenant_id == tenant_id,
            Agent.id == resource_id,
        )
        agent_res = await db.execute(agent_q)
        agent = agent_res.scalar_one_or_none()
        if agent:
            agent.status = "REVOKED"

        # Propagate to underlying MCPServer model if resource is an MCP server
        server_q = select(MCPServer).where(
            MCPServer.tenant_id == tenant_id,
            MCPServer.id == resource_id,
        )
        server_res = await db.execute(server_q)
        server = server_res.scalar_one_or_none()
        if server:
            server.status = "DISABLED"

        # Revoke all active capability grants for this agent
        await db.execute(
            update(CapabilityGrant)
            .where(
                CapabilityGrant.tenant_id == tenant_id,
                CapabilityGrant.agent_id == resource_id,
            )
            .values(is_revoked=True)
        )

        # Emit transactional outbox event for distributed revocation
        from app.infrastructure.outbox import emit_outbox_event

        emit_outbox_event(
            session=db,
            event_type="AGENT_REVOKED"
            if (resource and resource.resource_type == "AGENT")
            else "FLEET_RESOURCE_REVOKED",
            aggregate_id=resource_id,
            payload={
                "reason": reason,
                "resource_type": resource.resource_type if resource else "AGENT",
            },
            tenant_id=tenant_id,
            workspace_id=resource.workspace_id if resource else None,
        )

        await db.commit()
        if resource:
            await db.refresh(resource)
            return resource
        return None

    @staticmethod
    async def list_fleet(
        db: AsyncSession,
        tenant_id: str,
        workspace_id: Optional[str] = None,
        resource_type: Optional[str] = None,
    ) -> List[FleetResource]:
        """Lists fleet inventory and evaluates real-time staleness."""
        q = select(FleetResource).where(FleetResource.tenant_id == tenant_id)
        if workspace_id:
            q = q.where(FleetResource.workspace_id == workspace_id)
        if resource_type:
            q = q.where(FleetResource.resource_type == resource_type.upper())

        res = await db.execute(q)
        resources = res.scalars().all()

        now = utcnow()
        for r in resources:
            last_hb = ensure_utc(r.last_heartbeat_at)
            staleness = (now - last_hb).total_seconds()
            if staleness > MAX_STALENESS_SECONDS and r.status == "ACTIVE":
                r.drift_status = "DISCONNECTED"

        return resources

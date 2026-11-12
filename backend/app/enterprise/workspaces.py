"""Enterprise Departmental Workspaces and boundary isolation."""

import re
from typing import List, Optional, Dict, Any
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.exceptions import AuthorizationError
from app.database.models import Workspace, WorkspaceMembership, Agent, MCPServer, utcnow


class WorkspaceManager:
    """Manages workspace lifecycle and cross-workspace access control."""

    @staticmethod
    async def create_workspace(
        db: AsyncSession,
        organization_id: str,
        name: str,
        slug: Optional[str] = None,
        description: Optional[str] = None,
        is_default: bool = False,
    ) -> Workspace:
        """Creates a new workspace within an organization."""
        if not slug:
            slug = re.sub(r"[^a-z0-9_-]", "-", name.lower()).strip("-")

        ws = Workspace(
            organization_id=organization_id,
            tenant_id=organization_id,
            name=name,
            slug=slug,
            description=description,
            is_default=is_default,
        )
        db.add(ws)
        await db.commit()
        await db.refresh(ws)
        return ws

    @staticmethod
    async def list_workspaces(db: AsyncSession, organization_id: str) -> List[Workspace]:
        """Lists all workspaces belonging to an organization."""
        q = select(Workspace).where(Workspace.organization_id == organization_id)
        res = await db.execute(q)
        return res.scalars().all()

    @staticmethod
    async def verify_agent_workspace_access(
        db: AsyncSession, agent_id: str, target_workspace_id: Optional[str]
    ) -> bool:
        """
        Enforces workspace boundary jailing:
        Agents registered to Workspace X cannot automatically operate in Workspace Y.
        """
        if not target_workspace_id:
            return True

        q = select(Agent).where(Agent.id == agent_id)
        res = await db.execute(q)
        agent = res.scalar_one_or_none()
        if not agent:
            raise AuthorizationError(f"Agent '{agent_id}' not found.")

        agent_ws = getattr(agent, "workspace_id", None)
        # If agent has a specific workspace, it cannot operate outside it without cross-workspace permission
        if agent_ws and agent_ws != target_workspace_id:
            raise AuthorizationError(
                f"Workspace Violation: Agent '{agent_id}' is jailed to workspace '{agent_ws}' "
                f"and cannot access resources in workspace '{target_workspace_id}'."
            )

        return True

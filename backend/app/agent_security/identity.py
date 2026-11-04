"""Agent Identity and Lifecycle Management."""

import json
from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.core.exceptions import PrivGuardException
from app.database.models import Agent, utcnow


class AgentIdentityManager:
    """Manages AI agent registration, identity verification, and status."""

    async def register_agent(
        self,
        db: AsyncSession,
        app_id: str,
        name: str,
        description: Optional[str] = None,
        allowed_tools: Optional[List[str]] = None,
    ) -> Agent:
        """Registers a new AI agent bound to the authenticated application."""
        tools_list = allowed_tools or ["read_file", "search_web"]
        agent = Agent(
            app_id=app_id,
            name=name.strip(),
            description=description.strip() if description else None,
            status="ACTIVE",
            allowed_tools=json.dumps(tools_list),
            created_at=datetime.now(timezone.utc),
            last_activity_at=datetime.now(timezone.utc),
        )
        db.add(agent)
        await db.commit()
        await db.refresh(agent)
        return agent

    async def get_agent(
        self,
        db: AsyncSession,
        agent_id: str,
        app_id: str,
    ) -> Agent:
        """Retrieves an agent enforcing application ownership."""
        query = select(Agent).where(Agent.id == agent_id, Agent.app_id == app_id)
        result = await db.execute(query)
        agent = result.scalar_one_or_none()
        if not agent:
            raise PrivGuardException(
                message=f"Agent '{agent_id}' not found or not owned by caller.",
                status_code=404,
                error_code="AGENT_NOT_FOUND",
            )
        return agent

    async def list_agents(
        self,
        db: AsyncSession,
        app_id: str,
    ) -> List[Agent]:
        """Lists all agents belonging to the authenticated application."""
        query = select(Agent).where(Agent.app_id == app_id).order_by(Agent.created_at.desc())
        result = await db.execute(query)
        return list(result.scalars().all())

    async def set_status(
        self,
        db: AsyncSession,
        agent_id: str,
        app_id: str,
        new_status: str,
    ) -> Agent:
        """Updates agent operational status (ACTIVE, DISABLED, REVOKED)."""
        agent = await self.get_agent(db, agent_id, app_id)
        if new_status not in ("ACTIVE", "DISABLED", "REVOKED"):
            raise PrivGuardException(
                message=f"Invalid status '{new_status}'. Allowed: ACTIVE, DISABLED, REVOKED",
                status_code=400,
                error_code="INVALID_AGENT_STATUS",
            )
        agent.status = new_status
        agent.last_activity_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(agent)
        return agent

    async def validate_agent_active(
        self,
        db: AsyncSession,
        agent_id: str,
        app_id: str,
    ) -> Agent:
        """Verifies that an agent exists, belongs to caller, and is currently ACTIVE."""
        agent = await self.get_agent(db, agent_id, app_id)
        if agent.status != "ACTIVE":
            raise PrivGuardException(
                message=f"Agent '{agent_id}' access denied: status is '{agent.status}'.",
                status_code=403,
                error_code="AGENT_NOT_ACTIVE",
            )
        # Touch activity timestamp
        agent.last_activity_at = datetime.now(timezone.utc)
        await db.commit()
        return agent


# Shared identity manager instance
agent_identity_manager = AgentIdentityManager()


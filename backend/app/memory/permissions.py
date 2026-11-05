"""Granular Memory Permission Engine with Default-Deny Authorization."""

from datetime import datetime, timezone
from typing import List, Optional
from sqlalchemy import select, and_, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import MemoryPermissionError, PrivGuardException
from app.database.models import Agent, CapabilityGrant, MemoryPermission, ensure_utc, utcnow

VALID_OPERATIONS = {
    "memory.read",
    "memory.propose_write",
    "memory.update",
    "memory.delete",
}


class MemoryPermissionEngine:
    """Enforces server-side, least-privilege authorization over memory records."""

    async def check_permission(
        self,
        db: AsyncSession,
        app_id: str,
        owner_id: str,
        agent_id: Optional[str],
        operation: str,
        memory_id: Optional[str] = None,
        category: Optional[str] = None,
    ) -> bool:
        """
        Evaluates whether an actor (user or agent) is authorized for an operation.
        Direct user calls (agent_id is None) are permitted on their own records.
        Agent calls require an explicit, unexpired MemoryPermission.
        """
        if operation not in VALID_OPERATIONS:
            raise PrivGuardException(f"Invalid memory operation '{operation}'", status_code=400)

        # Direct user interaction on own vault
        if not agent_id:
            return True

        # Verify agent exists and is active under the application
        stmt_agent = select(Agent).where(Agent.id == agent_id, Agent.app_id == app_id)
        agent_res = await db.execute(stmt_agent)
        agent = agent_res.scalar_one_or_none()
        if not agent or agent.status != "ACTIVE":
            raise MemoryPermissionError(operation, agent_id or "unknown", resource=memory_id or category or "vault")

        # Query explicit permissions matching either specific memory_id or category wildcard
        now = datetime.now(timezone.utc)
        stmt_perm = select(MemoryPermission).where(
            MemoryPermission.app_id == app_id,
            MemoryPermission.owner_id == owner_id,
            MemoryPermission.agent_id == agent_id,
            MemoryPermission.operation == operation,
            MemoryPermission.is_granted == True,
            or_(
                MemoryPermission.memory_id == memory_id,
                MemoryPermission.category == category,
                and_(MemoryPermission.memory_id.is_(None), MemoryPermission.category.is_(None)),  # All-vault grant
            ),
        )
        res = await db.execute(stmt_perm)
        perms = res.scalars().all()

        for p in perms:
            if p.expires_at is None or ensure_utc(p.expires_at) > now:
                return True

        # Default: DENY
        raise MemoryPermissionError(operation, agent_id, resource=memory_id or category or "vault")

    async def grant_permission(
        self,
        db: AsyncSession,
        app_id: str,
        owner_id: str,
        agent_id: str,
        operation: str,
        memory_id: Optional[str] = None,
        category: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        ttl_seconds: Optional[int] = None,
    ) -> MemoryPermission:
        """Grants an agent permission over a specific memory, category, or whole vault."""
        if operation not in VALID_OPERATIONS:
            raise PrivGuardException(f"Invalid memory operation '{operation}'", status_code=400)

        if ttl_seconds and not expires_at:
            expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)

        perm = MemoryPermission(
            app_id=app_id,
            owner_id=owner_id,
            agent_id=agent_id,
            memory_id=memory_id,
            category=category,
            operation=operation,
            is_granted=True,
            expires_at=expires_at,
            created_at=utcnow(),
        )
        db.add(perm)
        await db.commit()
        await db.refresh(perm)
        return perm

    async def revoke_permission(
        self,
        db: AsyncSession,
        app_id: str,
        owner_id: str,
        permission_id: str,
    ) -> bool:
        """Revokes a memory permission immediately."""
        stmt = select(MemoryPermission).where(
            MemoryPermission.id == permission_id,
            MemoryPermission.app_id == app_id,
            MemoryPermission.owner_id == owner_id,
        )
        res = await db.execute(stmt)
        perm = res.scalar_one_or_none()
        if not perm:
            return False

        perm.is_granted = False
        await db.commit()
        return True

    async def list_permissions(
        self,
        db: AsyncSession,
        app_id: str,
        owner_id: str,
        agent_id: Optional[str] = None,
    ) -> List[MemoryPermission]:
        """Lists active memory permissions for a user vault."""
        stmt = select(MemoryPermission).where(
            MemoryPermission.app_id == app_id,
            MemoryPermission.owner_id == owner_id,
            MemoryPermission.is_granted == True,
        )
        if agent_id:
            stmt = stmt.where(MemoryPermission.agent_id == agent_id)
        res = await db.execute(stmt)
        return list(res.scalars().all())


# Global memory permission engine
memory_permission_engine = MemoryPermissionEngine()

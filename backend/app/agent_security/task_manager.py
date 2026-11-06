"""Task Lifecycle Manager with automatic capability and approval revocation."""

from datetime import datetime, timedelta, timezone
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
from app.agent_security.identity import agent_identity_manager
from app.core.exceptions import PrivGuardException
from app.database.models import AgentTask, ApprovalRequest, CapabilityGrant, ensure_utc, utcnow


class TaskManager:
    """Manages agent tasks, states, and automatic boundary cleanup."""

    async def create_task(
        self,
        db: AsyncSession,
        agent_id: str,
        app_id: str,
        description: Optional[str] = None,
        ttl_seconds: int = 600,
        max_steps: int = 50,
    ) -> AgentTask:
        """Initializes a new task session bound to an active agent and caller app."""
        # Verify agent is active and owned by app
        await agent_identity_manager.validate_agent_active(db, agent_id, app_id)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=ttl_seconds)

        task = AgentTask(
            agent_id=agent_id,
            app_id=app_id,
            status="RUNNING",
            description=description,
            step_count=0,
            max_steps=max_steps,
            created_at=now,
            expires_at=expires_at,
        )
        db.add(task)
        await db.commit()
        await db.refresh(task)
        return task

    async def get_task(
        self,
        db: AsyncSession,
        task_id: str,
        app_id: str,
    ) -> AgentTask:
        """Retrieves a task enforcing application ownership."""
        query = select(AgentTask).where(AgentTask.id == task_id, AgentTask.app_id == app_id)
        result = await db.execute(query)
        task = result.scalar_one_or_none()
        if not task:
            raise PrivGuardException(
                message=f"Task '{task_id}' not found or unauthorized.",
                status_code=404,
                error_code="TASK_NOT_FOUND",
            )
        return task

    async def validate_task_active(
        self,
        db: AsyncSession,
        task_id: str,
        app_id: str,
        agent_id: Optional[str] = None,
    ) -> AgentTask:
        """Validates that a task is active, unexpired, and correctly assigned."""
        task = await self.get_task(db, task_id, app_id)

        if agent_id and task.agent_id != agent_id:
            raise PrivGuardException(
                message=f"Task '{task_id}' does not belong to agent '{agent_id}'.",
                status_code=403,
                error_code="TASK_AGENT_MISMATCH",
            )

        now = datetime.now(timezone.utc)
        if ensure_utc(task.expires_at) < now:
            await self._cleanup_task_resources(db, task_id, "EXPIRED")
            task.status = "EXPIRED"
            task.completed_at = now
            await db.commit()
            raise PrivGuardException(
                message=f"Task '{task_id}' has expired.",
                status_code=403,
                error_code="TASK_EXPIRED",
            )

        if task.status in ("COMPLETED", "FAILED", "CANCELLED", "EXPIRED", "STEP_LIMIT_EXCEEDED"):
            raise PrivGuardException(
                message=f"Task '{task_id}' is closed (status: {task.status}).",
                status_code=403,
                error_code="TASK_ALREADY_CLOSED",
            )

        return task

    async def record_step(
        self,
        db: AsyncSession,
        task_id: str,
        app_id: str,
    ) -> int:
        """
        Increments task execution step counter.
        Enforces MAX_TASK_STEPS to prevent runaway agent loops or recursion resource exhaustion.
        """
        task = await self.get_task(db, task_id, app_id)
        current_steps = getattr(task, "step_count", 0) or 0
        limit = getattr(task, "max_steps", 50) or 50

        if current_steps >= limit:
            task.status = "STEP_LIMIT_EXCEEDED"
            task.completed_at = datetime.now(timezone.utc)
            await self._cleanup_task_resources(db, task_id, "STEP_LIMIT_EXCEEDED")
            await db.commit()
            raise PrivGuardException(
                message=f"Task '{task_id}' exceeded maximum execution step budget ({limit} steps).",
                status_code=429,
                error_code="TASK_STEP_LIMIT_EXCEEDED",
            )

        task.step_count = current_steps + 1
        await db.commit()
        return task.step_count

    async def cancel_task(
        self,
        db: AsyncSession,
        task_id: str,
        app_id: str,
    ) -> AgentTask:
        """Cancels a task and revokes all associated capabilities and approvals."""
        task = await self.get_task(db, task_id, app_id)
        now = datetime.now(timezone.utc)
        task.status = "CANCELLED"
        task.completed_at = now

        await self._cleanup_task_resources(db, task_id, "CANCELLED")
        await db.commit()
        await db.refresh(task)
        return task

    async def complete_task(
        self,
        db: AsyncSession,
        task_id: str,
        app_id: str,
        status: str = "COMPLETED",
    ) -> AgentTask:
        """Marks a task as completed/failed and revokes remaining temporary capabilities."""
        task = await self.get_task(db, task_id, app_id)
        now = datetime.now(timezone.utc)
        task.status = status
        task.completed_at = now

        await self._cleanup_task_resources(db, task_id, status)
        await db.commit()
        await db.refresh(task)
        return task

    async def _cleanup_task_resources(self, db: AsyncSession, task_id: str, terminal_status: str):
        """Revokes all capabilities and expires all pending approvals for a task."""
        # 1. Revoke all capability grants for this task
        await db.execute(update(CapabilityGrant).where(CapabilityGrant.task_id == task_id).values(is_revoked=True))
        # 2. Expire all pending approval requests for this task
        await db.execute(
            update(ApprovalRequest)
            .where(
                ApprovalRequest.task_id == task_id,
                ApprovalRequest.status == "PENDING",
            )
            .values(status="EXPIRED", resolved_at=datetime.now(timezone.utc))
        )


# Shared task manager instance
task_manager = TaskManager()

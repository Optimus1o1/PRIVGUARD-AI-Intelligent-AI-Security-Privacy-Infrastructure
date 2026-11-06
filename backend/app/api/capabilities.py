"""Temporary Capability Token Endpoints."""

import json
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from app.agent_security.capability_manager import capability_manager
from app.agent_security.identity import agent_identity_manager
from app.agent_security.task_manager import task_manager
from app.agent_security.tool_registry import tool_registry
from app.core.authentication import get_current_app
from app.database.connection import get_db_session
from app.database.models import Application

router = APIRouter(prefix="/v1/capabilities", tags=["Agent Security - Capabilities"])


class RequestCapabilityPayload(BaseModel):
    agent_id: str = Field(..., description="Target agent ID")
    task_id: str = Field(..., description="Task session ID to bind the capability to")
    tool_name: str = Field(..., description="Name of the permitted tool")
    resource: Optional[str] = Field(None, description="Permitted target resource/scope")
    permissions: Optional[List[str]] = Field(default_factory=lambda: ["execute"])
    ttl_seconds: int = Field(300, ge=10, le=3600, description="Validity window in seconds")
    max_uses: int = Field(1, ge=1, le=100, description="Maximum number of executions allowed")


class CapabilityResponse(BaseModel):
    id: str
    agent_id: str
    task_id: str
    tool_name: str
    resource: Optional[str]
    permissions: List[str]
    max_uses: int
    uses_count: int
    is_revoked: bool
    expires_at: datetime
    capability_token: Optional[str] = None  # Returned only upon issuance!


@router.post("/request", response_model=CapabilityResponse)
async def request_capability(
    payload: RequestCapabilityPayload,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> CapabilityResponse:
    """Issues a task-scoped, time-limited, revocable capability token."""
    # 1. Validate agent and task boundaries
    await agent_identity_manager.validate_agent_active(db, payload.agent_id, current_app.id)
    await task_manager.validate_task_active(db, payload.task_id, current_app.id, payload.agent_id)

    # 2. Check tool exists
    tool_registry.get_tool(payload.tool_name)

    # 3. Issue capability and obtain one-time secret token
    grant, raw_secret = await capability_manager.issue_capability(
        db=db,
        agent_id=payload.agent_id,
        task_id=payload.task_id,
        app_id=current_app.id,
        tool_name=payload.tool_name,
        resource=payload.resource,
        permissions=payload.permissions,
        ttl_seconds=payload.ttl_seconds,
        max_uses=payload.max_uses,
    )

    return CapabilityResponse(
        id=grant.id,
        agent_id=grant.agent_id,
        task_id=grant.task_id,
        tool_name=grant.tool_name,
        resource=grant.resource,
        permissions=json.loads(grant.permissions),
        max_uses=grant.max_uses,
        uses_count=grant.uses_count,
        is_revoked=grant.is_revoked,
        expires_at=grant.expires_at,
        capability_token=raw_secret,
    )


@router.post("/{capability_id}/revoke", response_model=CapabilityResponse)
async def revoke_capability(
    capability_id: str,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> CapabilityResponse:
    """Immediately revokes an active capability grant."""
    grant = await capability_manager.revoke_capability(db, capability_id, current_app.id)
    return CapabilityResponse(
        id=grant.id,
        agent_id=grant.agent_id,
        task_id=grant.task_id,
        tool_name=grant.tool_name,
        resource=grant.resource,
        permissions=json.loads(grant.permissions),
        max_uses=grant.max_uses,
        uses_count=grant.uses_count,
        is_revoked=grant.is_revoked,
        expires_at=grant.expires_at,
        capability_token=None,
    )

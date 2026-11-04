"""Human-in-the-Loop Approval Endpoints."""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from app.approvals.approval_engine import approval_engine
from app.core.authentication import get_current_app
from app.database.connection import get_db_session
from app.database.models import Application

router = APIRouter(prefix="/v1/approvals", tags=["Agent Security - Approvals"])


class ApprovalActionResponse(BaseModel):
    id: str
    task_id: str
    agent_id: str
    tool_name: str
    target_resource: Optional[str]
    action_parameters: Dict[str, Any]
    action_hash: str
    risk_level: str
    status: str
    created_at: datetime
    expires_at: datetime
    resolved_at: Optional[datetime]
    approver_id: Optional[str]


class ResolveApprovalPayload(BaseModel):
    approver_id: Optional[str] = Field("security_admin", description="Identity of the approver")


@router.get("/pending", response_model=List[ApprovalActionResponse])
async def list_pending_approvals(
    agent_id: Optional[str] = Query(None, description="Optional agent filter"),
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> List[ApprovalActionResponse]:
    """Lists pending human approval requests awaiting operator decision."""
    requests = await approval_engine.list_pending(
        db=db,
        app_id=current_app.id,
        agent_id=agent_id,
    )
    return [
        ApprovalActionResponse(
            id=r.id,
            task_id=r.task_id,
            agent_id=r.agent_id,
            tool_name=r.tool_name,
            target_resource=r.target_resource,
            action_parameters=json.loads(r.action_parameters),
            action_hash=r.action_hash,
            risk_level=r.risk_level,
            status=r.status,
            created_at=r.created_at,
            expires_at=r.expires_at,
            resolved_at=r.resolved_at,
            approver_id=r.approver_id,
        )
        for r in requests
    ]


@router.post("/{approval_id}/approve", response_model=ApprovalActionResponse)
async def approve_request(
    approval_id: str,
    payload: ResolveApprovalPayload = ResolveApprovalPayload(),
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> ApprovalActionResponse:
    """Grants human authorization for the exact proposed action."""
    req = await approval_engine.approve(
        db=db,
        approval_id=approval_id,
        app_id=current_app.id,
        approver_id=payload.approver_id or "security_admin",
    )
    return ApprovalActionResponse(
        id=req.id,
        task_id=req.task_id,
        agent_id=req.agent_id,
        tool_name=req.tool_name,
        target_resource=req.target_resource,
        action_parameters=json.loads(req.action_parameters),
        action_hash=req.action_hash,
        risk_level=req.risk_level,
        status=req.status,
        created_at=req.created_at,
        expires_at=req.expires_at,
        resolved_at=req.resolved_at,
        approver_id=req.approver_id,
    )


@router.post("/{approval_id}/reject", response_model=ApprovalActionResponse)
async def reject_request(
    approval_id: str,
    payload: ResolveApprovalPayload = ResolveApprovalPayload(),
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> ApprovalActionResponse:
    """Rejects the proposed action, permanently preventing its execution."""
    req = await approval_engine.reject(
        db=db,
        approval_id=approval_id,
        app_id=current_app.id,
        approver_id=payload.approver_id or "security_admin",
    )
    return ApprovalActionResponse(
        id=req.id,
        task_id=req.task_id,
        agent_id=req.agent_id,
        tool_name=req.tool_name,
        target_resource=req.target_resource,
        action_parameters=json.loads(req.action_parameters),
        action_hash=req.action_hash,
        risk_level=req.risk_level,
        status=req.status,
        created_at=req.created_at,
        expires_at=req.expires_at,
        resolved_at=req.resolved_at,
        approver_id=req.approver_id,
    )

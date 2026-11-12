"""Human-in-the-loop approval models for PRIVGUARD SDK."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from privguard_sdk.types import ApprovalStatus, RiskLevel


class ApprovalActionResponse(BaseModel):
    """Pending or resolved human approval request."""

    id: str
    task_id: str
    agent_id: str
    tool_name: str
    target_resource: str | None = None
    action_parameters: dict[str, Any] = Field(default_factory=dict)
    action_hash: str = Field(..., description="HMAC-SHA256 hash binding tool, target, and parameters")
    risk_level: RiskLevel
    status: ApprovalStatus
    created_at: datetime
    expires_at: datetime
    resolved_at: datetime | None = None
    approver_id: str | None = None


class ResolveApprovalRequest(BaseModel):
    """Payload to approve or reject a pending action."""

    approver_id: str | None = Field("security_admin", description="Identity of the operator")


class ComputeActionHashRequest(BaseModel):
    """Payload to deterministically compute an action hash."""

    tool_name: str
    target_resource: str | None = None
    action_parameters: dict[str, Any] | None = None


class ComputeActionHashResponse(BaseModel):
    """Resulting action hash."""

    action_hash: str

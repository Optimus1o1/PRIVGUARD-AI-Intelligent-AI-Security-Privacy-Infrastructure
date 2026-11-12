"""Human-in-the-loop approval resource."""

from typing import Any

from privguard_sdk.models.approvals import (
    ApprovalActionResponse,
    ComputeActionHashRequest,
    ComputeActionHashResponse,
    ResolveApprovalRequest,
)
from privguard_sdk.resources.base import AsyncResource, SyncResource


class ApprovalsResource(SyncResource):
    """Synchronous Approval endpoints."""

    def list_pending(self, agent_id: str | None = None) -> list[ApprovalActionResponse]:
        """Lists pending approval requests awaiting operator authorization."""
        params = {}
        if agent_id:
            params["agent_id"] = agent_id
        data = self._transport.request("GET", "/v1/approvals/pending", params=params)
        return [ApprovalActionResponse.model_validate(item) for item in data]

    def get(self, approval_id: str) -> ApprovalActionResponse:
        """Retrieves details of an approval request."""
        data = self._transport.request("GET", f"/v1/approvals/{approval_id}")
        return ApprovalActionResponse.model_validate(data)

    def approve(self, approval_id: str, approver_id: str = "security_admin") -> ApprovalActionResponse:
        """Authorizes a held high-risk action."""
        req = ResolveApprovalRequest(approver_id=approver_id)
        data = self._transport.request("POST", f"/v1/approvals/{approval_id}/approve", json_data=req)
        return ApprovalActionResponse.model_validate(data)

    def reject(self, approval_id: str, approver_id: str = "security_admin") -> ApprovalActionResponse:
        """Rejects a held high-risk action."""
        req = ResolveApprovalRequest(approver_id=approver_id)
        data = self._transport.request("POST", f"/v1/approvals/{approval_id}/reject", json_data=req)
        return ApprovalActionResponse.model_validate(data)

    def compute_action_hash(
        self,
        tool_name: str,
        target_resource: str | None = None,
        action_parameters: dict[str, Any] | None = None,
    ) -> str:
        """Computes HMAC action hash for parameter anti-tampering verification."""
        req = ComputeActionHashRequest(
            tool_name=tool_name,
            target_resource=target_resource,
            action_parameters=action_parameters or {},
        )
        data = self._transport.request("POST", "/v1/approvals/action-hash", json_data=req)
        res = ComputeActionHashResponse.model_validate(data)
        return res.action_hash


class AsyncApprovalsResource(AsyncResource):
    """Asynchronous Approval endpoints."""

    async def list_pending(self, agent_id: str | None = None) -> list[ApprovalActionResponse]:
        """Lists pending approval requests asynchronously."""
        params = {}
        if agent_id:
            params["agent_id"] = agent_id
        data = await self._transport.request("GET", "/v1/approvals/pending", params=params)
        return [ApprovalActionResponse.model_validate(item) for item in data]

    async def get(self, approval_id: str) -> ApprovalActionResponse:
        """Retrieves details of an approval request asynchronously."""
        data = await self._transport.request("GET", f"/v1/approvals/{approval_id}")
        return ApprovalActionResponse.model_validate(data)

    async def approve(self, approval_id: str, approver_id: str = "security_admin") -> ApprovalActionResponse:
        """Authorizes a held high-risk action asynchronously."""
        req = ResolveApprovalRequest(approver_id=approver_id)
        data = await self._transport.request("POST", f"/v1/approvals/{approval_id}/approve", json_data=req)
        return ApprovalActionResponse.model_validate(data)

    async def reject(self, approval_id: str, approver_id: str = "security_admin") -> ApprovalActionResponse:
        """Rejects a held high-risk action asynchronously."""
        req = ResolveApprovalRequest(approver_id=approver_id)
        data = await self._transport.request("POST", f"/v1/approvals/{approval_id}/reject", json_data=req)
        return ApprovalActionResponse.model_validate(data)

    async def compute_action_hash(
        self,
        tool_name: str,
        target_resource: str | None = None,
        action_parameters: dict[str, Any] | None = None,
    ) -> str:
        """Computes HMAC action hash asynchronously."""
        req = ComputeActionHashRequest(
            tool_name=tool_name,
            target_resource=target_resource,
            action_parameters=action_parameters or {},
        )
        data = await self._transport.request("POST", "/v1/approvals/action-hash", json_data=req)
        res = ComputeActionHashResponse.model_validate(data)
        return res.action_hash

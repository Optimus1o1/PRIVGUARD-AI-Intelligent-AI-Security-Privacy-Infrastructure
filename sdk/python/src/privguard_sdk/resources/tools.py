"""Controlled tool execution broker resource."""

from typing import Any

from privguard_sdk.models.tools import ExecuteToolRequest, ExecuteToolResponse, RegisteredTool
from privguard_sdk.resources.base import AsyncResource, SyncResource


class ToolsResource(SyncResource):
    """Synchronous Tool Execution Broker endpoints."""

    def list(self) -> list[RegisteredTool]:
        """Lists registered tools in the PRIVGUARD allowlist."""
        data = self._transport.request("GET", "/v1/tools")
        return [RegisteredTool.model_validate(item) for item in data]

    def execute(
        self,
        tool_name: str,
        agent_id: str,
        task_id: str,
        capability_token: str,
        parameters: dict[str, Any] | None = None,
        approval_id: str | None = None,
    ) -> ExecuteToolResponse:
        """Executes a tool through the Agent Security Broker with capability enforcement."""
        req = ExecuteToolRequest(
            agent_id=agent_id,
            task_id=task_id,
            capability_token=capability_token,
            parameters=parameters or {},
            approval_id=approval_id,
        )
        data = self._transport.request("POST", f"/v1/tools/{tool_name}/execute", json_data=req)
        return ExecuteToolResponse.model_validate(data)


class AsyncToolsResource(AsyncResource):
    """Asynchronous Tool Execution Broker endpoints."""

    async def list(self) -> list[RegisteredTool]:
        """Lists registered tools in the PRIVGUARD allowlist asynchronously."""
        data = await self._transport.request("GET", "/v1/tools")
        return [RegisteredTool.model_validate(item) for item in data]

    async def execute(
        self,
        tool_name: str,
        agent_id: str,
        task_id: str,
        capability_token: str,
        parameters: dict[str, Any] | None = None,
        approval_id: str | None = None,
    ) -> ExecuteToolResponse:
        """Executes a tool asynchronously through the Agent Security Broker."""
        req = ExecuteToolRequest(
            agent_id=agent_id,
            task_id=task_id,
            capability_token=capability_token,
            parameters=parameters or {},
            approval_id=approval_id,
        )
        data = await self._transport.request("POST", f"/v1/tools/{tool_name}/execute", json_data=req)
        return ExecuteToolResponse.model_validate(data)

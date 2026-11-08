"""Agent identity and governance resource."""

from privguard_sdk.models.agents import AgentRegisterRequest, AgentResponse, AgentStatusUpdateRequest
from privguard_sdk.resources.base import AsyncResource, SyncResource
from privguard_sdk.types import AgentStatus


class AgentsResource(SyncResource):
    """Synchronous Agent Security Broker endpoints."""

    def register(
        self,
        name: str,
        description: str | None = None,
        allowed_tools: list[str] | None = None,
    ) -> AgentResponse:
        """Registers an AI agent bound to the authenticated application."""
        req = AgentRegisterRequest(name=name, description=description, allowed_tools=allowed_tools)
        data = self._transport.request("POST", "/v1/agents/register", json_data=req)
        return AgentResponse.model_validate(data)

    def list(self) -> list[AgentResponse]:
        """Lists registered agents belonging to the caller application."""
        data = self._transport.request("GET", "/v1/agents")
        return [AgentResponse.model_validate(item) for item in data]

    def get(self, agent_id: str) -> AgentResponse:
        """Retrieves details of a registered agent."""
        data = self._transport.request("GET", f"/v1/agents/{agent_id}")
        return AgentResponse.model_validate(data)

    def update_status(self, agent_id: str, status: AgentStatus | str) -> AgentResponse:
        """Updates an agent's operational status ('ACTIVE', 'PAUSED', 'REVOKED')."""
        status_enum = AgentStatus(status) if isinstance(status, str) else status
        req = AgentStatusUpdateRequest(status=status_enum)
        data = self._transport.request("PATCH", f"/v1/agents/{agent_id}/status", json_data=req)
        return AgentResponse.model_validate(data)


class AsyncAgentsResource(AsyncResource):
    """Asynchronous Agent Security Broker endpoints."""

    async def register(
        self,
        name: str,
        description: str | None = None,
        allowed_tools: list[str] | None = None,
    ) -> AgentResponse:
        """Registers an AI agent asynchronously."""
        req = AgentRegisterRequest(name=name, description=description, allowed_tools=allowed_tools)
        data = await self._transport.request("POST", "/v1/agents/register", json_data=req)
        return AgentResponse.model_validate(data)

    async def list(self) -> list[AgentResponse]:
        """Lists registered agents asynchronously."""
        data = await self._transport.request("GET", "/v1/agents")
        return [AgentResponse.model_validate(item) for item in data]

    async def get(self, agent_id: str) -> AgentResponse:
        """Retrieves details of a registered agent asynchronously."""
        data = await self._transport.request("GET", f"/v1/agents/{agent_id}")
        return AgentResponse.model_validate(data)

    async def update_status(self, agent_id: str, status: AgentStatus | str) -> AgentResponse:
        """Updates an agent's operational status asynchronously."""
        status_enum = AgentStatus(status) if isinstance(status, str) else status
        req = AgentStatusUpdateRequest(status=status_enum)
        data = await self._transport.request("PATCH", f"/v1/agents/{agent_id}/status", json_data=req)
        return AgentResponse.model_validate(data)

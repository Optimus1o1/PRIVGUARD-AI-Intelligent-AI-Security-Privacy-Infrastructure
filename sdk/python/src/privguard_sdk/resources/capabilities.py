"""Capability token management resource."""

from privguard_sdk.models.capabilities import (
    CapabilityResponse,
    RequestCapabilityRequest,
    ValidateCapabilityRequest,
    ValidateCapabilityResponse,
)
from privguard_sdk.resources.base import AsyncResource, SyncResource


class CapabilitiesResource(SyncResource):
    """Synchronous Capability Token endpoints."""

    def request(
        self,
        agent_id: str,
        task_id: str,
        tool_name: str,
        resource: str | None = None,
        permissions: list[str] | None = None,
        ttl_seconds: int = 300,
        max_uses: int = 1,
    ) -> CapabilityResponse:
        """Requests a time-limited, task-scoped, revocable capability token."""
        req = RequestCapabilityRequest(
            agent_id=agent_id,
            task_id=task_id,
            tool_name=tool_name,
            resource=resource,
            permissions=permissions,
            ttl_seconds=ttl_seconds,
            max_uses=max_uses,
        )
        data = self._transport.request("POST", "/v1/capabilities/request", json_data=req)
        return CapabilityResponse.model_validate(data)

    def validate(
        self,
        capability_token: str,
        tool_name: str,
        resource: str | None = None,
        required_permission: str = "execute",
    ) -> ValidateCapabilityResponse:
        """Validates capability token integrity, expiry, and remaining use counts."""
        req = ValidateCapabilityRequest(
            capability_token=capability_token,
            tool_name=tool_name,
            resource=resource,
            required_permission=required_permission,
        )
        data = self._transport.request("POST", "/v1/capabilities/validate", json_data=req)
        return ValidateCapabilityResponse.model_validate(data)

    def revoke(self, token: str) -> CapabilityResponse:
        """Immediately revokes a capability token across all cluster replicas."""
        data = self._transport.request("POST", f"/v1/capabilities/{token}/revoke")
        return CapabilityResponse.model_validate(data)


class AsyncCapabilitiesResource(AsyncResource):
    """Asynchronous Capability Token endpoints."""

    async def request(
        self,
        agent_id: str,
        task_id: str,
        tool_name: str,
        resource: str | None = None,
        permissions: list[str] | None = None,
        ttl_seconds: int = 300,
        max_uses: int = 1,
    ) -> CapabilityResponse:
        """Requests a capability token asynchronously."""
        req = RequestCapabilityRequest(
            agent_id=agent_id,
            task_id=task_id,
            tool_name=tool_name,
            resource=resource,
            permissions=permissions,
            ttl_seconds=ttl_seconds,
            max_uses=max_uses,
        )
        data = await self._transport.request("POST", "/v1/capabilities/request", json_data=req)
        return CapabilityResponse.model_validate(data)

    async def validate(
        self,
        capability_token: str,
        tool_name: str,
        resource: str | None = None,
        required_permission: str = "execute",
    ) -> ValidateCapabilityResponse:
        """Validates capability token asynchronously."""
        req = ValidateCapabilityRequest(
            capability_token=capability_token,
            tool_name=tool_name,
            resource=resource,
            required_permission=required_permission,
        )
        data = await self._transport.request("POST", "/v1/capabilities/validate", json_data=req)
        return ValidateCapabilityResponse.model_validate(data)

    async def revoke(self, token: str) -> CapabilityResponse:
        """Revokes a capability token asynchronously."""
        data = await self._transport.request("POST", f"/v1/capabilities/{token}/revoke")
        return CapabilityResponse.model_validate(data)

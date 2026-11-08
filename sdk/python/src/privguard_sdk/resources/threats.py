"""Threat detection resource."""

from privguard_sdk.models.threats import InspectContentRequest, InspectContentResponse, ThreatEventResponse
from privguard_sdk.resources.base import AsyncResource, SyncResource
from privguard_sdk.types import SourceType


class ThreatsResource(SyncResource):
    """Synchronous Threat Detection endpoints."""

    def inspect(
        self,
        text: str,
        source_type: SourceType = SourceType.USER_INPUT,
    ) -> InspectContentResponse:
        """Inspects content for prompt injections, jailbreaks, and untrusted directives."""
        req = InspectContentRequest(text=text, source_type=source_type)
        data = self._transport.request("POST", "/v1/threats/inspect", json_data=req)
        return InspectContentResponse.model_validate(data)

    def list_events(
        self,
        limit: int = 50,
        threat_type: str | None = None,
    ) -> list[ThreatEventResponse]:
        """Lists logged threat detection events."""
        params = {"limit": limit}
        if threat_type:
            params["threat_type"] = threat_type
        data = self._transport.request("GET", "/v1/threats/events", params=params)
        return [ThreatEventResponse.model_validate(item) for item in data]


class AsyncThreatsResource(AsyncResource):
    """Asynchronous Threat Detection endpoints."""

    async def inspect(
        self,
        text: str,
        source_type: SourceType = SourceType.USER_INPUT,
    ) -> InspectContentResponse:
        """Inspects content asynchronously for prompt injections, jailbreaks, and untrusted directives."""
        req = InspectContentRequest(text=text, source_type=source_type)
        data = await self._transport.request("POST", "/v1/threats/inspect", json_data=req)
        return InspectContentResponse.model_validate(data)

    async def list_events(
        self,
        limit: int = 50,
        threat_type: str | None = None,
    ) -> list[ThreatEventResponse]:
        """Lists logged threat detection events asynchronously."""
        params = {"limit": limit}
        if threat_type:
            params["threat_type"] = threat_type
        data = await self._transport.request("GET", "/v1/threats/events", params=params)
        return [ThreatEventResponse.model_validate(item) for item in data]

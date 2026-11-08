"""Security audit and monitoring resource."""

from privguard_sdk.models.audit import AuditEventResponse
from privguard_sdk.resources.base import AsyncResource, SyncResource


class AuditResource(SyncResource):
    """Synchronous Audit Log query endpoints."""

    def list_events(
        self,
        event_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AuditEventResponse]:
        """Queries tamper-evident, strictly content-free security audit logs."""
        params = {"limit": limit, "offset": offset}
        if event_type:
            params["event_type"] = event_type
        data = self._transport.request("GET", "/v1/audit/events", params=params)
        return [AuditEventResponse.model_validate(item) for item in data]


class AsyncAuditResource(AsyncResource):
    """Asynchronous Audit Log query endpoints."""

    async def list_events(
        self,
        event_type: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[AuditEventResponse]:
        """Queries security audit logs asynchronously."""
        params = {"limit": limit, "offset": offset}
        if event_type:
            params["event_type"] = event_type
        data = await self._transport.request("GET", "/v1/audit/events", params=params)
        return [AuditEventResponse.model_validate(item) for item in data]

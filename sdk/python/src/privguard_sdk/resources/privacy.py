"""Privacy and redaction resource."""

from privguard_sdk.models.privacy import InspectRequest, InspectResponse, RedactRequest, RedactResponse
from privguard_sdk.resources.base import AsyncResource, SyncResource


class PrivacyResource(SyncResource):
    """Synchronous Privacy Engine endpoints."""

    def inspect(self, text: str, request_id: str | None = None) -> InspectResponse:
        """Inspects text for sensitive information (secrets and PII)."""
        req = InspectRequest(text=text, request_id=request_id)
        data = self._transport.request("POST", "/v1/privacy/inspect", json_data=req)
        return InspectResponse.model_validate(data)

    def redact(self, text: str, reversible: bool = True) -> RedactResponse:
        """Sanitizes text via format-preserving PII token substitution."""
        req = RedactRequest(text=text, reversible=reversible)
        data = self._transport.request("POST", "/v1/privacy/redact", json_data=req)
        return RedactResponse.model_validate(data)


class AsyncPrivacyResource(AsyncResource):
    """Asynchronous Privacy Engine endpoints."""

    async def inspect(self, text: str, request_id: str | None = None) -> InspectResponse:
        """Inspects text asynchronously for sensitive information (secrets and PII)."""
        req = InspectRequest(text=text, request_id=request_id)
        data = await self._transport.request("POST", "/v1/privacy/inspect", json_data=req)
        return InspectResponse.model_validate(data)

    async def redact(self, text: str, reversible: bool = True) -> RedactResponse:
        """Sanitizes text asynchronously via format-preserving PII token substitution."""
        req = RedactRequest(text=text, reversible=reversible)
        data = await self._transport.request("POST", "/v1/privacy/redact", json_data=req)
        return RedactResponse.model_validate(data)

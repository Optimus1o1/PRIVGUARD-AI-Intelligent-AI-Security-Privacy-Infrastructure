"""Health and liveness probes resource."""

from privguard_sdk.models.health import LivenessResponse, ReadinessResponse
from privguard_sdk.resources.base import AsyncResource, SyncResource


class HealthResource(SyncResource):
    """Synchronous health check endpoints."""

    def check(self) -> LivenessResponse:
        """Verifies process liveness via /health."""
        data = self._transport.request("GET", "/health")
        return LivenessResponse.model_validate(data)

    def ready(self) -> ReadinessResponse:
        """Verifies infrastructure and dependency readiness via /ready."""
        data = self._transport.request("GET", "/ready")
        return ReadinessResponse.model_validate(data)


class AsyncHealthResource(AsyncResource):
    """Asynchronous health check endpoints."""

    async def check(self) -> LivenessResponse:
        """Verifies process liveness via /health."""
        data = await self._transport.request("GET", "/health")
        return LivenessResponse.model_validate(data)

    async def ready(self) -> ReadinessResponse:
        """Verifies infrastructure and dependency readiness via /ready."""
        data = await self._transport.request("GET", "/ready")
        return ReadinessResponse.model_validate(data)


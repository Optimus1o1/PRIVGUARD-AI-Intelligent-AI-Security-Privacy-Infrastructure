"""Asynchronous AsyncPrivGuardClient interface.

Moon Sanctum Labs - Decode. Build. Evolve.
"""

from typing import Any

import httpx

from privguard_sdk.config import PrivGuardConfig
from privguard_sdk.resources.agents import AsyncAgentsResource
from privguard_sdk.resources.approvals import AsyncApprovalsResource
from privguard_sdk.resources.audit import AsyncAuditResource
from privguard_sdk.resources.capabilities import AsyncCapabilitiesResource
from privguard_sdk.resources.compliance import AsyncComplianceResource
from privguard_sdk.resources.gateway import AsyncGatewayResource
from privguard_sdk.resources.health import AsyncHealthResource
from privguard_sdk.resources.memory import AsyncMemoryResource
from privguard_sdk.resources.privacy import AsyncPrivacyResource
from privguard_sdk.resources.tasks import AsyncTasksResource
from privguard_sdk.resources.threats import AsyncThreatsResource
from privguard_sdk.resources.tools import AsyncToolsResource
from privguard_sdk.transport.async_transport import AsyncTransport


class AsyncPrivGuardClient:
    """Official asynchronous client for PRIVGUARD AI.

    Usage:
        import asyncio
        from privguard_sdk import AsyncPrivGuardClient

        async def main():
            async with AsyncPrivGuardClient(
                base_url="https://privguard.internal",
                api_key="your_api_key",
                tenant_id="tenant_alpha"
            ) as client:
                health = await client.health.check()
                print(health.status)

        asyncio.run(main())
    """

    def __init__(
        self,
        base_url: str | None = None,
        api_key: str | None = None,
        tenant_id: str | None = None,
        user_id: str | None = None,
        workspace_id: str | None = None,
        timeout: float | httpx.Timeout = 30.0,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        verify_ssl: bool | str = True,
        default_headers: dict[str, str] | None = None,
        config: PrivGuardConfig | None = None,
    ) -> None:
        if config is not None:
            self.config = config
        else:
            kwargs: dict[str, Any] = {
                "timeout": timeout,
                "max_retries": max_retries,
                "backoff_factor": backoff_factor,
                "verify_ssl": verify_ssl,
                "default_headers": default_headers or {},
            }
            if base_url is not None:
                kwargs["base_url"] = base_url
            if api_key is not None:
                kwargs["api_key"] = api_key
            if tenant_id is not None:
                kwargs["tenant_id"] = tenant_id
            if user_id is not None:
                kwargs["user_id"] = user_id
            if workspace_id is not None:
                kwargs["workspace_id"] = workspace_id

            self.config = PrivGuardConfig(**kwargs)

        self._transport = AsyncTransport(self.config)

        # Initialize resource namespaces
        self.health = AsyncHealthResource(self._transport)
        self.gateway = AsyncGatewayResource(self._transport)
        self.privacy = AsyncPrivacyResource(self._transport)
        self.threats = AsyncThreatsResource(self._transport)
        self.agents = AsyncAgentsResource(self._transport)
        self.tasks = AsyncTasksResource(self._transport)
        self.capabilities = AsyncCapabilitiesResource(self._transport)
        self.approvals = AsyncApprovalsResource(self._transport)
        self.tools = AsyncToolsResource(self._transport)
        self.memory = AsyncMemoryResource(self._transport)
        self.audit = AsyncAuditResource(self._transport)
        self.compliance = AsyncComplianceResource(self._transport)

    async def aclose(self) -> None:
        """Asynchronously closes all active network connections."""
        await self._transport.aclose()

    def close(self) -> None:
        """Synchronous wrapper for closing connections."""
        self._transport.close()

    async def __aenter__(self) -> "AsyncPrivGuardClient":
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.aclose()

    def __repr__(self) -> str:
        return f"AsyncPrivGuardClient(config={self.config!r})"

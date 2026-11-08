"""Synchronous PrivGuardClient interface.

Moon Sanctum Labs - Decode. Build. Evolve.
"""

from typing import Any

import httpx

from privguard_sdk.config import PrivGuardConfig
from privguard_sdk.resources.agents import AgentsResource
from privguard_sdk.resources.approvals import ApprovalsResource
from privguard_sdk.resources.audit import AuditResource
from privguard_sdk.resources.capabilities import CapabilitiesResource
from privguard_sdk.resources.compliance import ComplianceResource
from privguard_sdk.resources.gateway import GatewayResource
from privguard_sdk.resources.health import HealthResource
from privguard_sdk.resources.memory import MemoryResource
from privguard_sdk.resources.privacy import PrivacyResource
from privguard_sdk.resources.tasks import TasksResource
from privguard_sdk.resources.threats import ThreatsResource
from privguard_sdk.resources.tools import ToolsResource
from privguard_sdk.transport.sync import SyncTransport


class PrivGuardClient:
    """Official synchronous client for PRIVGUARD AI.

    Usage:
        from privguard_sdk import PrivGuardClient

        client = PrivGuardClient(
            base_url="https://privguard.internal",
            api_key="your_api_key",
            tenant_id="tenant_alpha"
        )
        health = client.health.check()
        print(health.status)
        client.close()

    Or via context manager:
        with PrivGuardClient(api_key="...") as client:
            res = client.privacy.inspect("text")
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

        self._transport = SyncTransport(self.config)

        # Initialize resource namespaces
        self.health = HealthResource(self._transport)
        self.gateway = GatewayResource(self._transport)
        self.privacy = PrivacyResource(self._transport)
        self.threats = ThreatsResource(self._transport)
        self.agents = AgentsResource(self._transport)
        self.tasks = TasksResource(self._transport)
        self.capabilities = CapabilitiesResource(self._transport)
        self.approvals = ApprovalsResource(self._transport)
        self.tools = ToolsResource(self._transport)
        self.memory = MemoryResource(self._transport)
        self.audit = AuditResource(self._transport)
        self.compliance = ComplianceResource(self._transport)

    def close(self) -> None:
        """Closes all active network connections."""
        self._transport.close()

    def __enter__(self) -> "PrivGuardClient":
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        self.close()

    def __repr__(self) -> str:
        return f"PrivGuardClient(config={self.config!r})"

"""Client configuration for PRIVGUARD Python SDK.

Moon Sanctum Labs - Decode. Build. Evolve.
"""

import os
from dataclasses import dataclass, field

import httpx


@dataclass
class PrivGuardConfig:
    """Configuration options for PrivGuardClient and AsyncPrivGuardClient."""

    base_url: str = field(default_factory=lambda: os.getenv("PRIVGUARD_BASE_URL", "http://localhost:8000").rstrip("/"))
    api_key: str | None = field(default_factory=lambda: os.getenv("PRIVGUARD_API_KEY"))
    tenant_id: str | None = field(default_factory=lambda: os.getenv("PRIVGUARD_TENANT_ID"))
    user_id: str | None = field(default_factory=lambda: os.getenv("PRIVGUARD_USER_ID"))
    workspace_id: str | None = field(default_factory=lambda: os.getenv("PRIVGUARD_WORKSPACE_ID"))
    timeout: float | httpx.Timeout = field(
        default_factory=lambda: httpx.Timeout(timeout=30.0, connect=5.0, read=30.0, write=10.0)
    )
    max_retries: int = 3
    backoff_factor: float = 0.5
    verify_ssl: bool | str = True
    default_headers: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        self.base_url = self.base_url.rstrip("/")
        if isinstance(self.timeout, (int, float)):
            self.timeout = httpx.Timeout(float(self.timeout))

    def build_headers(self, override_headers: dict[str, str] | None = None) -> dict[str, str]:
        """Constructs standardized HTTP headers with authentication and context tokens."""
        headers: dict[str, str] = {
            "User-Agent": "privguard-python-sdk/0.1.0",
            "Accept": "application/json",
        }
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        if self.tenant_id:
            headers["X-Tenant-ID"] = self.tenant_id
        if self.user_id:
            headers["X-User-ID"] = self.user_id
        if self.workspace_id:
            headers["X-Workspace-ID"] = self.workspace_id

        headers.update(self.default_headers)
        if override_headers:
            headers.update(override_headers)
        return headers

    def __repr__(self) -> str:
        """Masks API keys and secrets to prevent accidental credential leakage in logs."""
        masked_key = "[NONE]"
        if self.api_key:
            if len(self.api_key) > 8:
                masked_key = f"{self.api_key[:4]}...{self.api_key[-4:]}"
            else:
                masked_key = "***"

        return (
            f"PrivGuardConfig("
            f"base_url={self.base_url!r}, "
            f"api_key={masked_key!r}, "
            f"tenant_id={self.tenant_id!r}, "
            f"user_id={self.user_id!r}, "
            f"workspace_id={self.workspace_id!r}, "
            f"max_retries={self.max_retries}, "
            f"verify_ssl={self.verify_ssl!r})"
        )

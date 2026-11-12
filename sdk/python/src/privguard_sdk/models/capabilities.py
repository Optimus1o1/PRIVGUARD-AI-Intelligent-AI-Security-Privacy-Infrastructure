"""Capability token management models for PRIVGUARD SDK."""

from datetime import datetime

from pydantic import BaseModel, Field


class RequestCapabilityRequest(BaseModel):
    """Payload to request a task-scoped capability token."""

    agent_id: str = Field(..., description="Target agent ID")
    task_id: str = Field(..., description="Active task session ID")
    tool_name: str = Field(..., description="Name of permitted tool")
    resource: str | None = Field(None, description="Permitted target resource/scope")
    permissions: list[str] | None = Field(default_factory=lambda: ["execute"])
    ttl_seconds: int = Field(300, ge=10, le=3600, description="Validity window in seconds")
    max_uses: int = Field(1, ge=1, le=100, description="Maximum permitted executions")


class CapabilityResponse(BaseModel):
    """Capability token grant."""

    id: str
    agent_id: str
    task_id: str
    tool_name: str
    resource: str | None = None
    permissions: list[str] = Field(default_factory=list)
    max_uses: int
    uses_count: int
    is_revoked: bool
    expires_at: datetime
    capability_token: str | None = Field(None, description="One-time secret token (returned only on issuance)")


class ValidateCapabilityRequest(BaseModel):
    """Payload to validate a capability token before invocation."""

    capability_token: str = Field(..., description="Opaque capability token")
    tool_name: str
    resource: str | None = None
    required_permission: str = "execute"


class ValidateCapabilityResponse(BaseModel):
    """Result of capability token validation."""

    is_valid: bool
    grant: CapabilityResponse | None = None
    reason: str | None = None

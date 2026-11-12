"""Agent identity and governance models for PRIVGUARD SDK."""

from datetime import datetime

from pydantic import BaseModel, Field

from privguard_sdk.types import AgentStatus


class AgentRegisterRequest(BaseModel):
    """Payload to register an AI agent."""

    name: str = Field(..., min_length=1, max_length=100, description="Human-readable agent name")
    description: str | None = Field(None, max_length=255, description="Agent purpose description")
    allowed_tools: list[str] | None = Field(
        default_factory=lambda: ["read_file", "search_web"],
        description="List of tool names the agent is permitted to invoke",
    )


class AgentResponse(BaseModel):
    """Registered AI agent metadata."""

    id: str = Field(..., description="Unique agent identifier")
    name: str
    description: str | None = None
    status: AgentStatus = Field(default=AgentStatus.ACTIVE)
    allowed_tools: list[str] = Field(default_factory=list)
    created_at: datetime
    last_activity_at: datetime


class AgentStatusUpdateRequest(BaseModel):
    """Payload to change an agent's operational status."""

    status: AgentStatus = Field(..., description="Target status ('ACTIVE', 'PAUSED', 'REVOKED')")

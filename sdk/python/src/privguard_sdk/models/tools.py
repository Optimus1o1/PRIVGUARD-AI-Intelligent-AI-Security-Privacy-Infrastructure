"""Controlled tool execution broker models for PRIVGUARD SDK."""

from typing import Any

from pydantic import BaseModel, Field


class RegisteredTool(BaseModel):
    """Tool definition registered in the PRIVGUARD allowlist."""

    name: str = Field(..., description="Unique tool identifier")
    description: str = Field(..., description="Tool capability summary")
    parameter_schema: dict[str, Any] = Field(default_factory=dict, description="JSON schema defining parameters")
    is_active: bool = True


class ExecuteToolRequest(BaseModel):
    """Payload to invoke a tool through the Agent Security Broker."""

    agent_id: str = Field(..., description="Executing agent ID")
    task_id: str = Field(..., description="Active task session ID")
    capability_token: str = Field(..., description="Valid capability token for this tool")
    parameters: dict[str, Any] = Field(default_factory=dict, description="Execution parameters matching tool schema")
    approval_id: str | None = Field(None, description="Approval ID if operation required human authorization")


class ExecuteToolResponse(BaseModel):
    """Result of brokered tool execution."""

    execution_id: str
    status: str
    tool: str
    output: str
    duration_ms: float

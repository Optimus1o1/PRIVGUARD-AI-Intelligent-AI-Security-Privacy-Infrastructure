"""OpenAI-compatible Model Gateway models for PRIVGUARD SDK."""

from typing import Any

from pydantic import BaseModel, Field


class ChatMessage(BaseModel):
    """Represents a single chat message."""

    role: str = Field(..., description="Message author role ('user', 'assistant', 'system', 'tool')")
    content: str = Field(..., description="Message text payload")
    name: str | None = Field(None, description="Optional name identifier")


class ChatCompletionRequest(BaseModel):
    """Request payload sent to /v1/chat/completions."""

    model: str = Field(..., description="Upstream model identifier (e.g. 'gpt-4o', 'claude-3-5-sonnet')")
    messages: list[ChatMessage] = Field(..., description="List of conversation turns")
    temperature: float | None = Field(0.7, ge=0.0, le=2.0)
    max_tokens: int | None = Field(None, ge=1)
    stream: bool | None = Field(False, description="Whether to stream partial message deltas")
    tools: list[dict[str, Any]] | None = Field(None, description="Available tool definitions")
    tool_choice: Any | None = Field(None, description="Tool selection policy")


class ChatChoice(BaseModel):
    """Single completion candidate."""

    index: int
    message: dict[str, Any]
    finish_reason: str | None = "stop"


class ChatCompletionResponse(BaseModel):
    """Response returned by /v1/chat/completions in non-streaming mode."""

    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: list[ChatChoice]
    usage: dict[str, int] = Field(default_factory=dict)
    privguard_meta: dict[str, Any] = Field(default_factory=dict, description="PRIVGUARD inspection telemetry")


class ChatCompletionChunk(BaseModel):
    """Streaming chunk emitted during Server-Sent Events (SSE)."""

    id: str
    object: str = "chat.completion.chunk"
    created: int
    model: str
    choices: list[dict[str, Any]]
    usage: dict[str, int] | None = None
    privguard_meta: dict[str, Any] | None = None

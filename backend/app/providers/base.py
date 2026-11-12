"""Abstract base class for upstream model providers."""

from abc import ABC, abstractmethod
from typing import Any, AsyncIterator, Dict, Optional
from pydantic import BaseModel, Field


class ProviderResponse(BaseModel):
    """Standardized response from an upstream model provider."""

    id: str
    model: str
    content: str
    finish_reason: Optional[str] = "stop"
    usage: Dict[str, Any] = Field(
        default_factory=lambda: {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0}
    )
    raw_response: Optional[Dict[str, Any]] = None


class BaseProvider(ABC):
    """Abstract interface for all model provider integrations."""

    @abstractmethod
    async def complete(self, request_payload: Dict[str, Any]) -> ProviderResponse:
        """Sends a non-streaming chat completion request to the upstream model."""
        pass

    @abstractmethod
    async def stream(self, request_payload: Dict[str, Any]) -> AsyncIterator[str]:
        """Sends a streaming chat completion request and yields raw SSE event chunks."""
        pass

"""Server-side provider registry preventing SSRF vulnerabilities."""

from typing import Any, Dict, Optional
from app.core.config import settings
from app.core.exceptions import ModelNotConfiguredError
from app.providers.base import BaseProvider, ProviderResponse
from app.providers.openai_compatible import OpenAICompatibleProvider


class LocalMockProvider(BaseProvider):
    """Local fallback provider for test and development environments."""

    async def complete(self, request_payload: Dict[str, Any]) -> ProviderResponse:
        messages = request_payload.get("messages", [])
        last_content = messages[-1].get("content", "") if messages else ""
        content = f"[PRIVGUARD PROTECTED COMPLETED] Successfully processed sanitized prompt: '{last_content}'"
        return ProviderResponse(
            id="mock_comp_001",
            model=request_payload.get("model", "mock-model"),
            content=content,
            finish_reason="stop",
            usage={
                "prompt_tokens": len(last_content.split()),
                "completion_tokens": len(content.split()),
                "total_tokens": len(last_content.split()) + len(content.split()),
            },
        )

    async def stream(self, request_payload: Dict[str, Any]):
        import json
        messages = request_payload.get("messages", [])
        last_content = messages[-1].get("content", "") if messages else ""
        chunks = [
            "[PRIVGUARD PROTECTED COMPLETED] ",
            "Successfully processed ",
            f"sanitized prompt: '{last_content}'",
        ]
        for c in chunks:
            data = {
                "id": "mock_stream_001",
                "object": "chat.completion.chunk",
                "choices": [{"index": 0, "delta": {"content": c}, "finish_reason": None}],
            }
            yield f"data: {json.dumps(data)}"
        done_data = {
            "id": "mock_stream_001",
            "object": "chat.completion.chunk",
            "choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
        }
        yield f"data: {json.dumps(done_data)}"
        yield "data: [DONE]"


class ProviderRegistry:
    """Manages allowed server-side providers and prevents arbitrary SSRF targets."""

    def __init__(self):
        self._providers: Dict[str, BaseProvider] = {}
        self._default_provider: Optional[BaseProvider] = None
        self._initialize_defaults()

    def _initialize_defaults(self):
        """Initializes default upstream provider based on environment settings."""
        if settings.UPSTREAM_LLM_API_KEY:
            self._default_provider = OpenAICompatibleProvider(
                base_url=settings.UPSTREAM_LLM_BASE_URL,
                api_key=settings.UPSTREAM_LLM_API_KEY,
                timeout_seconds=settings.UPSTREAM_TIMEOUT_SECONDS,
            )
        else:
            self._default_provider = LocalMockProvider()

    def register(self, model_pattern: str, provider: BaseProvider) -> None:
        """Registers a provider for a specific model name or pattern."""
        self._providers[model_pattern] = provider

    def set_default(self, provider: BaseProvider) -> None:
        """Sets the global default upstream provider."""
        self._default_provider = provider

    def get_provider(self, model: str) -> BaseProvider:
        """
        Resolves the appropriate server-side provider for the given model.
        Strictly prevents client-supplied arbitrary URLs.
        """
        if model in self._providers:
            return self._providers[model]

        # Check prefix match (e.g. "gpt-" -> openai)
        for pattern, provider in self._providers.items():
            if pattern.endswith("*") and model.startswith(pattern[:-1]):
                return provider

        if self._default_provider:
            return self._default_provider

        raise ModelNotConfiguredError(model)


# Shared global provider registry instance
provider_registry = ProviderRegistry()

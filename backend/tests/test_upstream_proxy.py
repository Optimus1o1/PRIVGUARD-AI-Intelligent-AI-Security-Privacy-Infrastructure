"""Tests for upstream provider proxying and error translation."""

import json
import pytest
import httpx
from httpx import AsyncClient
from app.core.exceptions import (
    UpstreamAuthenticationError,
    UpstreamProviderError,
    UpstreamRateLimitError,
    UpstreamTimeoutError,
)
from app.database.models import Application
from app.providers.openai_compatible import OpenAICompatibleProvider
from app.providers.registry import provider_registry


@pytest.mark.asyncio
async def test_upstream_successful_completion():
    """Valid upstream HTTP 200 response is properly parsed into ProviderResponse."""
    def mock_handler(request: httpx.Request):
        assert request.headers["authorization"] == "Bearer mock-api-key"
        body = json.loads(request.content)
        assert body["model"] == "mock-gpt-4o"
        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-mock-123",
                "object": "chat.completion",
                "model": "mock-gpt-4o",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": "Hello from upstream model!"},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
            },
        )

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = OpenAICompatibleProvider(
            base_url="https://mock-upstream.internal/v1",
            api_key="mock-api-key",
            client=client,
        )
        res = await provider.complete({"model": "mock-gpt-4o", "messages": [{"role": "user", "content": "hi"}]})
        assert res.content == "Hello from upstream model!"
        assert res.model == "mock-gpt-4o"
        assert res.id == "chatcmpl-mock-123"


@pytest.mark.asyncio
async def test_upstream_401_authentication_error():
    """Upstream 401 maps to UpstreamAuthenticationError."""
    def mock_handler(request: httpx.Request):
        return httpx.Response(401, json={"error": "Invalid API key"})

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = OpenAICompatibleProvider(
            base_url="https://mock-upstream.internal/v1",
            api_key="bad-key",
            client=client,
        )
        with pytest.raises(UpstreamAuthenticationError):
            await provider.complete({"model": "gpt-4o", "messages": []})


@pytest.mark.asyncio
async def test_upstream_429_rate_limit_error():
    """Upstream 429 maps to UpstreamRateLimitError."""
    def mock_handler(request: httpx.Request):
        return httpx.Response(429, headers={"retry-after": "30"}, json={"error": "Rate limit reached"})

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = OpenAICompatibleProvider(
            base_url="https://mock-upstream.internal/v1",
            client=client,
        )
        with pytest.raises(UpstreamRateLimitError) as exc_info:
            await provider.complete({"model": "gpt-4o", "messages": []})
        assert exc_info.value.status_code == 429
        assert exc_info.value.details.get("retry_after") == "30"


@pytest.mark.asyncio
async def test_upstream_500_provider_error():
    """Upstream 500 error maps to UpstreamProviderError (HTTP 502)."""
    def mock_handler(request: httpx.Request):
        return httpx.Response(500, json={"error": "Internal server error at provider"})

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as client:
        provider = OpenAICompatibleProvider(
            base_url="https://mock-upstream.internal/v1",
            client=client,
        )
        with pytest.raises(UpstreamProviderError) as exc_info:
            await provider.complete({"model": "gpt-4o", "messages": []})
        assert exc_info.value.status_code == 502


@pytest.mark.asyncio
async def test_gateway_with_mock_provider_and_response_restoration(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """End-to-end gateway call forwards sanitized request and restores response PII."""
    def mock_upstream(request: httpx.Request):
        body = json.loads(request.content)
        user_prompt = body["messages"][0]["content"]
        # Upstream model only sees <EMAIL_1>
        assert "<EMAIL_1>" in user_prompt
        assert "aniket@example.com" not in user_prompt

        return httpx.Response(
            200,
            json={
                "id": "chatcmpl-test-456",
                "object": "chat.completion",
                "model": "test-mock-model",
                "choices": [
                    {
                        "index": 0,
                        "message": {
                            "role": "assistant",
                            "content": "Acknowledged. Dispatching report to <EMAIL_1> now.",
                        },
                        "finish_reason": "stop",
                    }
                ],
                "usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20},
            },
        )

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(mock_upstream))
    test_provider = OpenAICompatibleProvider(
        base_url="https://mock-upstream.internal/v1",
        api_key="test-secret-upstream-key",
        client=mock_client,
    )

    provider_registry.register("test-mock-model", test_provider)

    payload = {
        "model": "test-mock-model",
        "messages": [
            {"role": "user", "content": "Please send monthly billing to aniket@example.com."}
        ],
        "stream": False,
    }

    res = await client.post("/v1/chat/completions", json=payload, headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    # Response delivered to client has <EMAIL_1> restored!
    assert "aniket@example.com" in data["choices"][0]["message"]["content"]
    assert data["privguard_meta"]["tokens_restored"] == 1
    assert data["privguard_meta"]["security_action"] == "REDACT"


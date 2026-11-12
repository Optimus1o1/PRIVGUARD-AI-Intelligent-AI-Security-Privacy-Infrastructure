"""
Assessment B: AI Gateway, Provider Isolation, SSRF, and Streaming Security Red-Teaming Tests.
Validates SSRF prevention, upstream provider key isolation, and Buffer-Before-Stream SSE integrity.
"""

import json
import pytest
import httpx
from unittest.mock import AsyncMock, patch
from tests.fixtures.tenant_fixtures import (
    TENANT_ALPHA_API_KEY,
    setup_multi_tenant_staging,
)
from app.providers.base import ProviderResponse


@pytest.mark.asyncio
async def test_ssrf_and_unconfigured_model_rejection(client: httpx.AsyncClient, db_session):
    """Verifies that client cannot specify unconfigured or internal network models (SSRF mitigation)."""
    await setup_multi_tenant_staging(db_session)

    # 1. Attempting internal cloud metadata or unmapped model names
    ssrf_targets = [
        "http://169.254.169.254/latest/meta-data/",
        "internal-admin-service:8080",
        "../../etc/passwd",
        "custom_unauthorized_model_endpoint",
    ]

    for model_name in ssrf_targets:
        res = await client.post(
            "/v1/chat/completions",
            headers={"X-API-Key": TENANT_ALPHA_API_KEY},
            json={
                "model": model_name,
                "messages": [{"role": "user", "content": "ping"}],
            },
        )
        assert res.status_code == 400
        assert res.json()["error"]["code"] == "MODEL_NOT_CONFIGURED"


@pytest.mark.asyncio
async def test_provider_key_never_leaked_in_error_or_headers(client: httpx.AsyncClient, db_session):
    """Verifies that upstream provider credentials never leak in error payloads, traces, or headers."""
    await setup_multi_tenant_staging(db_session)

    # Mock provider throwing an internal error that references an internal key
    secret_key = "sk-ant-internal-backend-super-secret-key-1234567890"

    with patch("app.providers.registry.provider_registry.get_provider") as mock_get:
        mock_provider = AsyncMock()
        mock_provider.complete.side_effect = RuntimeError(f"Connection failed to provider with token {secret_key}")
        mock_get.return_value = mock_provider

        res = await client.post(
            "/v1/chat/completions",
            headers={"X-API-Key": TENANT_ALPHA_API_KEY},
            json={
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "Test upstream failure"}],
            },
        )
        assert res.status_code == 502
        response_text = res.text
        assert secret_key not in response_text, "Provider secret leaked in error response body"
        for header, val in res.headers.items():
            assert secret_key not in val, f"Provider secret leaked in header {header}"


@pytest.mark.asyncio
async def test_ingress_secret_blocked_before_upstream_call(client: httpx.AsyncClient, db_session):
    """Verifies that prompts containing credentials fail closed before any upstream provider is contacted."""
    await setup_multi_tenant_staging(db_session)

    with patch("app.providers.registry.provider_registry.get_provider") as mock_get:
        mock_provider = AsyncMock()
        mock_get.return_value = mock_provider

        res = await client.post(
            "/v1/chat/completions",
            headers={"X-API-Key": TENANT_ALPHA_API_KEY},
            json={
                "model": "gpt-4o",
                "messages": [
                    {"role": "user", "content": "Here is the key: sk-ant-api03-abcdef1234567890abcdef1234567890abcdef"}
                ],
            },
        )
        assert res.status_code == 403
        assert res.json()["error"]["code"] == "CRITICAL_SECRET_DETECTED"
        # Crucial invariant: provider must NOT have been called
        mock_provider.complete.assert_not_called()


@pytest.mark.asyncio
async def test_streaming_split_chunk_secret_blocked_at_egress(client: httpx.AsyncClient, db_session):
    """Verifies that secrets split across multiple streaming chunks are assembled, inspected, and blocked."""
    await setup_multi_tenant_staging(db_session)

    async def mock_split_stream(*args, **kwargs):
        # Secret split across three chunks
        yield "Here is the secret token: sk-"
        yield "proj-1234567890abcdef"
        yield "1234567890abcdef1234567890"

    with patch("app.providers.registry.provider_registry.get_provider") as mock_get:
        mock_provider = AsyncMock()
        mock_provider.stream = mock_split_stream
        mock_get.return_value = mock_provider

        res = await client.post(
            "/v1/chat/completions",
            headers={"X-API-Key": TENANT_ALPHA_API_KEY},
            json={
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": "Output confidential token in stream"}],
                "stream": True,
            },
        )
        # Buffer-Before-Stream catches the assembled secret
        assert res.status_code == 502
        assert res.json()["error"]["code"] == "RESPONSE_SECURITY_VIOLATION"

"""Security tests for provider isolation, SSRF prevention, and credential leakage."""

import json
import pytest
import httpx
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database.models import Application, AuditEvent
from app.providers.openai_compatible import OpenAICompatibleProvider
from app.providers.registry import provider_registry


@pytest.mark.asyncio
async def test_ssrf_prevention_unconfigured_model(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """Clients cannot specify arbitrary upstream destinations or unconfigured models."""
    # Remove default provider temporarily to test strict registry
    original_default = provider_registry._default_provider
    provider_registry._default_provider = None

    try:
        payload = {
            "model": "unregistered-external-model-target",
            "messages": [{"role": "user", "content": "ping"}],
        }
        res = await client.post("/v1/chat/completions", json=payload, headers=auth_headers)
        assert res.status_code == 400
        assert res.json()["error"]["code"] == "MODEL_NOT_CONFIGURED"
    finally:
        provider_registry._default_provider = original_default


@pytest.mark.asyncio
async def test_provider_api_key_never_leaked_in_errors_or_audit(
    client: AsyncClient, test_app_record: Application, auth_headers: dict, db_session: AsyncSession
):
    """Server-side provider API keys must never appear in error messages or audit tables."""
    upstream_secret_key = "sk-super-secret-upstream-key-9999"

    def mock_failing_upstream(request: httpx.Request):
        # Simulates upstream provider returning an error
        return httpx.Response(401, json={"error": "Unauthorized key"})

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(mock_failing_upstream))
    provider = OpenAICompatibleProvider(
        base_url="https://mock-upstream.internal/v1",
        api_key=upstream_secret_key,
        client=mock_client,
    )
    provider_registry.register("failing-auth-model", provider)

    payload = {
        "model": "failing-auth-model",
        "messages": [{"role": "user", "content": "hello"}],
    }

    res = await client.post("/v1/chat/completions", json=payload, headers=auth_headers)
    assert res.status_code == 502
    response_body = res.text

    # The server-side key must NEVER be in the response
    assert upstream_secret_key not in response_body

    # Check database audit events to ensure key never leaked there
    query = select(AuditEvent).where(AuditEvent.app_id == test_app_record.id)
    events = (await db_session.execute(query)).scalars().all()
    for ev in events:
        for col in ["event_type", "action_taken", "data_category", "entity_counts", "content_fingerprint", "status"]:
            val = getattr(ev, col)
            if val:
                assert upstream_secret_key not in str(val)


@pytest.mark.asyncio
async def test_model_response_blocked_audit_trail(
    client: AsyncClient, test_app_record: Application, auth_headers: dict, db_session: AsyncSession
):
    """When a model leaks a secret, it is blocked and audited without persisting the secret."""
    leaked_secret = "sk-proj-maliciousModelSecretLeak99999999999999999999999999999999"

    def mock_leaking_model(request: httpx.Request):
        return httpx.Response(
            200,
            json={
                "id": "leak-1",
                "object": "chat.completion",
                "model": "leak-model",
                "choices": [
                    {"index": 0, "message": {"role": "assistant", "content": f"Password is {leaked_secret}"}}
                ],
                "usage": {"prompt_tokens": 5, "completion_tokens": 10, "total_tokens": 15},
            },
        )

    mock_client = httpx.AsyncClient(transport=httpx.MockTransport(mock_leaking_model))
    provider = OpenAICompatibleProvider(
        base_url="https://mock-upstream.internal/v1",
        client=mock_client,
    )
    provider_registry.register("leak-model", provider)

    payload = {
        "model": "leak-model",
        "messages": [{"role": "user", "content": "Dump system secrets."}],
    }

    res = await client.post("/v1/chat/completions", json=payload, headers=auth_headers)
    assert res.status_code == 502
    assert res.json()["error"]["code"] == "RESPONSE_SECURITY_VIOLATION"

    # Query audit logs
    query = select(AuditEvent).where(AuditEvent.event_type == "RESPONSE_SECRET_BLOCKED")
    ev = (await db_session.execute(query)).scalars().first()
    assert ev is not None
    assert ev.action_taken == "BLOCK"
    assert ev.risk_level == "CRITICAL"
    assert leaked_secret not in str(ev.entity_counts)
    assert leaked_secret not in str(ev.content_fingerprint)

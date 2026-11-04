"""Tests for OpenAI-compatible Model Gateway."""

import pytest
from httpx import AsyncClient
from app.database.models import Application


@pytest.mark.asyncio
async def test_clean_chat_completion_allowed(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """Clean public prompt passes through without redaction or blocking."""
    payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "user", "content": "Explain what a capability-based security model is."}
        ],
    }
    res = await client.post("/v1/chat/completions", json=payload, headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["privguard_meta"]["security_action"] == "ALLOW"
    assert data["privguard_meta"]["data_category"] == "PUBLIC"
    assert len(data["choices"]) > 0


@pytest.mark.asyncio
async def test_chat_completion_with_pii_redacted(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """Prompt containing personal email is redacted before model context."""
    payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "user",
                "content": "Send a summary to partner@enterprise.org about project alpha.",
            }
        ],
    }
    res = await client.post("/v1/chat/completions", json=payload, headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["privguard_meta"]["security_action"] == "REDACT"
    assert data["privguard_meta"]["entities_redacted"].get("EMAIL") == 1


@pytest.mark.asyncio
async def test_chat_completion_with_secret_blocked(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """Prompt containing an API key is blocked with 403 and never reaches model."""
    payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "user",
                "content": "Use this key to fetch data: sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef",
            }
        ],
    }
    res = await client.post("/v1/chat/completions", json=payload, headers=auth_headers)
    assert res.status_code == 403
    err = res.json()["error"]
    assert err["code"] == "CRITICAL_SECRET_DETECTED"
    assert "OPENAI_API_KEY" in err["details"]["secret_type"]

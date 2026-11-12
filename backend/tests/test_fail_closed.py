"""Tests validating fail-closed security invariants."""

import pytest
from httpx import AsyncClient
from app.database.models import Application
from app.policies.engine import PolicyEngine
from app.policies.schemas import PolicyAction


def test_unknown_category_fails_closed():
    """Any unregistered data category must fail-closed to BLOCK."""
    strict_engine = PolicyEngine()
    decision = strict_engine.evaluate(category="NON_EXISTENT_UNKNOWN_CATEGORY")
    assert decision.action == PolicyAction.BLOCK
    assert decision.allow_execution is False
    assert "Fail-closed" in decision.reason


@pytest.mark.asyncio
async def test_corrupted_messages_structure_rejected(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """Malformed message arrays must be rejected cleanly with 422 Unprocessable Entity."""
    res = await client.post(
        "/v1/chat/completions",
        json={"model": "gpt-4o", "messages": "not-a-list"},
        headers=auth_headers,
    )
    assert res.status_code == 422


@pytest.mark.asyncio
async def test_secret_hidden_in_system_prompt_blocked(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """Secrets anywhere in system or developer messages are caught and blocked."""
    payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "system",
                "content": "Your database password is db_password = 'production_super_secret_pw_9999'",
            },
            {"role": "user", "content": "Help me optimize this database."},
        ],
    }
    res = await client.post("/v1/chat/completions", json=payload, headers=auth_headers)
    assert res.status_code == 403
    assert res.json()["error"]["code"] == "CRITICAL_SECRET_DETECTED"


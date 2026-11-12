"""Tests ensuring zero raw content retention in audit logs."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database.models import Application, AuditEvent


@pytest.mark.asyncio
async def test_audit_logs_contain_no_raw_prompts_or_secrets(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
    db_session: AsyncSession,
):
    """
    Core Invariant: Audit records must never persist raw prompt,
    response, secret, or PII text.
    """
    sensitive_email = "confidential_ceo@megacorp.internal"
    secret_key = "ghp_VerySecretGitHubToken99999999999999"

    # 1. Trigger Redacted Gateway Call
    await client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": f"Alert {sensitive_email} immediately."}],
        },
        headers=auth_headers,
    )

    # 2. Trigger Blocked Secret Call
    await client.post(
        "/v1/chat/completions",
        json={
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": f"Here is my deploy token: {secret_key}"}],
        },
        headers=auth_headers,
    )

    # 3. Query all recorded audit events directly from database
    query = select(AuditEvent).where(AuditEvent.app_id == test_app_record.id)
    result = await db_session.execute(query)
    events = result.scalars().all()

    assert len(events) >= 2

    for ev in events:
        # Check every single string column on the audit record
        for field_name in ["event_type", "action_taken", "data_category", "entity_counts", "content_fingerprint", "status"]:
            val = getattr(ev, field_name)
            if val is not None:
                assert sensitive_email not in str(val), f"Raw PII found in audit field {field_name}!"
                assert secret_key not in str(val), f"Raw secret found in audit field {field_name}!"

        # Fingerprint must be a 64-char sha256 hash
        if ev.content_fingerprint:
            assert len(ev.content_fingerprint) == 64


@pytest.mark.asyncio
async def test_audit_query_endpoint(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """The /v1/audit/events endpoint returns structured metadata cleanly."""
    res = await client.get("/v1/audit/events", headers=auth_headers)
    assert res.status_code == 200
    events = res.json()
    assert isinstance(events, list)
    if events:
        ev = events[0]
        assert "request_id" in ev
        assert "event_type" in ev
        assert "risk_level" in ev
        assert "content_fingerprint" in ev
        assert "raw_prompt" not in ev
        assert "text" not in ev


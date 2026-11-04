"""Tests for cryptographic temporary capabilities and revocation controls."""

from datetime import datetime, timedelta, timezone
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from app.database.models import Application, CapabilityGrant


@pytest.mark.asyncio
async def test_capability_cryptographic_hashing_in_db(
    client: AsyncClient, test_app_record: Application, auth_headers: dict, db_session: AsyncSession
):
    """Plaintext capability secrets must NEVER be persisted in the database."""
    # Register agent and create task
    res_ag = await client.post("/v1/agents/register", json={"name": "Cap Agent"}, headers=auth_headers)
    agent_id = res_ag.json()["id"]

    res_tsk = await client.post("/v1/tasks", json={"agent_id": agent_id}, headers=auth_headers)
    task_id = res_tsk.json()["id"]

    # Request capability
    res_cap = await client.post(
        "/v1/capabilities/request",
        json={
            "agent_id": agent_id,
            "task_id": task_id,
            "tool_name": "read_file",
            "max_uses": 1,
        },
        headers=auth_headers,
    )
    assert res_cap.status_code == 200
    data = res_cap.json()
    cap_id = data["id"]
    raw_token = data["capability_token"]
    assert raw_token.startswith("pg_cap_")

    # Inspect database record directly
    query = select(CapabilityGrant).where(CapabilityGrant.id == cap_id)
    grant = (await db_session.execute(query)).scalar_one()

    # The raw token must NOT be stored in any column
    assert grant.secret_hash != raw_token
    assert len(grant.secret_hash) == 64  # SHA-256


@pytest.mark.asyncio
async def test_capability_max_uses_and_immediate_revocation(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """Enforces max_uses limit and tests instant revocation."""
    # Register agent & task
    res_ag = await client.post("/v1/agents/register", json={"name": "Revoke Agent"}, headers=auth_headers)
    agent_id = res_ag.json()["id"]
    res_tsk = await client.post("/v1/tasks", json={"agent_id": agent_id}, headers=auth_headers)
    task_id = res_tsk.json()["id"]

    # 1. Issue single-use capability
    res_cap = await client.post(
        "/v1/capabilities/request",
        json={
            "agent_id": agent_id,
            "task_id": task_id,
            "tool_name": "search_web",
            "max_uses": 1,
        },
        headers=auth_headers,
    )
    token = res_cap.json()["capability_token"]
    cap_id = res_cap.json()["id"]

    # First execution succeeds
    exec_payload = {
        "agent_id": agent_id,
        "task_id": task_id,
        "capability_token": token,
        "parameters": {"query": "Antigravity Architecture"},
    }
    res_exec1 = await client.post("/v1/tools/search_web/execute", json=exec_payload, headers=auth_headers)
    assert res_exec1.status_code == 200

    # Second execution fails (max uses = 1 exceeded)
    res_exec2 = await client.post("/v1/tools/search_web/execute", json=exec_payload, headers=auth_headers)
    assert res_exec2.status_code == 403
    assert res_exec2.json()["error"]["code"] == "CAPABILITY_MAX_USES_EXCEEDED"

    # 2. Test Revocation
    res_cap2 = await client.post(
        "/v1/capabilities/request",
        json={
            "agent_id": agent_id,
            "task_id": task_id,
            "tool_name": "search_web",
            "max_uses": 5,
        },
        headers=auth_headers,
    )
    token2 = res_cap2.json()["capability_token"]
    cap2_id = res_cap2.json()["id"]

    # Revoke before use
    res_rev = await client.post(f"/v1/capabilities/{cap2_id}/revoke", headers=auth_headers)
    assert res_rev.status_code == 200
    assert res_rev.json()["is_revoked"] is True

    # Immediate execution attempt fails
    exec_payload2 = {
        "agent_id": agent_id,
        "task_id": task_id,
        "capability_token": token2,
        "parameters": {"query": "Test"},
    }
    res_exec3 = await client.post("/v1/tools/search_web/execute", json=exec_payload2, headers=auth_headers)
    assert res_exec3.status_code == 403
    assert res_exec3.json()["error"]["code"] == "CAPABILITY_REVOKED"

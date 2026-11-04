"""Tests for agent identity, registration, ownership, and status controls."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.security import hash_api_key
from app.database.models import Application


@pytest.mark.asyncio
async def test_agent_registration_and_lifecycle(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """Registers an agent and tests retrieval, disabling, and revocation."""
    # 1. Register
    reg_payload = {
        "name": "Research Agent Alpha",
        "description": "Autonomous document researcher",
        "allowed_tools": ["read_file", "search_web"],
    }
    res = await client.post("/v1/agents/register", json=reg_payload, headers=auth_headers)
    assert res.status_code == 200
    agent = res.json()
    assert agent["name"] == "Research Agent Alpha"
    assert agent["status"] == "ACTIVE"
    assert "read_file" in agent["allowed_tools"]
    agent_id = agent["id"]

    # 2. Retrieve
    res_get = await client.get(f"/v1/agents/{agent_id}", headers=auth_headers)
    assert res_get.status_code == 200
    assert res_get.json()["id"] == agent_id

    # 3. Disable
    res_dis = await client.post(f"/v1/agents/{agent_id}/disable", headers=auth_headers)
    assert res_dis.status_code == 200
    assert res_dis.json()["status"] == "DISABLED"

    # 4. Revoke
    res_rev = await client.post(f"/v1/agents/{agent_id}/revoke", headers=auth_headers)
    assert res_rev.status_code == 200
    assert res_rev.json()["status"] == "REVOKED"


@pytest.mark.asyncio
async def test_cross_application_agent_isolation(
    client: AsyncClient, test_app_record: Application, auth_headers: dict, db_session: AsyncSession
):
    """An application cannot access or execute agents belonging to a different application."""
    # Create second application
    app2_key = "pg_live_tenant_b_key_7777"
    app2 = Application(
        id="app_tenant_b",
        name="Tenant B Application",
        api_key_hash=hash_api_key(app2_key),
        is_active=True,
    )
    db_session.add(app2)
    await db_session.commit()

    # App 1 registers agent
    res = await client.post(
        "/v1/agents/register",
        json={"name": "Tenant A Secret Agent"},
        headers=auth_headers,
    )
    agent_id = res.json()["id"]

    # App 2 attempts to query App 1's agent
    res_cross = await client.get(
        f"/v1/agents/{agent_id}",
        headers={"X-API-Key": app2_key},
    )
    assert res_cross.status_code == 404
    assert res_cross.json()["error"]["code"] == "AGENT_NOT_FOUND"

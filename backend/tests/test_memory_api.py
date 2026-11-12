"""Automated API integration tests for PRIVGUARD Personal AI Memory Vault Endpoints."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from app.database.models import Application, AgentIdentity


@pytest.fixture
async def memory_agent(db_session: AsyncSession, test_app_record: Application):
    agent = AgentIdentity(
        id="ag_mem_api_agent",
        app_id=test_app_record.id,
        name="API Memory Agent",
        status="ACTIVE",
    )
    db_session.add(agent)
    await db_session.commit()
    return agent


@pytest.mark.asyncio
async def test_memory_crud_api_flow(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
):
    """Tests direct creation, listing, retrieval, update, and cryptographic deletion."""
    headers = {**auth_headers, "X-User-ID": "user_api_tester"}

    # 1. Create Memory
    res_create = await client.post(
        "/v1/memory",
        headers=headers,
        json={
            "key": "Preferred Coding Standard",
            "value": "Always use Black formatter, line length 100, PEP 8.",
            "category": "USER_PREFERENCES",
            "retention_days": 90,
        },
    )
    assert res_create.status_code == 201
    created_data = res_create.json()
    assert created_data["status"] == "ACTIVE"
    assert created_data["version"] == 1
    memory_id = created_data["id"]

    # 2. List Memories
    res_list = await client.get("/v1/memory", headers=headers)
    assert res_list.status_code == 200
    memories = res_list.json()
    assert any(m["id"] == memory_id for m in memories)

    # 3. Get / Decrypt Memory
    res_get = await client.get(f"/v1/memory/{memory_id}", headers=headers)
    assert res_get.status_code == 200
    detail = res_get.json()
    assert detail["value"] == "Always use Black formatter, line length 100, PEP 8."

    # 4. Update Memory
    res_update = await client.patch(
        f"/v1/memory/{memory_id}",
        headers=headers,
        json={
            "new_value": "Always use Ruff formatter, line length 100.",
            "expected_version": 1,
        },
    )
    assert res_update.status_code == 200
    assert res_update.json()["version"] == 2

    # Verify updated decryption
    res_get_updated = await client.get(f"/v1/memory/{memory_id}", headers=headers)
    assert res_get_updated.json()["value"] == "Always use Ruff formatter, line length 100."

    # 5. Search / Retrieve Endpoint
    res_search = await client.post(
        "/v1/memory/retrieve",
        headers=headers,
        json={"query": "Ruff", "categories": ["USER_PREFERENCES"]},
    )
    assert res_search.status_code == 200
    search_data = res_search.json()
    assert search_data["retrieved_count"] == 1
    assert "Ruff" in search_data["memories"][0]["content"]

    # 6. Cryptographic Deletion
    res_del = await client.delete(f"/v1/memory/{memory_id}", headers=headers)
    assert res_del.status_code == 204

    # Confirm not found
    res_get_deleted = await client.get(f"/v1/memory/{memory_id}", headers=headers)
    assert res_get_deleted.status_code == 404


@pytest.mark.asyncio
async def test_proposals_api_flow(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
    memory_agent: AgentIdentity,
):
    """Tests agent proposal submission, listing, and approval flow."""
    headers = {**auth_headers, "X-User-ID": "user_api_tester"}

    # First grant agent propose_write permission
    res_grant = await client.post(
        "/v1/memory/permissions",
        headers=headers,
        json={
            "agent_id": memory_agent.id,
            "operation": "memory.propose_write",
            "category": "USER_PREFERENCES",
        },
    )
    assert res_grant.status_code == 201

    # 1. Agent submits proposal
    res_prop = await client.post(
        "/v1/memory/proposals",
        headers=headers,
        json={
            "proposed_key": "Language preference",
            "proposed_value": "User requested documentation in TypeScript.",
            "category": "USER_PREFERENCES",
            "agent_id": memory_agent.id,
            "task_id": "tsk_api_1",
        },
    )
    assert res_prop.status_code == 201
    prop_data = res_prop.json()
    prop_id = prop_data["id"]
    assert prop_data["status"] == "PROPOSED"

    # 2. List proposals
    res_props = await client.get("/v1/memory/proposals", headers=headers)
    assert res_props.status_code == 200
    assert any(p["id"] == prop_id for p in res_props.json())

    # 3. User approves proposal
    res_approve = await client.post(
        f"/v1/memory/proposals/{prop_id}/approve",
        headers=headers,
        json={"retention_days": 45},
    )
    assert res_approve.status_code == 200
    active_record = res_approve.json()
    assert active_record["status"] == "ACTIVE"

    # Verify memory is stored and decryptable
    res_get_mem = await client.get(f"/v1/memory/{active_record['id']}", headers=headers)
    assert res_get_mem.status_code == 200
    assert res_get_mem.json()["value"] == "User requested documentation in TypeScript."


@pytest.mark.asyncio
async def test_retention_and_security_api(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
):
    """Tests retention metrics, KEK rotation, and vault purge via REST API."""
    headers = {**auth_headers, "X-User-ID": "user_security_tester"}

    # 1. Create a memory
    await client.post(
        "/v1/memory",
        headers=headers,
        json={
            "key": "Personal Interest",
            "value": "Interested in distributed consensus protocols.",
            "category": "PERSONAL_PREFERENCES",
        },
    )

    # 2. Check retention metrics
    res_ret = await client.get("/v1/memory/retention", headers=headers)
    assert res_ret.status_code == 200
    ret_data = res_ret.json()
    assert ret_data["active_count"] >= 1
    assert "PERSONAL_PREFERENCES" in ret_data["categories_breakdown"]

    # 3. Rotate User KEK
    res_rot = await client.post("/v1/memory/key/rotate", headers=headers)
    assert res_rot.status_code == 200
    rot_data = res_rot.json()
    assert rot_data["new_key_version"] == 2
    assert rot_data["records_rotated"] >= 1

    # 4. Check Audit Trail
    res_audit = await client.get("/v1/memory/audit", headers=headers)
    assert res_audit.status_code == 200
    audit_events = res_audit.json()
    assert any(e["operation"] == "ROTATE_KEY" for e in audit_events)

    # 5. Purge Vault
    res_purge = await client.post("/v1/memory/purge", headers=headers)
    assert res_purge.status_code == 200
    purge_data = res_purge.json()
    assert purge_data["status"] == "COMPLETED"
    assert purge_data["items_deleted"] >= 1


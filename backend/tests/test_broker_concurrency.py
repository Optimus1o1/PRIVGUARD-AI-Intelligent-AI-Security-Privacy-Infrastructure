"""Concurrency and race condition tests for capability and approval consumption."""

import asyncio
import pytest
from httpx import AsyncClient
from app.database.models import Application


@pytest.mark.asyncio
async def test_concurrent_single_use_capability_consumption(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """
    RACE CONDITION TEST:
    Two concurrent requests racing to consume the same 1-use capability.
    Exactly one must succeed, and the second must receive a 403 error.
    """
    res_ag = await client.post("/v1/agents/register", json={"name": "Race Agent"}, headers=auth_headers)
    agent_id = res_ag.json()["id"]
    res_tsk = await client.post("/v1/tasks", json={"agent_id": agent_id}, headers=auth_headers)
    task_id = res_tsk.json()["id"]

    # Issue single-use capability
    res_cap = await client.post(
        "/v1/capabilities/request",
        json={"agent_id": agent_id, "task_id": task_id, "tool_name": "search_web", "max_uses": 1},
        headers=auth_headers,
    )
    cap_token = res_cap.json()["capability_token"]

    payload = {
        "agent_id": agent_id,
        "task_id": task_id,
        "capability_token": cap_token,
        "parameters": {"query": "Concurrency Race Check"},
    }

    # Execute two parallel requests simultaneously
    res1, res2 = await asyncio.gather(
        client.post("/v1/tools/search_web/execute", json=payload, headers=auth_headers),
        client.post("/v1/tools/search_web/execute", json=payload, headers=auth_headers),
    )

    statuses = [res1.status_code, res2.status_code]
    assert 200 in statuses
    assert 403 in statuses


@pytest.mark.asyncio
async def test_concurrent_single_use_approval_consumption(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """
    RACE CONDITION TEST:
    Two concurrent requests racing to consume the same human approval.
    Exactly one must succeed, and the second must fail with APPROVAL_ALREADY_CONSUMED.
    """
    res_ag = await client.post(
        "/v1/agents/register",
        json={"name": "Approval Race Agent", "allowed_tools": ["send_email"]},
        headers=auth_headers,
    )
    agent_id = res_ag.json()["id"]
    res_tsk = await client.post("/v1/tasks", json={"agent_id": agent_id}, headers=auth_headers)
    task_id = res_tsk.json()["id"]

    res_cap = await client.post(
        "/v1/capabilities/request",
        json={"agent_id": agent_id, "task_id": task_id, "tool_name": "send_email", "max_uses": 5},
        headers=auth_headers,
    )
    cap_token = res_cap.json()["capability_token"]

    # Request approval
    params = {"recipient": "boss@corp.com", "subject": "Bonus", "body": "Approved?"}
    res_hold = await client.post(
        "/v1/tools/send_email/execute",
        json={"agent_id": agent_id, "task_id": task_id, "capability_token": cap_token, "parameters": params},
        headers=auth_headers,
    )
    approval_id = res_hold.json()["error"]["details"]["approval_id"]

    # Approve
    await client.post(f"/v1/approvals/{approval_id}/approve", headers=auth_headers)

    # Fire two concurrent executions with the same approval_id
    payload = {
        "agent_id": agent_id,
        "task_id": task_id,
        "capability_token": cap_token,
        "approval_id": approval_id,
        "parameters": params,
    }

    res1, res2 = await asyncio.gather(
        client.post("/v1/tools/send_email/execute", json=payload, headers=auth_headers),
        client.post("/v1/tools/send_email/execute", json=payload, headers=auth_headers),
    )

    statuses = [res1.status_code, res2.status_code]
    assert 200 in statuses
    assert 403 in statuses

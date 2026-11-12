"""
Assessment E: Human Approval Cryptographic Binding, Action Tampering, and Anti-Replay Red-Teaming Tests.
Validates HMAC binding, parameter alteration detection, single-use anti-replay, and race prevention.
"""

import asyncio
import pytest
import httpx
from tests.fixtures.tenant_fixtures import (
    TENANT_ALPHA_API_KEY,
    setup_multi_tenant_staging,
)


@pytest.mark.asyncio
async def test_parameter_tampering_attack_rejected(client: httpx.AsyncClient, db_session):
    """
    CRITICAL RED-TEAM INVARIANT:
    If a user approves an action with parameters A, but the executing agent attempts
    execution with parameters B (e.g. modified recipient), PRIVGUARD must detect the
    cryptographic mismatch and immediately block execution.
    """
    await setup_multi_tenant_staging(db_session)

    # 1. Setup Agent & Task
    reg = await client.post(
        "/v1/agents/register",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"name": "Tamper Test Agent", "allowed_tools": ["send_email"]},
    )
    agent_id = reg.json()["id"]

    task = await client.post("/v1/tasks", headers={"X-API-Key": TENANT_ALPHA_API_KEY}, json={"agent_id": agent_id})
    task_id = task.json()["id"]

    cap = await client.post(
        "/v1/capabilities/request",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "task_id": task_id, "tool_name": "send_email"},
    )
    token = cap.json()["capability_token"]

    # 2. Initial request for benign recipient
    initial_params = {"recipient": "legitimate_partner@corp.com", "subject": "Meeting", "body": "See you at 3"}
    res1 = await client.post(
        "/v1/tools/send_email/execute",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "task_id": task_id, "capability_token": token, "parameters": initial_params},
    )
    assert res1.status_code == 402
    approval_id = res1.json()["error"]["details"]["approval_id"]

    # 3. Human Operator approves the exact benign request
    appr_res = await client.post(
        f"/v1/approvals/{approval_id}/approve",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
    )
    assert appr_res.status_code == 200
    assert appr_res.json()["status"] == "APPROVED"

    # 4. Adversary/Compromised Agent modifies recipient to attacker@evil.com
    tampered_params = {"recipient": "attacker@evil.com", "subject": "Meeting", "body": "See you at 3"}
    res2 = await client.post(
        "/v1/tools/send_email/execute",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={
            "agent_id": agent_id,
            "task_id": task_id,
            "capability_token": token,
            "parameters": tampered_params,
            "approval_id": approval_id,
        },
    )
    assert res2.status_code == 403
    assert res2.json()["error"]["code"] == "APPROVAL_TAMPERING_DETECTED"


@pytest.mark.asyncio
async def test_tool_substitution_attack_rejected(client: httpx.AsyncClient, db_session):
    """Verifies that an approval granted for Tool A cannot be used to execute Tool B."""
    await setup_multi_tenant_staging(db_session)

    reg = await client.post(
        "/v1/agents/register",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"name": "Multi Tool Agent", "allowed_tools": ["send_email", "delete_file"]},
    )
    agent_id = reg.json()["id"]

    task = await client.post("/v1/tasks", headers={"X-API-Key": TENANT_ALPHA_API_KEY}, json={"agent_id": agent_id})
    task_id = task.json()["id"]

    cap = await client.post(
        "/v1/capabilities/request",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "task_id": task_id, "tool_name": "send_email"},
    )
    token = cap.json()["capability_token"]

    # Trigger approval for send_email
    res1 = await client.post(
        "/v1/tools/send_email/execute",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={
            "agent_id": agent_id,
            "task_id": task_id,
            "capability_token": token,
            "parameters": {"recipient": "user@corp.com", "subject": "Hi", "body": "Hello"},
        },
    )
    approval_id = res1.json()["error"]["details"]["approval_id"]

    # Approve send_email
    await client.post(f"/v1/approvals/{approval_id}/approve", headers={"X-API-Key": TENANT_ALPHA_API_KEY})

    # Request capability for delete_file
    cap_del = await client.post(
        "/v1/capabilities/request",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "task_id": task_id, "tool_name": "delete_file"},
    )
    token_del = cap_del.json()["capability_token"]

    # Attempt to execute delete_file with send_email's approval_id
    del_res = await client.post(
        "/v1/tools/delete_file/execute",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={
            "agent_id": agent_id,
            "task_id": task_id,
            "capability_token": token_del,
            "parameters": {"path": "test.txt"},
            "approval_id": approval_id,
        },
    )
    assert del_res.status_code == 403
    assert del_res.json()["error"]["code"] == "APPROVAL_TAMPERING_DETECTED"


@pytest.mark.asyncio
async def test_anti_replay_single_use_consumption(client: httpx.AsyncClient, db_session):
    """Verifies that an approved action can only be executed once (strict single-use)."""
    await setup_multi_tenant_staging(db_session)

    reg = await client.post(
        "/v1/agents/register",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"name": "Replay Agent", "allowed_tools": ["send_email"]},
    )
    agent_id = reg.json()["id"]

    task = await client.post("/v1/tasks", headers={"X-API-Key": TENANT_ALPHA_API_KEY}, json={"agent_id": agent_id})
    task_id = task.json()["id"]

    cap = await client.post(
        "/v1/capabilities/request",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "task_id": task_id, "tool_name": "send_email", "max_uses": 5},
    )
    token = cap.json()["capability_token"]

    params = {"recipient": "client@corp.com", "subject": "Invoice", "body": "Please pay"}

    # 1. Trigger approval
    res1 = await client.post(
        "/v1/tools/send_email/execute",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "task_id": task_id, "capability_token": token, "parameters": params},
    )
    approval_id = res1.json()["error"]["details"]["approval_id"]

    # 2. Approve
    await client.post(f"/v1/approvals/{approval_id}/approve", headers={"X-API-Key": TENANT_ALPHA_API_KEY})

    # 3. First execution succeeds
    exec1 = await client.post(
        "/v1/tools/send_email/execute",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={
            "agent_id": agent_id,
            "task_id": task_id,
            "capability_token": token,
            "parameters": params,
            "approval_id": approval_id,
        },
    )
    assert exec1.status_code == 200

    # 4. Replay attempt with same approval ID MUST fail
    exec2 = await client.post(
        "/v1/tools/send_email/execute",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={
            "agent_id": agent_id,
            "task_id": task_id,
            "capability_token": token,
            "parameters": params,
            "approval_id": approval_id,
        },
    )
    assert exec2.status_code == 403
    assert exec2.json()["error"]["code"] == "APPROVAL_ALREADY_CONSUMED"


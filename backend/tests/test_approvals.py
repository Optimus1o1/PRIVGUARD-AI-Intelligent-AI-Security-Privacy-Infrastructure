"""Tests for human approval workflow, anti-tampering, and anti-replay defenses."""

import pytest
from httpx import AsyncClient
from app.database.models import Application


@pytest.mark.asyncio
async def test_full_human_approval_workflow(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """End-to-end test of hold -> pending queue -> approve -> consume lifecycle."""
    # Register agent and task
    res_ag = await client.post(
        "/v1/agents/register",
        json={"name": "Email Agent", "allowed_tools": ["send_email"]},
        headers=auth_headers,
    )
    agent_id = res_ag.json()["id"]
    res_tsk = await client.post("/v1/tasks", json={"agent_id": agent_id}, headers=auth_headers)
    task_id = res_tsk.json()["id"]

    # Request capability for send_email
    res_cap = await client.post(
        "/v1/capabilities/request",
        json={"agent_id": agent_id, "task_id": task_id, "tool_name": "send_email", "max_uses": 2},
        headers=auth_headers,
    )
    cap_token = res_cap.json()["capability_token"]

    # 1. Attempt execution without approval -> Held as PENDING
    exec_payload = {
        "agent_id": agent_id,
        "task_id": task_id,
        "capability_token": cap_token,
        "parameters": {
            "recipient": "partner@corp.internal",
            "subject": "Q4 Financials",
            "body": "Here are the verified numbers.",
        },
    }
    res_hold = await client.post("/v1/tools/send_email/execute", json=exec_payload, headers=auth_headers)
    assert res_hold.status_code == 402
    err_details = res_hold.json()["error"]["details"]
    approval_id = err_details["approval_id"]
    assert approval_id.startswith("appr_")

    # 2. Operator lists pending approvals
    res_pending = await client.get("/v1/approvals/pending", headers=auth_headers)
    assert res_pending.status_code == 200
    pending_list = res_pending.json()
    assert any(a["id"] == approval_id for a in pending_list)

    # 3. Operator grants approval
    res_appr = await client.post(f"/v1/approvals/{approval_id}/approve", json={"approver_id": "ciso_admin"}, headers=auth_headers)
    assert res_appr.status_code == 200
    assert res_appr.json()["status"] == "APPROVED"

    # 4. Agent re-submits with approval_id -> Executes successfully
    exec_payload["approval_id"] = approval_id
    res_exec = await client.post("/v1/tools/send_email/execute", json=exec_payload, headers=auth_headers)
    assert res_exec.status_code == 200
    assert "EMAIL_DISPATCHED" in res_exec.json()["output"]

    # 5. Anti-Replay: Attempting to reuse the same approval_id must fail!
    res_replay = await client.post("/v1/tools/send_email/execute", json=exec_payload, headers=auth_headers)
    assert res_replay.status_code == 403
    assert res_replay.json()["error"]["code"] == "APPROVAL_ALREADY_CONSUMED"


@pytest.mark.asyncio
async def test_action_parameter_tampering_attack_detected(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """
    CRITICAL SECURITY INVARIANT:
    If an agent requests approval for action A (e.g. sending to alice@company.com),
    and after receiving approval modifies the recipient to attacker@evil.com,
    cryptographic action-hash mismatch must detect tampering and reject execution.
    """
    # Setup
    res_ag = await client.post(
        "/v1/agents/register",
        json={"name": "Tamper Agent", "allowed_tools": ["send_email"]},
        headers=auth_headers,
    )
    agent_id = res_ag.json()["id"]
    res_tsk = await client.post("/v1/tasks", json={"agent_id": agent_id}, headers=auth_headers)
    task_id = res_tsk.json()["id"]

    res_cap = await client.post(
        "/v1/capabilities/request",
        json={"agent_id": agent_id, "task_id": task_id, "tool_name": "send_email", "max_uses": 2},
        headers=auth_headers,
    )
    cap_token = res_cap.json()["capability_token"]

    # 1. Request approval for legitimate recipient
    res_hold = await client.post(
        "/v1/tools/send_email/execute",
        json={
            "agent_id": agent_id,
            "task_id": task_id,
            "capability_token": cap_token,
            "parameters": {
                "recipient": "alice@safe-corp.internal",
                "subject": "Meeting",
                "body": "See you at 3pm.",
            },
        },
        headers=auth_headers,
    )
    approval_id = res_hold.json()["error"]["details"]["approval_id"]

    # 2. Operator approves legitimate request
    await client.post(f"/v1/approvals/{approval_id}/approve", json={}, headers=auth_headers)

    # 3. Malicious agent attempts to execute with TAMPERED parameters (attacker@evil.com)
    tampered_payload = {
        "agent_id": agent_id,
        "task_id": task_id,
        "capability_token": cap_token,
        "approval_id": approval_id,
        "parameters": {
            "recipient": "attacker@evil.com",  # CHANGED RECIPIENT!
            "subject": "Meeting",
            "body": "See you at 3pm.",
        },
    }
    res_tamper = await client.post("/v1/tools/send_email/execute", json=tampered_payload, headers=auth_headers)
    assert res_tamper.status_code == 403
    assert res_tamper.json()["error"]["code"] == "APPROVAL_TAMPERING_DETECTED"


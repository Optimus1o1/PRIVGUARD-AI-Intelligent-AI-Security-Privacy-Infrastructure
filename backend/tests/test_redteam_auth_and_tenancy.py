"""
Assessment A: Authentication, Tenant Isolation & IDOR Red-Teaming Tests.
Validates multi-tenant boundaries across Agents, Tasks, Capabilities, Approvals, Taints, and Audit.
"""

import pytest
import httpx
from sqlalchemy.ext.asyncio import AsyncSession
from tests.fixtures.tenant_fixtures import (
    TENANT_ALPHA_APP_ID,
    TENANT_ALPHA_API_KEY,
    TENANT_BRAVO_APP_ID,
    TENANT_BRAVO_API_KEY,
    setup_multi_tenant_staging,
)


@pytest.mark.asyncio
async def test_cross_tenant_agent_isolation(client: httpx.AsyncClient, db_session: AsyncSession):
    """Verifies that Tenant Bravo cannot inspect, disable, or revoke Tenant Alpha's agents."""
    await setup_multi_tenant_staging(db_session)

    # 1. Tenant Alpha registers an agent
    reg_res = await client.post(
        "/v1/agents/register",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={
            "name": "Alpha Financial Agent",
            "allowed_tools": ["read_file", "search_web"],
        },
    )
    assert reg_res.status_code == 200
    agent_id = reg_res.json()["id"]

    # 2. Tenant Bravo attempts to fetch Tenant Alpha's agent
    get_res = await client.get(
        f"/v1/agents/{agent_id}",
        headers={"X-API-Key": TENANT_BRAVO_API_KEY},
    )
    assert get_res.status_code == 404, "Tenant Bravo should not be able to find Tenant Alpha's agent"

    # 3. Tenant Bravo attempts to disable Tenant Alpha's agent
    dis_res = await client.post(
        f"/v1/agents/{agent_id}/disable",
        headers={"X-API-Key": TENANT_BRAVO_API_KEY},
    )
    assert dis_res.status_code == 404, "Tenant Bravo should not be able to disable Tenant Alpha's agent"

    # 4. Tenant Bravo attempts to revoke Tenant Alpha's agent
    rev_res = await client.post(
        f"/v1/agents/{agent_id}/revoke",
        headers={"X-API-Key": TENANT_BRAVO_API_KEY},
    )
    assert rev_res.status_code == 404, "Tenant Bravo should not be able to revoke Tenant Alpha's agent"


@pytest.mark.asyncio
async def test_cross_tenant_task_isolation(client: httpx.AsyncClient, db_session: AsyncSession):
    """Verifies that Tenant Bravo cannot query or abort Tenant Alpha's tasks."""
    await setup_multi_tenant_staging(db_session)

    # 1. Tenant Alpha registers agent and creates a task
    reg_res = await client.post(
        "/v1/agents/register",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"name": "Alpha Worker", "allowed_tools": ["read_file"]},
    )
    assert reg_res.status_code == 200
    agent_id = reg_res.json()["id"]

    task_res = await client.post(
        "/v1/tasks",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "description": "Confidential payroll parsing"},
    )
    assert task_res.status_code == 200
    task_id = task_res.json()["id"]

    # 2. Tenant Bravo attempts to get task details
    get_res = await client.get(
        f"/v1/tasks/{task_id}",
        headers={"X-API-Key": TENANT_BRAVO_API_KEY},
    )
    assert get_res.status_code == 404, "Tenant Bravo must not access Tenant Alpha's task"

    # 3. Tenant Bravo attempts to cancel task
    cancel_res = await client.post(
        f"/v1/tasks/{task_id}/cancel",
        headers={"X-API-Key": TENANT_BRAVO_API_KEY},
    )
    assert cancel_res.status_code == 404, "Tenant Bravo must not cancel Tenant Alpha's task"


@pytest.mark.asyncio
async def test_cross_tenant_capability_theft_prevention(client: httpx.AsyncClient, db_session: AsyncSession):
    """Verifies that Tenant Bravo cannot request a capability bound to Tenant Alpha's agent or task."""
    await setup_multi_tenant_staging(db_session)

    # Tenant Alpha setup
    reg_res = await client.post(
        "/v1/agents/register",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"name": "Alpha DB Agent", "allowed_tools": ["read_file"]},
    )
    agent_id = reg_res.json()["id"]

    task_res = await client.post(
        "/v1/tasks",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "description": "Alpha DB read"},
    )
    task_id = task_res.json()["id"]

    # Tenant Bravo attempts to request capability bound to Alpha's agent and task
    cap_res = await client.post(
        "/v1/capabilities/request",
        headers={"X-API-Key": TENANT_BRAVO_API_KEY},
        json={
            "agent_id": agent_id,
            "task_id": task_id,
            "tool_name": "read_file",
        },
    )
    # Must fail because agent does not belong to Tenant Bravo
    assert cap_res.status_code in (403, 404), "Tenant Bravo cannot bind capabilities to foreign agents"


@pytest.mark.asyncio
async def test_cross_tenant_approval_isolation(client: httpx.AsyncClient, db_session: AsyncSession):
    """Verifies that Tenant Bravo cannot see or resolve Tenant Alpha's pending approvals."""
    await setup_multi_tenant_staging(db_session)

    # 1. Tenant Alpha sets up agent and task
    reg_res = await client.post(
        "/v1/agents/register",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"name": "Alpha Exec", "allowed_tools": ["send_email"]},
    )
    agent_id = reg_res.json()["id"]

    task_res = await client.post(
        "/v1/tasks",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "description": "Send confidential memo"},
    )
    task_id = task_res.json()["id"]

    # 2. Issue capability
    cap_res = await client.post(
        "/v1/capabilities/request",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "task_id": task_id, "tool_name": "send_email"},
    )
    assert cap_res.status_code == 200
    token = cap_res.json()["capability_token"]

    # 3. Trigger approval requirement
    exec_res = await client.post(
        "/v1/tools/send_email/execute",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={
            "agent_id": agent_id,
            "task_id": task_id,
            "capability_token": token,
            "parameters": {"recipient": "ceo@alpha.com", "subject": "Financials", "body": "Q3 Report"},
        },
    )
    assert exec_res.status_code == 402
    approval_id = exec_res.json()["error"]["details"]["approval_id"]

    # 4. Tenant Bravo lists pending approvals
    bravo_pending = await client.get(
        "/v1/approvals/pending",
        headers={"X-API-Key": TENANT_BRAVO_API_KEY},
    )
    assert bravo_pending.status_code == 200
    pending_ids = [a["id"] for a in bravo_pending.json()]
    assert approval_id not in pending_ids, "Tenant Bravo must not see Tenant Alpha's pending approvals"

    # 5. Tenant Bravo attempts to approve Tenant Alpha's request
    bravo_approve = await client.post(
        f"/v1/approvals/{approval_id}/approve",
        headers={"X-API-Key": TENANT_BRAVO_API_KEY},
    )
    assert bravo_approve.status_code == 404, "Tenant Bravo cannot approve Tenant Alpha's request"

    # 6. Tenant Bravo attempts to reject Tenant Alpha's request
    bravo_reject = await client.post(
        f"/v1/approvals/{approval_id}/reject",
        headers={"X-API-Key": TENANT_BRAVO_API_KEY},
    )
    assert bravo_reject.status_code == 404, "Tenant Bravo cannot reject Tenant Alpha's request"


@pytest.mark.asyncio
async def test_cross_tenant_audit_isolation(client: httpx.AsyncClient, db_session: AsyncSession):
    """Verifies that non-admin tenants can only query their own audit events."""
    await setup_multi_tenant_staging(db_session)

    # 1. Tenant Alpha runs inspection generating an audit record
    await client.post(
        "/v1/privacy/inspect",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"text": "Alpha company confidential internal text."},
    )

    # 2. Tenant Bravo queries audit events
    res = await client.get(
        "/v1/audit/events",
        headers={"X-API-Key": TENANT_BRAVO_API_KEY},
    )
    assert res.status_code == 200
    events = res.json()
    for evt in events:
        assert evt.get("app_id") != TENANT_ALPHA_APP_ID, "Tenant Bravo must not see Tenant Alpha's audit events"

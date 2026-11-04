"""
Assessment D: Agent Security Broker, Capability Lifecycle, and Sandbox Jail Red-Teaming Tests.
Validates least privilege, capability single-use, revocation, and filesystem boundary enforcement.
"""

import pytest
import httpx
from tests.fixtures.tenant_fixtures import (
    TENANT_ALPHA_API_KEY,
    setup_multi_tenant_staging,
)


@pytest.mark.asyncio
async def test_disabled_agent_cannot_execute_tools(client: httpx.AsyncClient, db_session):
    """Verifies that once an agent is disabled, all tool execution attempts are blocked."""
    await setup_multi_tenant_staging(db_session)

    # 1. Register agent
    reg_res = await client.post(
        "/v1/agents/register",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"name": "Suspicious Agent", "allowed_tools": ["search_web"]},
    )
    agent_id = reg_res.json()["id"]

    # 2. Create task and get capability
    task_res = await client.post(
        "/v1/tasks",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "description": "Web task"},
    )
    task_id = task_res.json()["id"]

    cap_res = await client.post(
        "/v1/capabilities/request",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "task_id": task_id, "tool_name": "search_web"},
    )
    token = cap_res.json()["capability_token"]

    # 3. Disable agent
    await client.post(f"/v1/agents/{agent_id}/disable", headers={"X-API-Key": TENANT_ALPHA_API_KEY})

    # 4. Attempt tool execution with valid capability token
    exec_res = await client.post(
        "/v1/tools/search_web/execute",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={
            "agent_id": agent_id,
            "task_id": task_id,
            "capability_token": token,
            "parameters": {"query": "python"},
        },
    )
    assert exec_res.status_code == 403
    assert exec_res.json()["error"]["code"] == "AGENT_NOT_ACTIVE"


@pytest.mark.asyncio
async def test_immediate_capability_revocation_enforced(client: httpx.AsyncClient, db_session):
    """Verifies that revoked capabilities cannot be consumed even if unexpired."""
    await setup_multi_tenant_staging(db_session)

    # 1. Setup agent & task
    reg = await client.post(
        "/v1/agents/register",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"name": "Revocable Agent", "allowed_tools": ["search_web"]},
    )
    agent_id = reg.json()["id"]

    task = await client.post(
        "/v1/tasks",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id},
    )
    task_id = task.json()["id"]

    # 2. Request capability with max_uses=5
    cap = await client.post(
        "/v1/capabilities/request",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "task_id": task_id, "tool_name": "search_web", "max_uses": 5},
    )
    cap_data = cap.json()
    cap_id = cap_data["id"]
    token = cap_data["capability_token"]

    # 3. First execution succeeds
    exec1 = await client.post(
        "/v1/tools/search_web/execute",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "task_id": task_id, "capability_token": token, "parameters": {"query": "q1"}},
    )
    assert exec1.status_code == 200

    # 4. Revoke capability
    rev = await client.post(
        f"/v1/capabilities/{cap_id}/revoke",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
    )
    assert rev.status_code == 200
    assert rev.json()["is_revoked"] is True

    # 5. Subsequent execution MUST be blocked
    exec2 = await client.post(
        "/v1/tools/search_web/execute",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "task_id": task_id, "capability_token": token, "parameters": {"query": "q2"}},
    )
    assert exec2.status_code == 403
    assert exec2.json()["error"]["code"] == "CAPABILITY_REVOKED"


@pytest.mark.asyncio
async def test_cross_task_capability_replay_rejected(client: httpx.AsyncClient, db_session):
    """Verifies that capability tokens are strictly bound to their task session and cannot be replayed across tasks."""
    await setup_multi_tenant_staging(db_session)

    # 1. Setup agent & two tasks
    reg = await client.post(
        "/v1/agents/register",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"name": "Replay Test Agent", "allowed_tools": ["search_web"]},
    )
    agent_id = reg.json()["id"]

    task1 = await client.post("/v1/tasks", headers={"X-API-Key": TENANT_ALPHA_API_KEY}, json={"agent_id": agent_id})
    task1_id = task1.json()["id"]

    task2 = await client.post("/v1/tasks", headers={"X-API-Key": TENANT_ALPHA_API_KEY}, json={"agent_id": agent_id})
    task2_id = task2.json()["id"]

    # 2. Issue capability bound to task1
    cap = await client.post(
        "/v1/capabilities/request",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "task_id": task1_id, "tool_name": "search_web"},
    )
    token = cap.json()["capability_token"]

    # 3. Attempt to use capability in task2
    exec_res = await client.post(
        "/v1/tools/search_web/execute",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "task_id": task2_id, "capability_token": token, "parameters": {"query": "test"}},
    )
    assert exec_res.status_code == 403
    assert exec_res.json()["error"]["code"] == "CAPABILITY_TASK_MISMATCH"


@pytest.mark.asyncio
async def test_filesystem_sandbox_directory_traversal_blocked(client: httpx.AsyncClient, db_session):
    """Verifies that directory traversal and absolute path escaping attempts are blocked in read_file."""
    await setup_multi_tenant_staging(db_session)

    reg = await client.post(
        "/v1/agents/register",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"name": "File Agent", "allowed_tools": ["read_file"]},
    )
    agent_id = reg.json()["id"]

    task = await client.post("/v1/tasks", headers={"X-API-Key": TENANT_ALPHA_API_KEY}, json={"agent_id": agent_id})
    task_id = task.json()["id"]

    cap = await client.post(
        "/v1/capabilities/request",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "task_id": task_id, "tool_name": "read_file", "max_uses": 10},
    )
    token = cap.json()["capability_token"]

    traversal_payloads = [
        "../../etc/passwd",
        "..\\..\\Windows\\System32\\cmd.exe",
        "/etc/shadow",
        "\\Windows\\win.ini",
        "C:\\autoexec.bat",
        "....//....//etc/passwd",
    ]

    for path in traversal_payloads:
        res = await client.post(
            "/v1/tools/read_file/execute",
            headers={"X-API-Key": TENANT_ALPHA_API_KEY},
            json={
                "agent_id": agent_id,
                "task_id": task_id,
                "capability_token": token,
                "parameters": {"path": path},
            },
        )
        assert res.status_code == 403, f"Traversal path '{path}' was not blocked with 403"
        assert res.json()["error"]["code"] in ("PATH_TRAVERSAL_DETECTED", "SANDBOX_BOUNDARY_VIOLATION")


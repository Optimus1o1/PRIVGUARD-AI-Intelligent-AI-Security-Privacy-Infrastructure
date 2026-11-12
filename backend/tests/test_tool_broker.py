"""Tests for Tool Broker, schema validation, sandboxing, and output scanning."""

import os
from pathlib import Path
import pytest
from httpx import AsyncClient
from app.agent_security.executor import SANDBOX_DIR, ensure_sandbox
from app.database.models import Application


@pytest.fixture(autouse=True)
def setup_sandbox_environment():
    """Ensures test sandbox directory and test files exist."""
    ensure_sandbox()
    test_file = SANDBOX_DIR / "project_specs.txt"
    test_file.write_text("Confidential Project Specifications: Architecture details.", encoding="utf-8")
    yield
    if test_file.exists():
        test_file.unlink()


@pytest.mark.asyncio
async def test_safe_file_read_in_sandbox(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """Agent can read files strictly within the sandbox directory."""
    res_ag = await client.post("/v1/agents/register", json={"name": "File Reader", "allowed_tools": ["read_file"]}, headers=auth_headers)
    agent_id = res_ag.json()["id"]
    res_tsk = await client.post("/v1/tasks", json={"agent_id": agent_id}, headers=auth_headers)
    task_id = res_tsk.json()["id"]

    res_cap = await client.post(
        "/v1/capabilities/request",
        json={"agent_id": agent_id, "task_id": task_id, "tool_name": "read_file", "resource": "project_specs.txt"},
        headers=auth_headers,
    )
    cap_token = res_cap.json()["capability_token"]

    exec_payload = {
        "agent_id": agent_id,
        "task_id": task_id,
        "capability_token": cap_token,
        "parameters": {"path": "project_specs.txt"},
    }
    res_exec = await client.post("/v1/tools/read_file/execute", json=exec_payload, headers=auth_headers)
    assert res_exec.status_code == 200
    assert "Confidential Project Specifications" in res_exec.json()["output"]


@pytest.mark.asyncio
async def test_path_traversal_attack_blocked(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """Attempts to escape sandbox via ../ or root paths are hard-blocked."""
    res_ag = await client.post("/v1/agents/register", json={"name": "Attacker Agent", "allowed_tools": ["read_file"]}, headers=auth_headers)
    agent_id = res_ag.json()["id"]
    res_tsk = await client.post("/v1/tasks", json={"agent_id": agent_id}, headers=auth_headers)
    task_id = res_tsk.json()["id"]

    res_cap = await client.post(
        "/v1/capabilities/request",
        json={"agent_id": agent_id, "task_id": task_id, "tool_name": "read_file"},
        headers=auth_headers,
    )
    cap_token = res_cap.json()["capability_token"]

    traversal_payload = {
        "agent_id": agent_id,
        "task_id": task_id,
        "capability_token": cap_token,
        "parameters": {"path": "../../windows/system32/cmd.exe"},
    }
    res_exec = await client.post("/v1/tools/read_file/execute", json=traversal_payload, headers=auth_headers)
    assert res_exec.status_code == 403
    assert "PATH_TRAVERSAL_DETECTED" in res_exec.json()["error"]["code"]


@pytest.mark.asyncio
async def test_unregistered_and_disabled_tools_rejected(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """Unregistered tools and disabled tools (execute_code) cannot be executed."""
    res_ag = await client.post("/v1/agents/register", json={"name": "Coder Agent", "allowed_tools": ["execute_code"]}, headers=auth_headers)
    agent_id = res_ag.json()["id"]
    res_tsk = await client.post("/v1/tasks", json={"agent_id": agent_id}, headers=auth_headers)
    task_id = res_tsk.json()["id"]

    # 1. Unregistered tool
    res_unreg = await client.post(
        "/v1/tools/arbitrary_bash/execute",
        json={"agent_id": agent_id, "task_id": task_id, "capability_token": "token", "parameters": {}},
        headers=auth_headers,
    )
    assert res_unreg.status_code == 403
    assert res_unreg.json()["error"]["code"] == "TOOL_EXECUTION_UNAUTHORIZED"

    # 2. execute_code is disabled
    res_cap = await client.post(
        "/v1/capabilities/request",
        json={"agent_id": agent_id, "task_id": task_id, "tool_name": "execute_code"},
        headers=auth_headers,
    )
    # Registry rejects requesting capability for disabled tool
    assert res_cap.status_code == 403
    assert "disabled" in res_cap.json()["error"]["message"]


@pytest.mark.asyncio
async def test_tool_output_secret_leak_blocked(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """If a tool output contains a sensitive secret, it is blocked from reaching the agent."""
    # Write a file containing a leaked OpenAI key in the sandbox
    leaked_file = SANDBOX_DIR / "leaked_credentials.env"
    secret_key = "sk-proj-leakedSecretFromSystemDump999999999999999999999999"
    leaked_file.write_text(f"OPENAI_KEY={secret_key}", encoding="utf-8")

    try:
        res_ag = await client.post("/v1/agents/register", json={"name": "Scanner Agent", "allowed_tools": ["read_file"]}, headers=auth_headers)
        agent_id = res_ag.json()["id"]
        res_tsk = await client.post("/v1/tasks", json={"agent_id": agent_id}, headers=auth_headers)
        task_id = res_tsk.json()["id"]

        res_cap = await client.post(
            "/v1/capabilities/request",
            json={"agent_id": agent_id, "task_id": task_id, "tool_name": "read_file", "resource": "leaked_credentials.env"},
            headers=auth_headers,
        )
        cap_token = res_cap.json()["capability_token"]

        exec_payload = {
            "agent_id": agent_id,
            "task_id": task_id,
            "capability_token": cap_token,
            "parameters": {"path": "leaked_credentials.env"},
        }
        res_exec = await client.post("/v1/tools/read_file/execute", json=exec_payload, headers=auth_headers)
        assert res_exec.status_code == 502
        assert res_exec.json()["error"]["code"] == "RESPONSE_SECURITY_VIOLATION"
        assert secret_key not in res_exec.text
    finally:
        if leaked_file.exists():
            leaked_file.unlink()


"""Resource Exhaustion, Bounded Buffers, and DoS Defense Testing.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import asyncio
import pytest
from httpx import AsyncClient, ASGITransport

from app.agent_security.capability_manager import capability_manager
from app.agent_security.task_manager import task_manager
from app.core.exceptions import PrivGuardException
from app.database.models import Agent, Application
from app.main import app
from app.mcp.client import ProtectedMCPClient


@pytest.mark.asyncio
async def test_oversized_payload_rejected_by_middleware():
    """
    CRITICAL INVARIANT:
    Requests with Content-Length exceeding MAX_REQUEST_SIZE_BYTES (10 MB)
    MUST BE IMMEDIATELY REJECTED at the ASGI edge with HTTP 413 Payload Too Large.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Simulate an 11 MB request via Content-Length header without allocating memory
        headers = {
            "Content-Length": str(11 * 1024 * 1024),
            "Content-Type": "application/json",
            "X-API-Key": "test_key",
        }
        resp = await client.post("/v1/chat/completions", headers=headers, content=b"{}")
        assert resp.status_code == 413
        data = resp.json()
        assert data["error"]["code"] == "PAYLOAD_TOO_LARGE"
        assert "exceeds maximum allowed size" in data["error"]["message"]


@pytest.mark.asyncio
async def test_streaming_chunked_payload_exceeding_limit_aborted():
    """
    CRITICAL INVARIANT:
    Chunked streaming payloads that lack Content-Length but exceed 10 MB in cumulative bytes
    must be aborted mid-stream with HTTP 413.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Generate 11 chunks of 1 MB each (11 MB total)
        async def large_stream():
            one_mb = b"X" * (1024 * 1024)
            for _ in range(11):
                yield one_mb

        headers = {
            "Content-Type": "application/octet-stream",
            "X-API-Key": "test_key",
        }
        resp = await client.post("/v1/chat/completions", headers=headers, content=large_stream())
        assert resp.status_code == 413
        data = resp.json()
        assert data["error"]["code"] == "PAYLOAD_TOO_LARGE"


@pytest.mark.asyncio
async def test_runaway_agent_task_step_limit_enforced(chaos_db_session):
    """
    CRITICAL INVARIANT:
    Tasks must enforce a strict execution step budget (MAX_TASK_STEPS).
    If an agent loops indefinitely, the task must transition to STEP_LIMIT_EXCEEDED,
    revoke all active capabilities, and raise HTTP 429.
    """
    db = chaos_db_session
    app_id = "app_step_budget"
    agent_id = "agent_runaway_looper"

    app_rec = Application(id=app_id, name="LoopApp", api_key_hash="hash_loop", tenant_id="t1", is_active=True)
    agent_rec = Agent(id=agent_id, app_id=app_id, tenant_id="t1", name="Looper", status="ACTIVE")
    db.add(app_rec)
    db.add(agent_rec)
    await db.commit()

    # Create task with a small step budget of 3 steps
    task = await task_manager.create_task(
        db=db,
        agent_id=agent_id,
        app_id=app_id,
        ttl_seconds=300,
        max_steps=3,
    )
    assert task.step_count == 0
    assert task.max_steps == 3

    # Issue 10-use capability to the looping agent
    grant, raw_token = await capability_manager.issue_capability(
        db=db,
        agent_id=agent_id,
        task_id=task.id,
        app_id=app_id,
        tool_name="read_file",
        max_uses=10,
    )

    # Step 1, 2, 3 succeed
    for expected_step in range(1, 4):
        step_num = await task_manager.record_step(db=db, task_id=task.id, app_id=app_id)
        assert step_num == expected_step

    # Step 4 exceeds max_steps (3) -> Must raise TASK_STEP_LIMIT_EXCEEDED
    with pytest.raises(PrivGuardException) as exc_info:
        await task_manager.record_step(db=db, task_id=task.id, app_id=app_id)

    assert exc_info.value.status_code == 429
    assert exc_info.value.error_code == "TASK_STEP_LIMIT_EXCEEDED"

    # Verify task state transitioned to terminal
    await db.refresh(task)
    assert task.status == "STEP_LIMIT_EXCEEDED"

    # Verify associated capabilities were revoked automatically
    await db.refresh(grant)
    assert grant.is_revoked is True


@pytest.mark.asyncio
async def test_mcp_upstream_socket_timeout():
    """
    CRITICAL INVARIANT:
    An external MCP server hanging indefinitely must be cut off after the configured timeout
    (default: 15s, tested here with 0.1s), preventing socket starvation.
    """
    # Protected client with very aggressive 0.1s timeout
    client = ProtectedMCPClient(timeout=0.1, allow_test_loopback=True)

    # Calling a non-routable blackhole IP (10.255.255.1) to force timeout
    with pytest.raises(PrivGuardException) as exc_info:
        await client.list_tools(endpoint_url="http://10.255.255.1:8123/mcp")

    assert exc_info.value.status_code in (502, 504)
    assert "Failed to connect to MCP server" in exc_info.value.message

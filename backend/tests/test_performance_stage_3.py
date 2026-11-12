"""Performance and latency benchmarks for Stage 3 Broker and Capabilities."""

import gc
import time
import pytest
from httpx import AsyncClient
from app.approvals.approval_engine import compute_action_hash
from app.database.models import Application


@pytest.mark.asyncio
async def test_stage_3_latency_benchmarks(
    client: AsyncClient, test_app_record: Application, auth_headers: dict
):
    """Benchmarks capability issuance, validation, and tool execution mediation."""
    gc.collect()

    # 1. Action hash computation benchmark (pure CPU cryptographic operation)
    params = {"path": "document_123.pdf", "user": "alice", "action": "read"}
    hash_times = []
    for _ in range(100):
        t0 = time.perf_counter()
        compute_action_hash("read_file", "document_123.pdf", params)
        hash_times.append((time.perf_counter() - t0) * 1000)

    hash_times.sort()
    hash_p95 = hash_times[95]

    # Setup agent & task
    res_ag = await client.post("/v1/agents/register", json={"name": "Perf Agent"}, headers=auth_headers)
    agent_id = res_ag.json()["id"]
    res_tsk = await client.post("/v1/tasks", json={"agent_id": agent_id}, headers=auth_headers)
    task_id = res_tsk.json()["id"]

    # Warmup issuance
    await client.post(
        "/v1/capabilities/request",
        json={"agent_id": agent_id, "task_id": task_id, "tool_name": "search_web", "max_uses": 100},
        headers=auth_headers,
    )
    gc.collect()

    # 2. Capability issuance latency
    cap_times = []
    tokens = []
    for _ in range(20):
        t0 = time.perf_counter()
        res = await client.post(
            "/v1/capabilities/request",
            json={"agent_id": agent_id, "task_id": task_id, "tool_name": "search_web", "max_uses": 100},
            headers=auth_headers,
        )
        cap_times.append((time.perf_counter() - t0) * 1000)
        tokens.append(res.json()["capability_token"])

    cap_times.sort()
    cap_p95 = cap_times[int(len(cap_times) * 0.95)]

    # 3. Tool broker mediation latency (end-to-end mediated execution)
    # Warmup
    warmup_res = await client.post(
        "/v1/tools/search_web/execute",
        json={"agent_id": agent_id, "task_id": task_id, "capability_token": tokens[0], "parameters": {"query": "warmup"}},
        headers=auth_headers,
    )
    assert warmup_res.status_code == 200
    gc.collect()

    exec_times = []
    for i in range(20):
        payload = {
            "agent_id": agent_id,
            "task_id": task_id,
            "capability_token": tokens[i],
            "parameters": {"query": f"bench_{i}"},
        }
        t0 = time.perf_counter()
        res_exec = await client.post("/v1/tools/search_web/execute", json=payload, headers=auth_headers)
        exec_times.append((time.perf_counter() - t0) * 1000)
        assert res_exec.status_code == 200

    exec_times.sort()
    exec_p95 = exec_times[int(len(exec_times) * 0.95)]

    print(
        f"\n[STAGE 3 BENCHMARKS] Action Hash P95: {hash_p95:.4f}ms | "
        f"Cap Issuance P95: {cap_p95:.2f}ms | Tool Broker Exec P95: {exec_p95:.2f}ms"
    )

    assert hash_p95 < 1.0  # sub-millisecond (< 1.0 ms)
    assert cap_p95 < 250.0  # strict sub-250ms issuance contract
    assert exec_p95 < 400.0  # strict sub-400ms mediation contract


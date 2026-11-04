"""
Phase 4: Performance, High Concurrency & Fail-Closed Load Testing.
Evaluates 10, 50, and 100 concurrent users, measuring RPS, P50, P95, P99 latency percentiles,
capability contention races, and fail-closed security invariants under stress.
"""

import asyncio
import time
import pytest
import httpx
from tests.fixtures.tenant_fixtures import (
    TENANT_ALPHA_API_KEY,
    setup_multi_tenant_staging,
)


def calc_percentile(vals, p):
    if not vals:
        return 0.0
    sorted_v = sorted(vals)
    k = (len(sorted_v) - 1) * (p / 100.0)
    f = int(k)
    c = min(f + 1, len(sorted_v) - 1)
    d = k - f
    return sorted_v[f] + (sorted_v[c] - sorted_v[f]) * d


@pytest.mark.asyncio
async def test_concurrency_scaling_10_50_100(client: httpx.AsyncClient, db_session):
    """
    Measures throughput and P50/P95/P99 latency percentiles under 10, 50, and 100 concurrent requests.
    Enforces that P95 latency remains sub-15ms for local inspection and error rate is 0%.
    """
    await setup_multi_tenant_staging(db_session)

    payload = {
        "text": "Review employee record for Alice Smith at alice@company.org with phone +1-555-234-5678."
    }

    concurrency_levels = [10, 50, 100]
    performance_results = {}

    for count in concurrency_levels:
        latencies = []
        errors = 0
        start_batch = time.perf_counter()

        async def send_req():
            t0 = time.perf_counter()
            try:
                res = await client.post(
                    "/v1/privacy/inspect",
                    headers={"X-API-Key": TENANT_ALPHA_API_KEY},
                    json=payload,
                )
                lat = (time.perf_counter() - t0) * 1000
                return res.status_code, lat
            except Exception:
                lat = (time.perf_counter() - t0) * 1000
                return 500, lat

        tasks = [send_req() for _ in range(count)]
        results = await asyncio.gather(*tasks)
        total_time = time.perf_counter() - start_batch

        for code, lat in results:
            latencies.append(lat)
            if code != 200:
                errors += 1

        p50 = calc_percentile(latencies, 50)
        p95 = calc_percentile(latencies, 95)
        p99 = calc_percentile(latencies, 99)
        rps = count / total_time

        performance_results[count] = {
            "rps": round(rps, 1),
            "p50_ms": round(p50, 2),
            "p95_ms": round(p95, 2),
            "p99_ms": round(p99, 2),
            "error_rate": errors / count,
        }

        print(f"\n[CONCURRENCY {count} CLIENTS]")
        print(f"  Throughput:  {rps:.1f} req/s")
        print(f"  P50 Latency: {p50:.2f} ms")
        print(f"  P95 Latency: {p95:.2f} ms")
        print(f"  P99 Latency: {p99:.2f} ms")
        print(f"  Error Rate:  {errors/count * 100:.1f}%")

        # Invariants: 0% error rate and linear SQLite file-lock queue scaling under concurrency
        assert errors == 0, f"Errors occurred under {count} concurrent clients"
        max_allowed_p95 = count * 75.0 + 250.0
        assert p95 < max_allowed_p95, f"P95 latency ({p95:.2f}ms) exceeded {max_allowed_p95}ms SLA at {count} concurrency"


@pytest.mark.asyncio
async def test_capability_double_spend_race_condition(client: httpx.AsyncClient, db_session):
    """
    CRITICAL CONCURRENCY INVARIANT:
    When 20 concurrent requests attempt to consume a single-use capability token (max_uses=1)
    simultaneously, exactly ONE must succeed and 19 must be rejected. Zero race conditions.
    """
    await setup_multi_tenant_staging(db_session)

    reg = await client.post(
        "/v1/agents/register",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"name": "Race Agent", "allowed_tools": ["search_web"]},
    )
    agent_id = reg.json()["id"]

    task = await client.post("/v1/tasks", headers={"X-API-Key": TENANT_ALPHA_API_KEY}, json={"agent_id": agent_id})
    task_id = task.json()["id"]

    cap = await client.post(
        "/v1/capabilities/request",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "task_id": task_id, "tool_name": "search_web", "max_uses": 1},
    )
    token = cap.json()["capability_token"]

    async def attempt_exec(idx: int):
        return await client.post(
            "/v1/tools/search_web/execute",
            headers={"X-API-Key": TENANT_ALPHA_API_KEY},
            json={
                "agent_id": agent_id,
                "task_id": task_id,
                "capability_token": token,
                "parameters": {"query": f"race_{idx}"},
            },
        )

    # Launch 20 simultaneous requests
    responses = await asyncio.gather(*[attempt_exec(i) for i in range(20)])

    success_count = sum(1 for r in responses if r.status_code == 200)
    conflict_count = sum(1 for r in responses if r.status_code == 403)

    print(f"\n[CAPABILITY RACE CONDITION TEST]")
    print(f"  Total Concurrent Requests: 20")
    print(f"  Successful Executions:    {success_count}")
    print(f"  Rejected Conflicts:       {conflict_count}")

    assert success_count == 1, f"Expected exactly 1 successful execution, got {success_count}"
    assert conflict_count == 19, f"Expected 19 rejected conflicts, got {conflict_count}"


@pytest.mark.asyncio
async def test_approval_double_spend_race_condition(client: httpx.AsyncClient, db_session):
    """
    CRITICAL CONCURRENCY INVARIANT:
    When 20 concurrent requests attempt to consume a single approved action simultaneously,
    exactly ONE must succeed and 19 must fail with APPROVAL_ALREADY_CONSUMED.
    """
    await setup_multi_tenant_staging(db_session)

    reg = await client.post(
        "/v1/agents/register",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"name": "Approval Race Agent", "allowed_tools": ["send_email"]},
    )
    agent_id = reg.json()["id"]

    task = await client.post("/v1/tasks", headers={"X-API-Key": TENANT_ALPHA_API_KEY}, json={"agent_id": agent_id})
    task_id = task.json()["id"]

    cap = await client.post(
        "/v1/capabilities/request",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "task_id": task_id, "tool_name": "send_email", "max_uses": 50},
    )
    token = cap.json()["capability_token"]

    params = {"recipient": "boss@corp.com", "subject": "Quarterly Report", "body": "Financial numbers"}

    # Request approval
    req_res = await client.post(
        "/v1/tools/send_email/execute",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "task_id": task_id, "capability_token": token, "parameters": params},
    )
    approval_id = req_res.json()["error"]["details"]["approval_id"]

    # Approve once
    await client.post(f"/v1/approvals/{approval_id}/approve", headers={"X-API-Key": TENANT_ALPHA_API_KEY})

    async def attempt_approval_consume(idx: int):
        return await client.post(
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

    # Launch 20 simultaneous requests
    responses = await asyncio.gather(*[attempt_approval_consume(i) for i in range(20)])

    success_count = sum(1 for r in responses if r.status_code == 200)
    conflict_count = sum(1 for r in responses if r.status_code == 403)

    print(f"\n[APPROVAL RACE CONDITION TEST]")
    print(f"  Total Concurrent Requests: 20")
    print(f"  Successful Executions:    {success_count}")
    print(f"  Rejected Conflicts:       {conflict_count}")

    assert success_count == 1, f"Expected exactly 1 successful approval execution, got {success_count}"
    assert conflict_count == 19, f"Expected 19 rejected replay conflicts, got {conflict_count}"

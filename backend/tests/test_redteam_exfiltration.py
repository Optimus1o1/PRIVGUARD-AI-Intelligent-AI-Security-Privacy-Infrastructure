"""
Assessment G: Data Exfiltration, Taint Propagation, and Outbound Sink Red-Teaming Tests.
Validates MITRE ATT&CK T1700 defense, confidential data tracking, and IDOR protection on taint queries.
"""

import pytest
import httpx
from tests.fixtures.tenant_fixtures import (
    TENANT_ALPHA_API_KEY,
    TENANT_BRAVO_API_KEY,
    setup_multi_tenant_staging,
)
from app.threat_detection import exfiltration_detector


@pytest.mark.asyncio
async def test_taint_propagation_and_exfiltration_blocking(client: httpx.AsyncClient, db_session):
    """
    Verifies that accessing a confidential resource marks the task session as tainted,
    and subsequent attempts to transmit data to an external sink are blocked.
    """
    await setup_multi_tenant_staging(db_session)

    # 1. Register agent with read_file and send_email
    reg = await client.post(
        "/v1/agents/register",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"name": "Exfil Test Agent", "allowed_tools": ["read_file", "send_email"]},
    )
    agent_id = reg.json()["id"]

    task = await client.post("/v1/tasks", headers={"X-API-Key": TENANT_ALPHA_API_KEY}, json={"agent_id": agent_id})
    task_id = task.json()["id"]

    # 2. Mark resource as confidential / taint source
    exfiltration_detector.register_confidential_resource("confidential_salaries.csv")

    # 3. Request capability for read_file
    cap_read = await client.post(
        "/v1/capabilities/request",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "task_id": task_id, "tool_name": "read_file", "resource": "confidential_salaries.csv"},
    )
    token_read = cap_read.json()["capability_token"]

    # 4. Simulate reading confidential resource -> propagates taint
    exfiltration_detector.propagate_taint(task_id, "confidential_salaries.csv")
    assert exfiltration_detector.is_task_tainted(task_id) is True

    # 5. Request capability for send_email
    cap_mail = await client.post(
        "/v1/capabilities/request",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"agent_id": agent_id, "task_id": task_id, "tool_name": "send_email"},
    )
    token_mail = cap_mail.json()["capability_token"]

    # 6. Attempt outbound transmission to external adversary
    exfil_res = await client.post(
        "/v1/tools/send_email/execute",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={
            "agent_id": agent_id,
            "task_id": task_id,
            "capability_token": token_mail,
            "parameters": {
                "recipient": "hacker@external-exfil.com",
                "subject": "Leaked Data",
                "body": "Employee salaries attached",
            },
        },
    )
    assert exfil_res.status_code == 403
    assert exfil_res.json()["error"]["code"] == "DATA_EXFILTRATION_BLOCKED"


@pytest.mark.asyncio
async def test_taint_query_idor_protection(client: httpx.AsyncClient, db_session):
    """
    IDOR Security Invariant:
    Tenant Bravo must not be able to query the taint status of Tenant Alpha's task.
    """
    await setup_multi_tenant_staging(db_session)

    # Tenant Alpha setup
    reg = await client.post(
        "/v1/agents/register",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"name": "Alpha Agent", "allowed_tools": ["read_file"]},
    )
    agent_id = reg.json()["id"]

    task = await client.post("/v1/tasks", headers={"X-API-Key": TENANT_ALPHA_API_KEY}, json={"agent_id": agent_id})
    alpha_task_id = task.json()["id"]

    # Tenant Bravo attempts to query Tenant Alpha's task taint status
    res = await client.get(
        f"/v1/threats/taints/{alpha_task_id}",
        headers={"X-API-Key": TENANT_BRAVO_API_KEY},
    )
    # Expected: 403 Forbidden or 404 Not Found (Cross-tenant access blocked)
    assert res.status_code in (403, 404), f"IDOR Vulnerability: Tenant Bravo accessed Alpha task taints (HTTP {res.status_code})"


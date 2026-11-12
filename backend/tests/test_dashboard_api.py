"""Automated Tests for Dashboard Control Center Endpoints."""

import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from app.database.models import (
    Agent,
    AgentTask,
    Application,
    ApprovalRequest,
    AuditEvent,
    PolicyRule,
    ThreatEvent,
    utcnow,
)
from datetime import timedelta


@pytest.mark.asyncio
async def test_dashboard_summary_default_values(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
):
    """Clean app returns verified base metrics with PROTECTED status."""
    res = await client.get("/v1/dashboard/summary", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["security_status"] == "PROTECTED"
    assert data["protection_score"] >= 95
    assert data["total_requests"] == 0
    assert data["blocked_requests"] == 0
    assert data["threats_detected"] == 0
    assert data["active_agents"] == 0
    assert data["running_tasks"] == 0
    assert data["pending_approvals"] == 0


@pytest.mark.asyncio
async def test_dashboard_summary_with_live_records(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
    db_session: AsyncSession,
):
    """Metrics dynamically reflect database records and trigger status updates."""
    app_id = test_app_record.id

    # 1. Add audit events
    audit_clean = AuditEvent(
        request_id="req_1",
        app_id=app_id,
        event_type="AI_COMPLETION",
        action_taken="ALLOW",
        risk_level="LOW",
    )
    audit_blocked = AuditEvent(
        request_id="req_2",
        app_id=app_id,
        event_type="AI_COMPLETION",
        action_taken="BLOCK",
        risk_level="CRITICAL",
    )
    audit_redact = AuditEvent(
        request_id="req_3",
        app_id=app_id,
        event_type="AI_COMPLETION",
        action_taken="REDACT",
        risk_level="MEDIUM",
    )
    db_session.add_all([audit_clean, audit_blocked, audit_redact])

    # 2. Add threat events
    threat_crit = ThreatEvent(
        application_id=app_id,
        threat_type="DIRECT_PROMPT_INJECTION",
        severity="CRITICAL",
        confidence=0.98,
        rule_id="INJ_001",
        action_taken="BLOCK",
        content_hash="abc",
    )
    db_session.add(threat_crit)

    # 3. Add agent and task
    agent = Agent(app_id=app_id, name="AnalyzerBot", status="ACTIVE", allowed_tools="[]")
    db_session.add(agent)
    await db_session.flush()

    task = AgentTask(
        agent_id=agent.id,
        app_id=app_id,
        status="RUNNING",
        expires_at=utcnow() + timedelta(minutes=10),
    )
    db_session.add(task)
    await db_session.flush()

    # 4. Add pending approval

    appr = ApprovalRequest(
        task_id=task.id,
        agent_id=agent.id,
        app_id=app_id,
        tool_name="send_email",
        action_parameters="{}",
        action_hash="hash123",
        risk_level="HIGH",
        status="PENDING",
        expires_at=utcnow() + timedelta(minutes=5),
    )
    db_session.add(appr)
    await db_session.commit()

    # Query summary
    res = await client.get("/v1/dashboard/summary", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["total_requests"] == 3
    assert data["blocked_requests"] == 1
    assert data["pii_redactions"] == 1
    assert data["threats_detected"] == 1
    assert data["critical_threats"] == 1
    assert data["active_agents"] == 1
    assert data["running_tasks"] == 1
    assert data["pending_approvals"] == 1
    # Critical threat sets status to CRITICAL_ALERT
    assert data["security_status"] == "CRITICAL_ALERT"


@pytest.mark.asyncio
async def test_threat_statistics_endpoint(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
    db_session: AsyncSession,
):
    """Threat statistics returns breakdown by severity, type, and timeline."""
    app_id = test_app_record.id

    t1 = ThreatEvent(
        application_id=app_id,
        threat_type="DIRECT_PROMPT_INJECTION",
        severity="HIGH",
        confidence=0.9,
        rule_id="INJ_001",
        action_taken="BLOCK",
        content_hash="h1",
    )
    t2 = ThreatEvent(
        application_id=app_id,
        threat_type="DATA_EXFILTRATION",
        severity="CRITICAL",
        confidence=1.0,
        rule_id="EXFIL_001",
        action_taken="BLOCK",
        content_hash="h2",
    )
    db_session.add_all([t1, t2])
    await db_session.commit()

    res = await client.get("/v1/dashboard/threat-statistics", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["by_severity"]["HIGH"] >= 1
    assert data["by_severity"]["CRITICAL"] >= 1
    assert "DIRECT_PROMPT_INJECTION" in data["by_type"]
    assert "DATA_EXFILTRATION" in data["by_type"]
    assert len(data["recent_timeline"]) == 7


@pytest.mark.asyncio
async def test_system_health_endpoint(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
):
    """System health returns operational components and latency metrics."""
    res = await client.get("/v1/dashboard/system-health", headers=auth_headers)
    assert res.status_code == 200
    data = res.json()
    assert data["overall_status"] == "HEALTHY"
    assert len(data["components"]) == 5
    component_names = [c["name"] for c in data["components"]]
    assert any("Database" in n for n in component_names)
    assert any("Gateway" in n for n in component_names)
    assert any("Privacy" in n for n in component_names)
    assert any("Broker" in n for n in component_names)
    assert any("Threat Detection" in n for n in component_names)


@pytest.mark.asyncio
async def test_task_listing_endpoint(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
    db_session: AsyncSession,
):
    """GET /v1/tasks supports status filtering and returns task records."""
    app_id = test_app_record.id
    agent = Agent(app_id=app_id, name="TaskAgent", allowed_tools="[]")
    db_session.add(agent)
    await db_session.flush()

    t_running = AgentTask(
        agent_id=agent.id,
        app_id=app_id,
        status="RUNNING",
        expires_at=utcnow() + timedelta(minutes=10),
    )
    t_completed = AgentTask(
        agent_id=agent.id,
        app_id=app_id,
        status="COMPLETED",
        expires_at=utcnow() + timedelta(minutes=10),
    )
    db_session.add_all([t_running, t_completed])
    await db_session.commit()

    # List all
    res_all = await client.get("/v1/tasks", headers=auth_headers)
    assert res_all.status_code == 200
    assert len(res_all.json()) >= 2

    # Filter running
    res_running = await client.get("/v1/tasks?status=RUNNING", headers=auth_headers)
    assert res_running.status_code == 200
    assert all(t["status"] == "RUNNING" for t in res_running.json())


@pytest.mark.asyncio
async def test_policy_crud_endpoints(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
):
    """Policy CRUD allows adding/modifying custom rules while protecting security invariants."""
    # 1. Create valid custom rule
    create_payload = {
        "category": "CONFIDENTIAL",
        "action": "REQUIRE_APPROVAL",
        "risk_level": "HIGH",
        "description": "Require human authorization for confidential resources",
        "is_enabled": True,
    }
    create_res = await client.post("/v1/policies", json=create_payload, headers=auth_headers)
    assert create_res.status_code == 200
    rule_data = create_res.json()
    rule_id = rule_data["id"]
    assert rule_data["category"] == "CONFIDENTIAL"
    assert rule_data["action"] == "REQUIRE_APPROVAL"

    # 2. Invariant: Setting CRITICAL category to ALLOW must be blocked
    invalid_payload = {
        "category": "CRITICAL",
        "action": "ALLOW",
        "risk_level": "LOW",
        "description": "Attempt to bypass critical secrets check",
    }
    invalid_res = await client.post("/v1/policies", json=invalid_payload, headers=auth_headers)
    assert invalid_res.status_code == 400
    assert "invariant" in invalid_res.json()["error"]["message"].lower()

    # 3. Update rule
    update_res = await client.put(
        f"/v1/policies/{rule_id}",
        json={"action": "BLOCK", "risk_level": "CRITICAL"},
        headers=auth_headers,
    )
    assert update_res.status_code == 200
    assert update_res.json()["action"] == "BLOCK"

    # 4. Delete rule
    del_res = await client.delete(f"/v1/policies/{rule_id}", headers=auth_headers)
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "SUCCESS"

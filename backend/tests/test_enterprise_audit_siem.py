"""Adversarial security tests for Tamper-Evident Audit Ledger and SIEM Export (Tests 39-42)."""

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update

from app.core.exceptions import MCPSSRFError
from app.database.models import Organization, EnterpriseAuditEvent, utcnow
from app.enterprise.audit import EnterpriseAuditLedger

ORG_AUDIT = "org_audit_test"


@pytest_asyncio.fixture
async def setup_audit_org(db_session: AsyncSession):
    org = Organization(
        id=ORG_AUDIT,
        slug="audit-test",
        name="Audit Test Org",
        status="ACTIVE",
    )
    db_session.add(org)
    await db_session.commit()


@pytest.mark.asyncio
async def test_39_valid_hash_chain_verifies(db_session: AsyncSession, setup_audit_org):
    """Test 39: Consecutive audit events form an intact cryptographically verifiable SHA-256 chain."""
    # Record sequence of events
    ev1 = await EnterpriseAuditLedger.record_event(
        db=db_session,
        tenant_id=ORG_AUDIT,
        action="USER_LOGIN",
        actor_type="USER",
        actor_id="usr_admin",
        resource_type="SESSION",
        resource_id="sess_1",
        details={"ip": "198.51.100.1"},
    )
    ev2 = await EnterpriseAuditLedger.record_event(
        db=db_session,
        tenant_id=ORG_AUDIT,
        action="POLICY_DEPLOYED",
        actor_type="USER",
        actor_id="usr_admin",
        resource_type="POLICY_BUNDLE",
        resource_id="pol_1",
        details={"version": 1},
    )
    ev3 = await EnterpriseAuditLedger.record_event(
        db=db_session,
        tenant_id=ORG_AUDIT,
        action="AGENT_REGISTERED",
        actor_type="USER",
        actor_id="usr_admin",
        resource_type="AGENT",
        resource_id="agent_1",
        details={"name": "Agent 1"},
    )

    # Verify link hashes
    assert ev2.previous_event_hash == ev1.event_hash
    assert ev3.previous_event_hash == ev2.event_hash

    is_valid, violations = await EnterpriseAuditLedger.verify_chain_integrity(db_session, ORG_AUDIT)
    assert is_valid is True
    assert len(violations) == 0


@pytest.mark.asyncio
async def test_40_tampered_audit_record_detected(db_session: AsyncSession, setup_audit_org):
    """Test 40: Any alteration of an existing audit event breaks hash chain verification."""
    # Create two events
    ev1 = await EnterpriseAuditLedger.record_event(
        db=db_session,
        tenant_id=ORG_AUDIT,
        action="USER_LOGIN",
        actor_type="USER",
        actor_id="usr_admin",
        resource_type="SESSION",
        resource_id="sess_tamper_1",
        details={"ip": "198.51.100.1"},
    )
    ev2 = await EnterpriseAuditLedger.record_event(
        db=db_session,
        tenant_id=ORG_AUDIT,
        action="POLICY_DEPLOYED",
        actor_type="USER",
        actor_id="usr_admin",
        resource_type="POLICY_BUNDLE",
        resource_id="pol_tamper_1",
        details={"version": 1},
    )

    # Malicious actor tampers with ev2 in the database directly
    ev2.details_json = '{"version":999}'
    await db_session.commit()

    # Chain verification must now detect tamper!
    is_valid, violations = await EnterpriseAuditLedger.verify_chain_integrity(db_session, ORG_AUDIT)
    assert is_valid is False
    assert len(violations) > 0
    assert any("Tamper detected" in v for v in violations)


def test_41_siem_export_ssrf_destination_blocked():
    """Test 41: Export destination targeting loopback or private networks is blocked."""
    # Attempting to export to localhost/AWS metadata
    with pytest.raises(MCPSSRFError):
        EnterpriseAuditLedger.validate_siem_export_destination("http://127.0.0.1:8080/siem")

    with pytest.raises(MCPSSRFError):
        EnterpriseAuditLedger.validate_siem_export_destination("http://169.254.169.254/latest/meta-data")

    with pytest.raises(MCPSSRFError):
        EnterpriseAuditLedger.validate_siem_export_destination("http://localhost:9000/telemetry")


@pytest.mark.asyncio
async def test_42_content_free_redacted_details(db_session: AsyncSession, setup_audit_org):
    """Test 42: Raw payload data ending in 'raw' is excluded from audit ledger details."""
    ev = await EnterpriseAuditLedger.record_event(
        db=db_session,
        tenant_id=ORG_AUDIT,
        action="TOOL_EXECUTED",
        actor_type="AGENT",
        actor_id="agent_1",
        resource_type="TOOL",
        resource_id="read_file",
        details={
            "tool_name": "read_file",
            "content_raw": "SUPER_SECRET_UNENCRYPTED_DATA",
            "status": "SUCCESS",
        },
    )
    assert "content_raw" not in ev.details_json
    assert "SUPER_SECRET_UNENCRYPTED_DATA" not in ev.details_json
    assert "tool_name" in ev.details_json


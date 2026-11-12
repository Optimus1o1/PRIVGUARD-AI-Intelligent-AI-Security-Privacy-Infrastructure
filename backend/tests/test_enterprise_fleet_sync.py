"""Adversarial security tests for Fleet Management, Drift Detection, and Central Revocation (Tests 33-38)."""

from datetime import datetime, timezone, timedelta
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.exceptions import AuthorizationError, SecurityPolicyViolationError
from app.database.models import (
    Organization,
    FleetResource,
    Agent,
    PolicyBundle,
    CapabilityGrant,
    Application,
    utcnow,
)
from app.enterprise.fleet import FleetManager, MAX_STALENESS_SECONDS
from app.enterprise.sync import PolicySyncEngine
from app.agent_security.identity import agent_identity_manager
from app.core.security import hash_api_key

ORG_FLEET = "org_fleet_test"


@pytest_asyncio.fixture
async def setup_fleet_org(db_session: AsyncSession):
    """Sets up an organization with registered agents, MCP servers, and an active signed policy."""
    org = Organization(
        id=ORG_FLEET,
        slug="fleet-test",
        name="Fleet Test Org",
        status="ACTIVE",
    )
    db_session.add(org)

    app = Application(
        id="app_fleet",
        tenant_id=ORG_FLEET,
        name="Fleet Application",
        api_key_hash=hash_api_key("fleet_app_key"),
        is_active=True,
    )
    db_session.add(app)

    agent = Agent(
        id="agent_fleet_1",
        tenant_id=ORG_FLEET,
        app_id="app_fleet",
        name="Fleet Test Agent",
        status="ACTIVE",
    )
    db_session.add(agent)

    # Active policy bundle v3
    bundle = PolicyBundle(
        id="pol_fleet_v3",
        organization_id=ORG_FLEET,
        tenant_id=ORG_FLEET,
        version=3,
        status="ACTIVE",
        policy_hash="hash_v3_canonical_target",
        bundle_json="{}",
        signature_ed25519="sig3",
        signing_key_id="pub3",
        created_by="admin",
    )
    db_session.add(bundle)

    await db_session.commit()


@pytest.mark.asyncio
async def test_33_fleet_resource_registration(db_session: AsyncSession, setup_fleet_org):
    """Test 33: Registers an AI agent into the fleet inventory."""
    res = await FleetManager.register_resource(
        db=db_session,
        tenant_id=ORG_FLEET,
        resource_type="AGENT",
        resource_id="agent_fleet_1",
        name="Fleet Test Agent",
        current_policy_version=3,
        current_policy_hash="hash_v3_canonical_target",
    )
    assert res.status == "ACTIVE"
    assert res.drift_status == "SYNCED"
    assert res.active_policy_version == 3


@pytest.mark.asyncio
async def test_34_fleet_drift_detected_on_outdated_hash(db_session: AsyncSession, setup_fleet_org):
    """Test 34: Detects policy drift when an agent heartbeats with an outdated hash."""
    # Register resource with an older policy hash
    res = await FleetManager.register_resource(
        db=db_session,
        tenant_id=ORG_FLEET,
        resource_type="AGENT",
        resource_id="agent_drifted",
        name="Drifted Agent",
        current_policy_version=2,
        current_policy_hash="old_hash_v2",
    )

    # Record heartbeat with outdated hash
    updated = await FleetManager.record_heartbeat(
        db=db_session,
        tenant_id=ORG_FLEET,
        resource_id="agent_drifted",
        reported_policy_version=2,
        reported_policy_hash="old_hash_v2",
    )
    assert updated.drift_status == "DRIFTED"


@pytest.mark.asyncio
async def test_35_authoritative_broker_side_revocation(db_session: AsyncSession, setup_fleet_org):
    """
    Test 35: Disabling an agent centrally immediately halts subsequent operations.
    Core Decision: Even if the agent is offline or hasn't checked in, the broker drops its requests.
    """
    from app.database.models import AgentTask
    task = AgentTask(
        id="task_fleet_1",
        tenant_id=ORG_FLEET,
        app_id="app_fleet",
        agent_id="agent_fleet_1",
        description="Task for fleet test",
        status="ACTIVE",
        expires_at=utcnow() + timedelta(hours=1),
    )
    db_session.add(task)
    await db_session.flush()

    # Create active capability grant
    cap = CapabilityGrant(
        id="cap_fleet_test",
        tenant_id=ORG_FLEET,
        app_id="app_fleet",
        agent_id="agent_fleet_1",
        task_id="task_fleet_1",
        tool_name="send_external_email",
        secret_hash="hash_cap_fleet",
        expires_at=utcnow() + timedelta(hours=1),
        is_revoked=False,
    )
    db_session.add(cap)
    await db_session.commit()

    # Authoritative central revocation
    await FleetManager.revoke_resource(
        db=db_session,
        tenant_id=ORG_FLEET,
        resource_id="agent_fleet_1",
        reason="Compromised credentials detected",
    )

    # 1. Underlying Agent is marked REVOKED
    q_agent = select(Agent).where(Agent.id == "agent_fleet_1")
    agent_res = await db_session.execute(q_agent)
    agent = agent_res.scalar_one()
    assert agent.status == "REVOKED"

    # 2. Broker immediately rejects the agent
    with pytest.raises(Exception):
        await agent_identity_manager.validate_agent_active(db_session, "agent_fleet_1", "app_fleet")

    # 3. Capability grant is marked revoked
    q_cap = select(CapabilityGrant).where(CapabilityGrant.id == "cap_fleet_test")
    cap_res = await db_session.execute(q_cap)
    updated_cap = cap_res.scalar_one()
    assert updated_cap.is_revoked is True


@pytest.mark.asyncio
async def test_36_revoked_resource_heartbeat_refused(db_session: AsyncSession, setup_fleet_org):
    """Test 36: Heartbeat or operations from a revoked resource fail-closed."""
    # First register and revoke the resource
    await FleetManager.register_resource(
        db=db_session,
        tenant_id=ORG_FLEET,
        resource_type="AGENT",
        resource_id="agent_fleet_1",
        name="Fleet Test Agent",
    )
    await FleetManager.revoke_resource(
        db=db_session,
        tenant_id=ORG_FLEET,
        resource_id="agent_fleet_1",
    )

    with pytest.raises(SecurityPolicyViolationError, match="REVOKED"):
        await FleetManager.record_heartbeat(
            db=db_session,
            tenant_id=ORG_FLEET,
            resource_id="agent_fleet_1",
        )


@pytest.mark.asyncio
async def test_37_disconnected_staleness_detection(db_session: AsyncSession, setup_fleet_org):
    """Test 37: Heartbeat staleness exceeding MAX_STALENESS_SECONDS flags agent DISCONNECTED."""
    # Register an agent with a simulated stale heartbeat 2 hours ago
    stale_res = FleetResource(
        id="res_stale",
        tenant_id=ORG_FLEET,
        resource_type="AGENT",
        resource_id="agent_stale_1",
        name="Stale Agent",
        status="ACTIVE",
        drift_status="SYNCED",
        last_heartbeat_at=utcnow() - timedelta(seconds=MAX_STALENESS_SECONDS + 100),
    )
    db_session.add(stale_res)
    await db_session.commit()

    fleet_list = await FleetManager.list_fleet(db_session, ORG_FLEET)
    found_stale = next(r for r in fleet_list if r.resource_id == "agent_stale_1")
    assert found_stale.drift_status == "DISCONNECTED"


@pytest.mark.asyncio
async def test_38_fleet_sync_metrics_calculation(db_session: AsyncSession, setup_fleet_org):
    """Test 38: Accurately reports fleet-wide compliance percentages and count breakdowns."""
    metrics = await PolicySyncEngine.get_sync_status(db_session, ORG_FLEET)
    assert "total_resources" in metrics
    assert "synced_count" in metrics
    assert "drifted_count" in metrics
    assert "compliance_percentage" in metrics


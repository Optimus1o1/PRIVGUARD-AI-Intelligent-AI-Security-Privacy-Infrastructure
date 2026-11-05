"""Tests for User-Controlled AI Memory Proposals & Consent Workflows."""

import pytest
from datetime import datetime, timezone, timedelta
from app.core.exceptions import MemoryNotFoundError, MemoryPermissionError, PrivGuardException
from app.database.models import Application, AgentIdentity, MemoryProposal, MemoryRecord
from app.memory.vault import memory_vault
from app.memory.permissions import memory_permission_engine


@pytest.fixture
async def setup_consent_env(db_session):
    """Sets up an application, owner, and agent with propose_write permission."""
    app = Application(
        id="app_consent_test",
        name="Consent App",
        api_key_hash="hash_consent",
        is_active=True,
    )
    db_session.add(app)

    agent = AgentIdentity(
        id="ag_consent_1",
        app_id=app.id,
        name="Assistant Agent",
        status="ACTIVE",
    )
    db_session.add(agent)
    await db_session.commit()

    owner_id = "user_consent_alice"

    # Grant agent permission to propose writes
    await memory_permission_engine.grant_permission(
        db=db_session,
        app_id=app.id,
        owner_id=owner_id,
        agent_id=agent.id,
        operation="memory.propose_write",
        category="USER_PREFERENCES",
    )

    return {"app": app, "agent": agent, "owner_id": owner_id}


@pytest.mark.asyncio
async def test_agent_propose_memory_awaiting_consent(db_session, setup_consent_env):
    """Verifies that an agent proposal enters PROPOSED state and does not create an active memory record."""
    env = setup_consent_env
    app = env["app"]
    agent = env["agent"]
    owner_id = env["owner_id"]

    proposal = await memory_vault.propose_memory(
        db=db_session,
        app_id=app.id,
        owner_id=owner_id,
        agent_id=agent.id,
        task_id="tsk_001",
        key="User prefers dark mode",
        value="Dark mode UI theme preferred across all sessions.",
        category="USER_PREFERENCES",
    )

    assert proposal.id.startswith("prop_")
    assert proposal.status == "PROPOSED"
    assert proposal.risk_level == "LOW"

    # Verify no active memory record exists yet
    with pytest.raises(MemoryNotFoundError):
        await memory_vault.get_memory(db_session, app.id, owner_id, proposal.id)


@pytest.mark.asyncio
async def test_user_approval_encrypts_and_activates_memory(db_session, setup_consent_env):
    """Verifies that human approval moves proposal to APPROVED and creates active encrypted memory."""
    env = setup_consent_env
    app = env["app"]
    agent = env["agent"]
    owner_id = env["owner_id"]

    proposal = await memory_vault.propose_memory(
        db=db_session,
        app_id=app.id,
        owner_id=owner_id,
        agent_id=agent.id,
        task_id="tsk_002",
        key="Framework Preference",
        value="Client exclusively develops with Next.js App Router.",
        category="USER_PREFERENCES",
    )

    # User approves proposal
    record = await memory_vault.approve_proposal(
        db=db_session,
        app_id=app.id,
        owner_id=owner_id,
        proposal_id=proposal.id,
        retention_days=30,
    )

    assert record.status == "ACTIVE"
    assert record.provenance == "AI_PROPOSED"
    assert record.retention_days == 30

    # User can now retrieve and decrypt it
    retrieved = await memory_vault.get_memory(db_session, app.id, owner_id, record.id)
    assert retrieved["value"] == "Client exclusively develops with Next.js App Router."
    assert retrieved["category"] == "USER_PREFERENCES"


@pytest.mark.asyncio
async def test_user_rejection_blocks_memory_storage(db_session, setup_consent_env):
    """Verifies that rejecting a proposal permanently marks it REJECTED and stores no memory."""
    env = setup_consent_env
    app = env["app"]
    agent = env["agent"]
    owner_id = env["owner_id"]

    proposal = await memory_vault.propose_memory(
        db=db_session,
        app_id=app.id,
        owner_id=owner_id,
        agent_id=agent.id,
        task_id="tsk_003",
        key="Unwanted Observation",
        value="User spent 3 hours browsing external links.",
        category="USER_PREFERENCES",
    )

    rejected = await memory_vault.reject_proposal(
        db=db_session,
        app_id=app.id,
        owner_id=owner_id,
        proposal_id=proposal.id,
        reason="Irrelevant tracking",
    )

    assert rejected.status == "REJECTED"

    # Cannot approve a rejected proposal
    with pytest.raises(PrivGuardException) as exc_info:
        await memory_vault.approve_proposal(
            db=db_session,
            app_id=app.id,
            owner_id=owner_id,
            proposal_id=proposal.id,
        )
    assert exc_info.value.error_code == "PROPOSAL_INVALID_STATE"


@pytest.mark.asyncio
async def test_cross_user_approval_prevented(db_session, setup_consent_env):
    """Verifies that User B cannot approve a proposal created for User A."""
    env = setup_consent_env
    app = env["app"]
    agent = env["agent"]
    owner_alice = env["owner_id"]
    owner_bob = "user_consent_bob"

    proposal = await memory_vault.propose_memory(
        db=db_session,
        app_id=app.id,
        owner_id=owner_alice,
        agent_id=agent.id,
        task_id="tsk_004",
        key="Alice's private secret",
        value="Alice prefers secret meetings at 4 PM.",
        category="USER_PREFERENCES",
    )

    # Bob attempts to approve Alice's proposal
    with pytest.raises(MemoryNotFoundError):
        await memory_vault.approve_proposal(
            db=db_session,
            app_id=app.id,
            owner_id=owner_bob,
            proposal_id=proposal.id,
        )

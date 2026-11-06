"""High-Concurrency and Race Condition Validation Under Chaos.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import asyncio
from datetime import datetime, timedelta, timezone
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_security.capability_manager import capability_manager
from app.agent_security.identity import agent_identity_manager
from app.agent_security.task_manager import task_manager
from app.agent_security.tool_broker import ToolBroker
from app.approvals.approval_engine import approval_engine
from app.core.exceptions import PrivGuardException
from app.database.models import Agent, Application, ApprovalRequest, CapabilityGrant, utcnow


@pytest.mark.asyncio
async def test_concurrent_approval_consumption_anti_replay(chaos_db_factory):
    """
    CRITICAL INVARIANT:
    When 10 concurrent requests simultaneously attempt to consume the SAME approval,
    atomic SQL Compare-And-Swap (CAS) guarantees that EXACTLY ONE succeeds.
    All 9 competing requests MUST fail with APPROVAL_ALREADY_CONSUMED.
    """
    app_id = "app_approval_race"
    tool_name = "deploy_contract"
    params = {"network": "mainnet", "amount": 100}

    # Setup Application and approved request
    async with chaos_db_factory() as db:
        app_rec = Application(id=app_id, name="TestApp", api_key_hash="hash_race_app", tenant_id="t1", is_active=True)
        db.add(app_rec)
        await db.commit()

        req = await approval_engine.create_request(
            db=db,
            task_id="task_race_1",
            agent_id="agent_race_1",
            app_id=app_id,
            tool_name=tool_name,
            target_resource="mainnet",
            parameters=params,
            risk_level="CRITICAL",
        )
        # Approve request
        await approval_engine.approve(db=db, approval_id=req.id, app_id=app_id)
        approval_id = req.id

    # Launch 10 concurrent consumption attempts across isolated worker sessions
    success_count = 0
    failure_count = 0

    async def attempt_consume():
        nonlocal success_count, failure_count
        try:
            async with chaos_db_factory() as worker_db:
                await approval_engine.verify_and_consume(
                    db=worker_db,
                    approval_id=approval_id,
                    tool_name=tool_name,
                    target_resource="mainnet",
                    parameters=params,
                    app_id=app_id,
                )
                success_count += 1
        except PrivGuardException as exc:
            if exc.error_code == "APPROVAL_ALREADY_CONSUMED":
                failure_count += 1
            else:
                raise

    await asyncio.gather(*(attempt_consume() for _ in range(10)))

    assert success_count == 1, f"Expected exactly 1 consumption to succeed, got {success_count}"
    assert failure_count == 9, f"Expected 9 consumption attempts to be rejected, got {failure_count}"


@pytest.mark.asyncio
async def test_concurrent_capability_consumption_single_use(chaos_db_factory):
    """
    CRITICAL INVARIANT:
    When 10 concurrent requests simultaneously attempt to consume a 1-use capability token,
    atomic SQL CAS guarantees that EXACTLY ONE succeeds.
    The other 9 MUST fail with CAPABILITY_MAX_USES_EXCEEDED.
    """
    app_id = "app_cap_race"
    agent_id = "agent_cap_race"
    task_id = "task_cap_race"

    async with chaos_db_factory() as db:
        app_rec = Application(id=app_id, name="TestApp", api_key_hash="hash_cap_app", tenant_id="t1", is_active=True)
        agent_rec = Agent(id=agent_id, app_id=app_id, tenant_id="t1", name="Worker", status="ACTIVE")
        db.add(app_rec)
        db.add(agent_rec)
        await db.commit()

        task = await task_manager.create_task(db=db, agent_id=agent_id, app_id=app_id, ttl_seconds=300)

        # Issue 1-use capability
        grant, raw_token = await capability_manager.issue_capability(
            db=db,
            agent_id=agent_id,
            task_id=task.id,
            app_id=app_id,
            tool_name="read_file",
            max_uses=1,
        )

    success_count = 0
    failure_count = 0

    async def attempt_use():
        nonlocal success_count, failure_count
        try:
            async with chaos_db_factory() as worker_db:
                await capability_manager.validate_and_consume(
                    db=worker_db,
                    raw_secret=raw_token,
                    expected_tool="read_file",
                    expected_agent_id=agent_id,
                    expected_task_id=task.id,
                    expected_app_id=app_id,
                    consume=True,
                )
                success_count += 1
        except PrivGuardException as exc:
            if exc.error_code == "CAPABILITY_MAX_USES_EXCEEDED":
                failure_count += 1
            else:
                raise

    await asyncio.gather(*(attempt_use() for _ in range(10)))

    assert success_count == 1, f"Expected exactly 1 capability consumption to succeed, got {success_count}"
    assert failure_count == 9, f"Expected 9 capability uses to be rejected, got {failure_count}"


@pytest.mark.asyncio
async def test_mid_task_agent_revocation_race(chaos_db_session: AsyncSession):
    """
    CRITICAL INVARIANT:
    If an agent is active when a task starts, but an administrator revokes the agent
    in PostgreSQL during the task, any subsequent tool execution MUST BE REJECTED.
    """
    db = chaos_db_session
    app_id = "app_midtask_rev"
    agent_id = "agent_midtask_rev"

    app_rec = Application(id=app_id, name="App", api_key_hash="hash_mid", tenant_id="t1", is_active=True)
    agent_rec = Agent(id=agent_id, app_id=app_id, tenant_id="t1", name="Worker", status="ACTIVE", allowed_tools='["read_file"]')
    db.add(app_rec)
    db.add(agent_rec)
    await db.commit()

    task = await task_manager.create_task(db=db, agent_id=agent_id, app_id=app_id, ttl_seconds=300)

    # Verify agent active before revocation
    agent_check = await agent_identity_manager.validate_agent_active(db, agent_id, app_id)
    assert agent_check.status == "ACTIVE"

    # Administrator revokes agent
    agent_rec.status = "REVOKED"
    await db.commit()

    # Next tool check MUST fail closed
    with pytest.raises(PrivGuardException) as exc_info:
        await agent_identity_manager.validate_agent_active(db, agent_id, app_id)

    assert exc_info.value.status_code == 403
    assert exc_info.value.error_code == "AGENT_NOT_ACTIVE"


@pytest.mark.asyncio
async def test_task_expiration_race(chaos_db_session: AsyncSession):
    """
    CRITICAL INVARIANT:
    A task whose expiration timestamp has passed MUST fail validation and revoke its resources.
    """
    db = chaos_db_session
    app_id = "app_expire_race"
    agent_id = "agent_expire_race"

    app_rec = Application(id=app_id, name="App", api_key_hash="hash_exp", tenant_id="t1", is_active=True)
    agent_rec = Agent(id=agent_id, app_id=app_id, tenant_id="t1", name="Worker", status="ACTIVE")
    db.add(app_rec)
    db.add(agent_rec)
    await db.commit()

    # Create task with negative TTL (already expired)
    task = await task_manager.create_task(db=db, agent_id=agent_id, app_id=app_id, ttl_seconds=-10)

    with pytest.raises(PrivGuardException) as exc_info:
        await task_manager.validate_task_active(db, task.id, app_id)

    assert exc_info.value.status_code == 403
    assert exc_info.value.error_code == "TASK_EXPIRED"

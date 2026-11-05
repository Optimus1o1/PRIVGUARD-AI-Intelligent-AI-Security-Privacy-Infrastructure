"""Tests for PRIVGUARD AI Memory Permissions & Tenant Isolation."""

import pytest
from app.core.exceptions import MemoryNotFoundError, MemoryPermissionError
from app.database.models import Application, AgentIdentity
from app.memory.vault import memory_vault
from app.memory.permissions import memory_permission_engine


@pytest.fixture
async def setup_perm_env(db_session):
    app1 = Application(id="app_tenant_1", name="App One", api_key_hash="hash_1", is_active=True)
    app2 = Application(id="app_tenant_2", name="App Two", api_key_hash="hash_2", is_active=True)
    db_session.add_all([app1, app2])

    agent1 = AgentIdentity(id="ag_tenant_1", app_id=app1.id, name="Agent 1", status="ACTIVE")
    agent2 = AgentIdentity(id="ag_tenant_2", app_id=app2.id, name="Agent 2", status="ACTIVE")
    db_session.add_all([agent1, agent2])
    await db_session.commit()

    return {"app1": app1, "app2": app2, "agent1": agent1, "agent2": agent2}


@pytest.mark.asyncio
async def test_default_deny_agent_cannot_propose_or_read(db_session, setup_perm_env):
    """Verifies that agents have zero access by default without explicit permission grant."""
    env = setup_perm_env
    app = env["app1"]
    agent = env["agent1"]
    owner_id = "user_default_deny"

    # Agent attempts to propose write without permission
    with pytest.raises(MemoryPermissionError) as exc_info:
        await memory_vault.propose_memory(
            db=db_session,
            app_id=app.id,
            owner_id=owner_id,
            agent_id=agent.id,
            task_id="tsk_denied",
            key="Sneaky observation",
            value="Attempting unauthorized storage",
        )
    assert exc_info.value.error_code == "MEMORY_ACCESS_DENIED"


@pytest.mark.asyncio
async def test_category_scoped_permissions(db_session, setup_perm_env):
    """Verifies that an agent granted permission on USER_PREFERENCES cannot access WORK_CONTEXT."""
    env = setup_perm_env
    app = env["app1"]
    agent = env["agent1"]
    owner_id = "user_category_scoped"

    # Grant agent permission ONLY for USER_PREFERENCES
    await memory_permission_engine.grant_permission(
        db=db_session,
        app_id=app.id,
        owner_id=owner_id,
        agent_id=agent.id,
        operation="memory.read",
        category="USER_PREFERENCES",
    )

    # Create two memories: one USER_PREFERENCES, one WORK_CONTEXT
    mem_pref = await memory_vault.create_memory(
        db=db_session,
        app_id=app.id,
        owner_id=owner_id,
        key="Font size preference",
        value="14px font size preferred",
        category="USER_PREFERENCES",
    )
    mem_work = await memory_vault.create_memory(
        db=db_session,
        app_id=app.id,
        owner_id=owner_id,
        key="Q3 revenue target",
        value="Confidential internal projection: $5M ARR",
        category="WORK_CONTEXT",
    )

    # Agent reads USER_PREFERENCES -> SUCCESS
    read_pref = await memory_vault.get_memory(
        db=db_session,
        app_id=app.id,
        owner_id=owner_id,
        memory_id=mem_pref.id,
        agent_id=agent.id,
    )
    assert read_pref["value"] == "14px font size preferred"

    # Agent reads WORK_CONTEXT -> FORBIDDEN
    with pytest.raises(MemoryPermissionError):
        await memory_vault.get_memory(
            db=db_session,
            app_id=app.id,
            owner_id=owner_id,
            memory_id=mem_work.id,
            agent_id=agent.id,
        )


@pytest.mark.asyncio
async def test_cross_user_isolation(db_session, setup_perm_env):
    """Verifies that User A's agent cannot read User B's memories even with matching category permissions."""
    env = setup_perm_env
    app = env["app1"]
    agent = env["agent1"]
    user_a = "user_alice_isolated"
    user_b = "user_bob_isolated"

    # Grant agent permission for user_a
    await memory_permission_engine.grant_permission(
        db=db_session,
        app_id=app.id,
        owner_id=user_a,
        agent_id=agent.id,
        operation="memory.read",
    )

    # User B creates a memory
    mem_b = await memory_vault.create_memory(
        db=db_session,
        app_id=app.id,
        owner_id=user_b,
        key="Bob's secret preference",
        value="Secret value",
        category="USER_PREFERENCES",
    )

    # Agent attempting to read mem_b under user_a scope -> 404 (memory does not exist for user_a)
    with pytest.raises(MemoryNotFoundError):
        await memory_vault.get_memory(
            db=db_session,
            app_id=app.id,
            owner_id=user_a,
            memory_id=mem_b.id,
            agent_id=agent.id,
        )


@pytest.mark.asyncio
async def test_cross_tenant_isolation(db_session, setup_perm_env):
    """Verifies that Application Two cannot query or decrypt Application One memories."""
    env = setup_perm_env
    app1 = env["app1"]
    app2 = env["app2"]
    owner_id = "user_shared_username"

    mem1 = await memory_vault.create_memory(
        db=db_session,
        app_id=app1.id,
        owner_id=owner_id,
        key="App 1 secret",
        value="Valuable IP",
        category="PROJECT_CONTEXT",
    )

    # App 2 attempts to get App 1's memory
    with pytest.raises(MemoryNotFoundError):
        await memory_vault.get_memory(
            db=db_session,
            app_id=app2.id,
            owner_id=owner_id,
            memory_id=mem1.id,
        )


@pytest.mark.asyncio
async def test_revoking_permission_blocks_subsequent_access(db_session, setup_perm_env):
    """Verifies that revoking a granted permission immediately blocks access."""
    env = setup_perm_env
    app = env["app1"]
    agent = env["agent1"]
    owner_id = "user_revoke_test"

    perm = await memory_permission_engine.grant_permission(
        db=db_session,
        app_id=app.id,
        owner_id=owner_id,
        agent_id=agent.id,
        operation="memory.read",
        category="USER_PREFERENCES",
    )

    mem = await memory_vault.create_memory(
        db=db_session,
        app_id=app.id,
        owner_id=owner_id,
        key="Preferred beverage",
        value="Matcha green tea",
        category="USER_PREFERENCES",
    )

    # Verify initially authorized
    res = await memory_vault.get_memory(db_session, app.id, owner_id, mem.id, agent_id=agent.id)
    assert res["value"] == "Matcha green tea"

    # Revoke permission
    perm.is_granted = False
    await db_session.commit()

    # Verify access now blocked
    with pytest.raises(MemoryPermissionError):
        await memory_vault.get_memory(db_session, app.id, owner_id, mem.id, agent_id=agent.id)

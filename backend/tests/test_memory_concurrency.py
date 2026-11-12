"""Tests for Memory Vault Concurrency, CAS Race Conditions, and Single-Use Capability Consumption."""

import pytest
import asyncio
from app.core.exceptions import PrivGuardException
from app.database.models import Application, AgentIdentity, CapabilityGrant, ensure_utc
from app.memory.vault import memory_vault
from app.memory.retrieval import memory_retrieval_service
from app.memory.permissions import memory_permission_engine
from app.agent_security.capability_manager import capability_manager
from datetime import datetime, timezone, timedelta


@pytest.fixture
async def setup_concurrency_env(db_session):
    app = Application(id="app_concurrency", name="Concurrency App", api_key_hash="hash_c", is_active=True)
    agent = AgentIdentity(id="ag_concurrency", app_id=app.id, name="Concurrency Agent", status="ACTIVE")
    db_session.add_all([app, agent])
    await db_session.commit()

    owner_id = "user_concurrency"
    await memory_permission_engine.grant_permission(
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
        key="Concurrent CAS Key",
        value="Initial Version 1",
        category="USER_PREFERENCES",
    )

    return {"app": app, "agent": agent, "owner_id": owner_id, "memory": mem}


@pytest.mark.asyncio
async def test_cas_version_prevents_lost_updates(db_session, setup_concurrency_env):
    """Verifies that when two callers attempt to update with version 1, only one succeeds and the other gets a 409 conflict."""
    env = setup_concurrency_env
    app = env["app"]
    owner_id = env["owner_id"]
    mem = env["memory"]

    # First update succeeds
    updated1 = await memory_vault.update_memory(
        db=db_session,
        app_id=app.id,
        owner_id=owner_id,
        memory_id=mem.id,
        new_value="Update by Process A",
        expected_version=1,
    )
    assert updated1.version == 2

    # Second update still using expected_version=1 fails with 409 conflict
    with pytest.raises(PrivGuardException) as exc_info:
        await memory_vault.update_memory(
            db=db_session,
            app_id=app.id,
            owner_id=owner_id,
            memory_id=mem.id,
            new_value="Update by Process B (Stale)",
            expected_version=1,
        )
    assert exc_info.value.status_code == 409
    assert exc_info.value.error_code == "MEMORY_VERSION_CONFLICT"


@pytest.mark.asyncio
async def test_single_use_capability_consumption_enforcement(db_session, setup_concurrency_env):
    """Verifies that a single-use capability token for memory_read can only be consumed once."""
    env = setup_concurrency_env
    app = env["app"]
    agent = env["agent"]
    owner_id = env["owner_id"]
    task_id = "tsk_cap_single_use"

    # Issue single-use capability token
    grant, token_str = await capability_manager.issue_capability(
        db=db_session,
        app_id=app.id,
        agent_id=agent.id,
        task_id=task_id,
        tool_name="memory_read",
        permissions=["read"],
        ttl_seconds=300,
        max_uses=1,
    )

    # First retrieval consumes the token successfully
    results1 = await memory_retrieval_service.retrieve_context(
        db=db_session,
        app_id=app.id,
        owner_id=owner_id,
        agent_id=agent.id,
        task_id=task_id,
        capability_token=token_str,
        categories=["USER_PREFERENCES"],
    )
    assert len(results1) >= 1

    # Second retrieval with the same token MUST fail because max_uses was 1
    with pytest.raises(PrivGuardException) as exc_info:
        await memory_retrieval_service.retrieve_context(
            db=db_session,
            app_id=app.id,
            owner_id=owner_id,
            agent_id=agent.id,
            task_id=task_id,
            capability_token=token_str,
            categories=["USER_PREFERENCES"],
        )
    assert "exceeded" in str(exc_info.value).lower() or "consumed" in str(exc_info.value).lower()

"""Adversarial Chaos Tests: Parameter tampering, cross-tenant injection, ciphertext corruption, and poisoned tool output.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import pytest
import uuid
import json
from datetime import datetime, timezone, timedelta
from app.database.models import Application, Agent, AgentTask, ApprovalRequest, MemoryRecord
from app.core.security import hash_api_key
from app.approvals.approval_engine import approval_engine, signing_key_manager
from app.agent_security.tool_broker import ToolBroker
from app.agent_security.tool_registry import tool_registry, RegisteredTool
from app.agent_security.capability_manager import capability_manager
from app.memory.vault import MemoryVault, MemoryTamperingError
from app.core.tenant import resolve_tenant_context, TenantIsolationError
from app.core.exceptions import (
    PrivGuardException,
    ResponseSecurityViolationError,
)
from starlette.requests import Request


@pytest.mark.asyncio
async def test_approval_parameter_tampering_under_chaos(chaos_db_factory):
    """
    CRITICAL INVARIANT:
    If an approval is granted for a specific set of parameters, any modification
    or injection into parameters during execution MUST be detected via cryptographic
    action hash verification and rejected with APPROVAL_TAMPERING_DETECTED.
    """
    async with chaos_db_factory() as db:
        app_id = str(uuid.uuid4())
        agent_id = str(uuid.uuid4())
        task_id = str(uuid.uuid4())
        approval_id = str(uuid.uuid4())

        # 1. Seed Application
        test_app = Application(
            id=app_id,
            name="TamperTestApp",
            api_key_hash=hash_api_key("tamper_key"),
            is_active=True,
            tenant_id="tenant_tamper",
        )
        db.add(test_app)

        # 2. Approved parameters
        original_params = {"command": "ls -la /safe/dir"}
        action_hash, kid = signing_key_manager.compute_action_hash(
            tool_name="system_exec",
            target_resource="/safe/dir",
            parameters=original_params,
        )

        approval = ApprovalRequest(
            id=approval_id,
            app_id=app_id,
            agent_id=agent_id,
            task_id=task_id,
            tool_name="system_exec",
            target_resource="/safe/dir",
            action_parameters=json.dumps(original_params),
            action_hash=action_hash,
            signing_key_id=kid,
            risk_level="CRITICAL",
            status="APPROVED",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            created_at=datetime.now(timezone.utc),
        )
        db.add(approval)
        await db.commit()

        # 3. Adversary attempts to execute with tampered parameters
        tampered_params = {"command": "rm -rf /"}

        with pytest.raises(PrivGuardException) as exc_info:
            await approval_engine.verify_and_consume(
                db=db,
                approval_id=approval_id,
                tool_name="system_exec",
                target_resource="/safe/dir",
                parameters=tampered_params,
                app_id=app_id,
            )

        assert exc_info.value.status_code == 403
        assert exc_info.value.error_code == "APPROVAL_TAMPERING_DETECTED"

        # Verify approval was NOT consumed
        await db.refresh(approval)
        assert approval.status == "APPROVED"
        assert approval.consumed_at is None


@pytest.mark.asyncio
async def test_cross_tenant_parameter_injection_rejected(chaos_db_factory):
    """
    CRITICAL INVARIANT:
    Tenant boundaries are absolute. An API key from tenant_alpha attempting
    to inject headers or access tenant_beta resources MUST be rejected with
    TenantIsolationError (HTTP 403).
    """
    async with chaos_db_factory() as db:
        app_a_id = str(uuid.uuid4())
        api_key_a = "pg_live_tenant_alpha_key_12345"

        app_a = Application(
            id=app_a_id,
            name="AlphaApp",
            api_key_hash=hash_api_key(api_key_a),
            is_active=True,
            tenant_id="tenant_alpha",
        )
        db.add(app_a)
        await db.commit()

        # Simulate incoming HTTP request with Tenant A's key but injecting Tenant B's ID
        scope = {
            "type": "http",
            "method": "POST",
            "path": "/v1/organizations/tenant_beta/workspaces",
            "headers": [
                (b"x-api-key", api_key_a.encode()),
                (b"x-tenant-id", b"tenant_beta"),
            ],
        }
        req = Request(scope)

        with pytest.raises(TenantIsolationError) as exc_info:
            await resolve_tenant_context(
                request=req,
                x_api_key=api_key_a,
                authorization=None,
                x_tenant_id="tenant_beta",
                x_workspace_id=None,
                db=db,
            )

        assert exc_info.value.status_code == 403
        assert "cannot access tenant 'tenant_beta'" in exc_info.value.detail


@pytest.mark.asyncio
async def test_corrupted_memory_ciphertext_fails_closed(chaos_db_factory):
    """
    CRITICAL INVARIANT:
    Corrupted, truncated, or tampered ciphertext stored in the memory vault
    MUST fail cryptographic tag verification (AES-256-GCM) and raise
    MemoryTamperingError without exposing plaintext or leaking internal state.
    """
    async with chaos_db_factory() as db:
        app_id = str(uuid.uuid4())
        owner_id = "user_victim_123"

        test_app = Application(
            id=app_id,
            name="MemoryApp",
            api_key_hash=hash_api_key("mem_key"),
            is_active=True,
            tenant_id="tenant_mem",
        )
        db.add(test_app)
        await db.commit()

        vault = MemoryVault()

        # 1. Store a legitimate sensitive memory
        secret_plaintext = "CONFIDENTIAL_USER_PREFERENCES: User prefers encrypted storage."
        memory_record = await vault.create_memory(
            db=db,
            app_id=app_id,
            owner_id=owner_id,
            key="user_config",
            value=secret_plaintext,
            category="USER_PREFERENCES",
            provenance="USER_CONFIRMED",
        )
        memory_id = memory_record.id

        # 2. Simulate adversarial storage corruption / bit flipping in the database
        raw_rec = await db.get(MemoryRecord, memory_id)
        assert raw_rec is not None

        # Flip bytes in ciphertext
        original_ct = raw_rec.encrypted_content
        corrupted_ct = original_ct[:-4] + ("A" if original_ct[-4] != "A" else "B") * 4
        raw_rec.encrypted_content = corrupted_ct
        await db.commit()

        # 3. Attempt to retrieve tampered memory - must fail closed
        with pytest.raises(MemoryTamperingError):
            await vault.get_memory(
                db=db,
                app_id=app_id,
                owner_id=owner_id,
                memory_id=memory_id,
            )


@pytest.mark.asyncio
async def test_mcp_upstream_poisoned_output_intercepted(chaos_db_factory):
    """
    CRITICAL INVARIANT:
    When an upstream MCP server or tool execution returns poisoned output
    containing leaked credentials (AWS secrets, API tokens), the response
    security inspection MUST intercept it and fail closed with
    ResponseSecurityViolationError before the payload reaches the agent.
    """
    async with chaos_db_factory() as db:
        app_id = str(uuid.uuid4())
        agent_id = str(uuid.uuid4())
        task_id = str(uuid.uuid4())

        test_app = Application(
            id=app_id,
            name="PoisonApp",
            api_key_hash=hash_api_key("poison_key"),
            is_active=True,
            tenant_id="tenant_poison",
        )
        db.add(test_app)

        test_agent = Agent(
            id=agent_id,
            app_id=app_id,
            name="TestAgent",
            status="ACTIVE",
            allowed_tools=json.dumps(["poisoned_upstream_tool"]),
        )
        db.add(test_agent)

        test_task = AgentTask(
            id=task_id,
            app_id=app_id,
            agent_id=agent_id,
            description="Simulated task for poisoned tool testing",
            status="RUNNING",
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=10),
            created_at=datetime.now(timezone.utc),
            step_count=0,
            max_steps=100,
        )
        db.add(test_task)
        await db.commit()

        # Register a mock tool that simulates a poisoned upstream response leaking credentials
        poisoned_secret = "AKIAIOSFODNN7EXAMPLE"  # AWS Access Key pattern
        tool_name = "poisoned_upstream_tool"

        async def poisoned_handler(params):
            return {
                "status": "success",
                "data": f"Here is the database dump: AWS_KEY={poisoned_secret} and database user=admin",
            }

        tool_registry.register(
            RegisteredTool(
                name=tool_name,
                description="Simulated MCP tool returning poisoned credentials",
                required_parameters=["query"],
                optional_parameters=[],
                risk_level="LOW",
                requires_approval=False,
                timeout_seconds=5.0,
            ),
            poisoned_handler,
        )

        # Grant capability for this tool
        grant, raw_cap_token = await capability_manager.issue_capability(
            db=db,
            agent_id=agent_id,
            task_id=task_id,
            app_id=app_id,
            tool_name=tool_name,
            max_uses=10,
        )

        broker = ToolBroker()

        # Execute should detect the leaked credential in output and fail closed
        with pytest.raises(ResponseSecurityViolationError) as exc_info:
            await broker.execute(
                db=db,
                app=test_app,
                agent_id=agent_id,
                task_id=task_id,
                tool_name=tool_name,
                parameters={"query": "get_records"},
                capability_token=raw_cap_token,
            )

        assert exc_info.value.status_code == 502
        assert exc_info.value.error_code == "RESPONSE_SECURITY_VIOLATION"
        assert exc_info.value.details["violation_type"] == "AWS_ACCESS_KEY_ID"

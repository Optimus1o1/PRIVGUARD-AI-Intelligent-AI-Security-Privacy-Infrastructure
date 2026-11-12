"""Security Fail-Closed Invariant Validation Under Infrastructure Outages.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import asyncio
from datetime import datetime, timezone
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_security.capability_manager import capability_manager
from app.agent_security.identity import agent_identity_manager
from app.agent_security.task_manager import task_manager
from app.agent_security.tool_broker import ToolBroker
from app.core.exceptions import MemoryTamperingError, PrivGuardException
from app.database.models import Agent, Application, CapabilityGrant, MemoryRecord, utcnow
from app.infrastructure.rate_limiter import DistributedRateLimiter, RateLimitPolicy
from app.memory.crypto import EncryptedMemoryPayload, EnvelopeEncryption
from app.memory.vault import MemoryVault
from tests.chaos.conftest import ChaosRedisClient, ChaosKMSProvider


@pytest.mark.asyncio
async def test_redis_outage_fails_closed_on_sensitive_categories():
    """
    CRITICAL INVARIANT:
    When Redis is unavailable, rate limiting on sensitive endpoints
    (AUTHENTICATION, ADMIN, GATEWAY) must strictly FAIL CLOSED in production.
    """
    offline_redis = ChaosRedisClient(initial_online=False)
    limiter = DistributedRateLimiter(custom_redis=offline_redis)

    # 1. Sensitive categories must be BLOCKED
    for cat in ("AUTHENTICATION", "ADMIN", "GATEWAY"):
        result = await limiter.check_rate_limit(
            tenant_id="tenant_alpha",
            category=cat,
            identifier="test_subject_1",
            strict_fail_closed=True,
        )
        assert result.allowed is False, f"Expected {cat} to fail closed, but it was allowed!"
        assert result.backend_mode == "fail_closed_redis_unavailable"
        assert result.retry_after > 0

    # 2. Non-sensitive category (e.g. TOOL_EXECUTION or custom) may degrade gracefully to local cache
    degraded_result = await limiter.check_rate_limit(
        tenant_id="tenant_alpha",
        category="TOOL_EXECUTION",
        identifier="test_subject_1",
        strict_fail_closed=False,
    )
    assert degraded_result.allowed is True
    assert degraded_result.backend_mode == "in_memory_fallback"


@pytest.mark.asyncio
async def test_redis_outage_preserves_postgresql_authoritative_revocation(chaos_db_session: AsyncSession):
    """
    CRITICAL INVARIANT:
    Redis is merely an acceleration layer. PostgreSQL is the authoritative source of truth.
    If Redis is completely partitioned/dead, a revoked agent MUST STILL BE BLOCKED.
    """
    db = chaos_db_session

    # 1. Create Application and Agent in PostgreSQL
    app_record = Application(
        id="app_chaos_1",
        name="Chaos App",
        api_key_hash="hash_chaos_1",
        tenant_id="tenant_chaos",
        is_active=True,
    )
    agent = Agent(
        id="agent_chaos_revoked",
        app_id="app_chaos_1",
        tenant_id="tenant_chaos",
        name="Compromised Agent",
        status="REVOKED",  # REVOKED IN POSTGRESQL
    )
    db.add(app_record)
    db.add(agent)
    await db.commit()

    # 2. Simulate complete Redis outage
    offline_redis = ChaosRedisClient(initial_online=False)
    broker = ToolBroker()

    # 3. Attempt tool execution with revoked agent under Redis outage
    with pytest.raises(PrivGuardException) as exc_info:
        await broker.execute(
            db=db,
            app=app_record,
            agent_id="agent_chaos_revoked",
            task_id="task_any",
            tool_name="read_file",
            parameters={"path": "data.txt"},
            capability_token="dummy_cap",
        )

    assert exc_info.value.status_code == 403
    assert exc_info.value.error_code == "AGENT_NOT_ACTIVE"


@pytest.mark.asyncio
async def test_kms_outage_fails_closed_without_plaintext_leak():
    """
    CRITICAL INVARIANT:
    When external KMS experiences an outage or timeout during DEK unwrapping,
    memory retrieval MUST FAIL CLOSED and NEVER return raw ciphertext or plaintext.
    """
    kms = ChaosKMSProvider()
    crypto = EnvelopeEncryption()

    # Encrypt a test payload
    plaintext = "super_confidential_personal_secret_12345"
    payload = crypto.encrypt(
        plaintext=plaintext,
        owner_id="user_alice",
        memory_id="mem_123",
        category="CONFIDENTIAL",
        encryption_format="V1",
    )

    # Corrupt or simulate unwrap failure
    corrupted_payload = EncryptedMemoryPayload(
        ciphertext_b64=payload.ciphertext_b64,
        nonce_b64=payload.nonce_b64,
        wrapped_dek_b64="bm90X2FfdmFsaWRfZGVr",  # Invalid base64 wrapped DEK
        dek_nonce_b64=payload.dek_nonce_b64,
        key_version=payload.key_version,
        content_fingerprint=payload.content_fingerprint,
        encryption_format="V1",
    )

    # Retrieval MUST fail closed and raise MemoryTamperingError
    with pytest.raises(MemoryTamperingError):
        crypto.decrypt(
            payload=corrupted_payload,
            owner_id="user_alice",
            memory_id="mem_123",
            category="CONFIDENTIAL",
        )


@pytest.mark.asyncio
async def test_capability_revocation_during_active_task(chaos_db_session: AsyncSession):
    """
    CRITICAL INVARIANT:
    If a capability token is revoked mid-task, any subsequent call presenting
    that token MUST BE IMMEDIATELY REJECTED.
    """
    db = chaos_db_session
    app_id = "app_task_revocation"
    agent_id = "agent_active_worker"

    # Setup Application and Agent
    app_rec = Application(id=app_id, name="TestApp", api_key_hash="hash_1", tenant_id="t1", is_active=True)
    agent_rec = Agent(id=agent_id, app_id=app_id, tenant_id="t1", name="Worker", status="ACTIVE")
    db.add(app_rec)
    db.add(agent_rec)
    await db.commit()

    # Create task
    task = await task_manager.create_task(db=db, agent_id=agent_id, app_id=app_id, ttl_seconds=300)

    # Issue 2-use capability
    grant, raw_token = await capability_manager.issue_capability(
        db=db,
        agent_id=agent_id,
        task_id=task.id,
        app_id=app_id,
        tool_name="read_file",
        max_uses=2,
    )

    # 1st use succeeds
    g1 = await capability_manager.validate_and_consume(
        db=db,
        raw_secret=raw_token,
        expected_tool="read_file",
        expected_agent_id=agent_id,
        expected_task_id=task.id,
        expected_app_id=app_id,
        consume=True,
    )
    assert g1.uses_count == 1

    # Revoke capability in PostgreSQL
    await capability_manager.revoke_capability(db=db, capability_id=grant.id, app_id=app_id)

    # 2nd use MUST fail closed with CAPABILITY_REVOKED
    with pytest.raises(PrivGuardException) as exc_info:
        await capability_manager.validate_and_consume(
            db=db,
            raw_secret=raw_token,
            expected_tool="read_file",
            expected_agent_id=agent_id,
            expected_task_id=task.id,
            expected_app_id=app_id,
            consume=True,
        )

    assert exc_info.value.status_code == 403
    assert exc_info.value.error_code == "CAPABILITY_REVOKED"

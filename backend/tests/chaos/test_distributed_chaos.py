"""Distributed System Failure, Partitioning, and Recovery Testing.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import json
import pytest
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database.models import Application, OutboxEvent, ToolExecutionRecord, utcnow
from app.infrastructure.outbox import emit_outbox_event, OutboxPublisher
from tests.chaos.conftest import ChaosRedisClient


@pytest.mark.asyncio
async def test_outbox_event_persistence_during_redis_offline(chaos_db_session: AsyncSession):
    """
    CRITICAL INVARIANT:
    Transactional outbox events must be durably stored in PostgreSQL even if Redis is down.
    When Redis recovers, events must be published cleanly.
    """
    db = chaos_db_session

    # 1. Emit an outbox event inside database transaction
    event = emit_outbox_event(
        session=db,
        event_type="AGENT_REVOKED",
        aggregate_id="agent_123",
        payload={"reason": "Compromised credential", "revoked_by": "sec_admin"},
        tenant_id="tenant_omega",
    )
    await db.commit()
    await db.refresh(event)

    assert event.status == "PENDING"
    assert event.retry_count == 0

    # 2. Publisher attempts delivery while Redis is offline
    offline_redis = ChaosRedisClient(initial_online=False)
    publisher = OutboxPublisher(custom_redis=offline_redis)

    published_count = await publisher.publish_pending_events(db=db, batch_size=10)
    assert published_count == 0

    # Event remains PENDING in PostgreSQL
    await db.refresh(event)
    assert event.status == "PENDING"

    # 3. Redis recovers
    offline_redis.set_online(True)
    published_count_recovered = await publisher.publish_pending_events(db=db, batch_size=10)
    assert published_count_recovered == 1

    # Event is now marked PUBLISHED
    await db.refresh(event)
    assert event.status == "PUBLISHED"
    assert event.published_at is not None

    # Redis Stream received the message
    stream_key = "stream:events:tenant_omega"
    assert stream_key in offline_redis.streams
    assert len(offline_redis.streams[stream_key]) == 1
    assert offline_redis.streams[stream_key][0]["data"]["event_type"] == "AGENT_REVOKED"


@pytest.mark.asyncio
async def test_dead_letter_handling_after_max_retries(chaos_db_session: AsyncSession):
    """
    CRITICAL INVARIANT:
    Poison-pill outbox events that persistently fail publishing must transition to
    DEAD_LETTER status after 5 retries without crashing the publisher loop.
    """
    db = chaos_db_session

    # Emit an event
    event = emit_outbox_event(
        session=db,
        event_type="POLICY_SYNC_FAILED",
        aggregate_id="policy_bundle_99",
        payload={"version": 99},
        tenant_id="tenant_omega",
    )
    await db.commit()
    await db.refresh(event)

    class FailingStreamRedis(ChaosRedisClient):
        async def xadd(self, name, fields, maxlen=None):
            raise RuntimeError("Chaos: Corrupted stream buffer")

    failing_redis = FailingStreamRedis(initial_online=True)
    publisher = OutboxPublisher(custom_redis=failing_redis)

    # Attempt publishing 5 times
    for attempt in range(5):
        await publisher.publish_pending_events(db=db, batch_size=10)
        await db.refresh(event)

    # After 5 failures, event must be DEAD_LETTER
    assert event.status == "DEAD_LETTER"
    assert event.retry_count >= 5


@pytest.mark.asyncio
async def test_atomic_transaction_rollback_on_failure(chaos_db_session: AsyncSession):
    """
    CRITICAL INVARIANT:
    If an operation fails mid-transaction, all changes (records, events)
    must roll back completely, preventing ghost or half-committed records.
    """
    db = chaos_db_session

    try:
        async with db.begin_nested():
            # Add an execution record
            record = ToolExecutionRecord(
                id="rec_chaos_rollback",
                task_id="task_1",
                agent_id="agent_1",
                app_id="app_1",
                tool_name="read_file",
                status="SUCCESS",
            )
            db.add(record)
            # Add outbox event
            emit_outbox_event(
                session=db,
                event_type="TOOL_EXECUTED",
                aggregate_id="rec_chaos_rollback",
                payload={"status": "SUCCESS"},
                tenant_id="tenant_alpha",
            )
            # Intentionally simulate crash
            raise RuntimeError("Chaos: Fatal power failure before commit")
    except RuntimeError:
        await db.rollback()

    # Query database to confirm neither record was committed
    query_rec = select(ToolExecutionRecord).where(ToolExecutionRecord.id == "rec_chaos_rollback")
    res_rec = await db.execute(query_rec)
    assert res_rec.scalar_one_or_none() is None

    query_evt = select(OutboxEvent).where(OutboxEvent.aggregate_id == "rec_chaos_rollback")
    res_evt = await db.execute(query_evt)
    assert res_evt.scalar_one_or_none() is None


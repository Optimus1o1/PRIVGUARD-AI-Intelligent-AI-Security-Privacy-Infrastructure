"""Unit tests for Redis State Reconstruction and Reconciliation on Recovery.
Verifies:
1. Category-specific state reconstruction (revocations, taints, policies, outbox events).
2. Safe Restriction Mode engagement for defensive warmup rate limiting.
3. Graceful fallback when Redis is offline.
"""

from unittest.mock import AsyncMock
import json
import pytest

from app.database.models import ActiveTaint, CapabilityGrant, OutboxEvent, PolicyBundle
from app.recovery.redis_reconciliation import reconcile_redis_on_recovery
from app.recovery.revocation_journal import record_revocation_entry


class MockRedis:
    def __init__(self):
        self.store = {}
        self.streams = {}

    async def set(self, key: str, value: str, ex: int | None = None):
        self.store[key] = (value, ex)

    async def get(self, key: str):
        item = self.store.get(key)
        return item[0] if item else None

    async def xadd(self, stream: str, fields: dict):
        if stream not in self.streams:
            self.streams[stream] = []
        self.streams[stream].append(fields)
        return "1-0"


@pytest.mark.asyncio
async def test_reconcile_redis_offline(db_session):
    summary = await reconcile_redis_on_recovery(db=db_session, redis_client=None)
    assert summary["status"] == "SKIPPED_REDIS_OFFLINE"


@pytest.mark.asyncio
async def test_reconcile_redis_full_state(db_session, test_app_record, monkeypatch, tmp_path):
    # Isolate journal
    journal_file = tmp_path / "revocation_journal.log"
    monkeypatch.setenv("PRIVGUARD_REVOCATION_JOURNAL_PATH", str(journal_file))

    import uuid
    from datetime import datetime, timedelta, timezone

    # 1. Seed PostgreSQL records
    # Revoked capability grant
    cap_id = f"cap_test_{uuid.uuid4().hex[:8]}"
    grant = CapabilityGrant(
        id=cap_id,
        secret_hash="hash_revoked_cap",
        agent_id="agent_1",
        task_id="task_1",
        app_id=test_app_record.id,
        tenant_id=test_app_record.id,
        tool_name="read_file",
        expires_at=datetime.now(timezone.utc) + timedelta(hours=1),
        is_revoked=True,
    )
    db_session.add(grant)

    # Active taint
    taint = ActiveTaint(
        task_id="task_1",
        tenant_id=test_app_record.id,
        resource="confidential_doc.pdf",
        taint_level="RESTRICTED",
    )
    db_session.add(taint)

    # Pending outbox event
    outbox = OutboxEvent(
        tenant_id=test_app_record.id,
        event_type="CAPABILITY_REVOKED",
        aggregate_id=cap_id,
        payload=json.dumps({"target": cap_id}),
        status="PENDING",
    )
    db_session.add(outbox)

    await db_session.commit()

    # Record journal entry
    record_revocation_entry(
        target_type="CAPABILITY",
        target_id="cap_from_journal_001",
        tenant_id=test_app_record.id,
        reason="Pre-crash revocation",
    )

    redis = MockRedis()
    summary = await reconcile_redis_on_recovery(db=db_session, redis_client=redis, warmup_safe_mode_seconds=300)

    assert summary["status"] == "COMPLETED"
    assert summary["revocations_reconciled"] >= 2
    assert summary["taint_records_reconstructed"] >= 1
    assert summary["outbox_events_replayed"] >= 1
    assert summary["safe_restriction_mode_enabled"] is True

    # Verify Redis contents
    # Safe restriction mode active
    assert "system:safe_restriction_mode" in redis.store
    assert redis.store["system:safe_restriction_mode"][0] == "ACTIVE"
    assert redis.store["system:safe_restriction_mode"][1] == 300

    # Taint present
    taint_key = f"taint:{test_app_record.id}:task_1"
    assert taint_key in redis.store
    taint_val = json.loads(redis.store[taint_key][0])
    assert taint_val["resource"] == "confidential_doc.pdf"

    # Outbox stream replayed
    assert "stream:events" in redis.streams
    assert len(redis.streams["stream:events"]) >= 1
    assert redis.streams["stream:events"][0]["replayed_on_recovery"] == "true"

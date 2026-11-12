"""Unit tests for Security Recovery Epoch and Independent Revocation Journal.
Verifies:
1. Monotonic advancement of security recovery epochs.
2. Capability tokens from prior epochs are invalidated immediately upon epoch advancement.
3. Cryptographic hash-chaining and tamper-detection of the independent revocation journal.
4. Database reconciliation replaying durable revocations into the database.
"""

import json
import os
from pathlib import Path
import pytest

from app.core.exceptions import PrivGuardException
from app.recovery.security_epoch import (
    get_current_security_epoch,
    advance_security_epoch,
)
from app.recovery.revocation_journal import (
    record_revocation_entry,
    verify_journal_integrity,
    replay_revocations_into_db,
)
from app.agent_security.capability_manager import CapabilityManager


@pytest.fixture(autouse=True)
def isolate_dr_paths(tmp_path, monkeypatch):
    epoch_file = tmp_path / "security_epoch.state"
    journal_file = tmp_path / "revocation_journal.log"
    monkeypatch.setenv("PRIVGUARD_SECURITY_EPOCH_STATE_PATH", str(epoch_file))
    monkeypatch.setenv("PRIVGUARD_REVOCATION_JOURNAL_PATH", str(journal_file))
    yield


def test_epoch_monotonicity_and_persistence():
    assert get_current_security_epoch() == 1

    new_epoch = advance_security_epoch(reason="TEST_DR_ADVANCE", operator="test_runner")
    assert new_epoch == 2
    assert get_current_security_epoch() == 2

    new_epoch = advance_security_epoch(reason="SECOND_ADVANCE", operator="test_runner")
    assert new_epoch == 3
    assert get_current_security_epoch() == 3


@pytest.mark.asyncio
async def test_capability_invalidated_across_epochs(db_session, test_app_record):
    mgr = CapabilityManager()

    # 1. Issue capability in epoch 1
    assert get_current_security_epoch() == 1
    grant, raw_token = await mgr.issue_capability(
        db=db_session,
        agent_id="test-agent-epoch",
        task_id="test-task-epoch",
        app_id=test_app_record.id,
        tool_name="execute_sql",
        resource="analytics.*",
        ttl_seconds=3600,
        max_uses=5,
    )
    assert raw_token.startswith("pg_cap_e1_")

    # Validate in same epoch - succeeds
    consumed = await mgr.validate_and_consume(
        db=db_session,
        raw_secret=raw_token,
        expected_tool="execute_sql",
        expected_agent_id="test-agent-epoch",
        expected_task_id="test-task-epoch",
        expected_app_id=test_app_record.id,
        resource="analytics.*",
        consume=False,
    )
    assert consumed.id == grant.id

    # 2. Advance security recovery epoch
    advance_security_epoch(reason="PITR_RESTORE_SIMULATION", operator="sre")
    assert get_current_security_epoch() == 2

    # 3. Validate again - MUST fail closed with CAPABILITY_EPOCH_INVALIDATED
    with pytest.raises(PrivGuardException) as exc_info:
        await mgr.validate_and_consume(
            db=db_session,
            raw_secret=raw_token,
            expected_tool="execute_sql",
            expected_agent_id="test-agent-epoch",
            expected_task_id="test-task-epoch",
            expected_app_id=test_app_record.id,
            resource="analytics.*",
            consume=False,
        )
    assert exc_info.value.error_code == "CAPABILITY_EPOCH_INVALIDATED"


def test_revocation_journal_hash_chain():
    entry1 = record_revocation_entry(
        target_type="CAPABILITY",
        target_id="cap_001",
        tenant_id="tenant-alpha",
        reason="Manual user revocation",
    )
    assert entry1["sequence_number"] == 1
    assert entry1["prev_hash"] == "GENESIS"

    entry2 = record_revocation_entry(
        target_type="AGENT",
        target_id="agent_999",
        tenant_id="tenant-alpha",
        reason="Agent compromise detected",
    )
    assert entry2["sequence_number"] == 2
    assert entry2["prev_hash"] == entry1["entry_hash"]

    is_valid, msg = verify_journal_integrity()
    assert is_valid is True
    assert "VALID" in msg


def test_revocation_journal_tampering_detected():
    record_revocation_entry(
        target_type="CAPABILITY",
        target_id="cap_101",
        tenant_id="tenant-alpha",
        reason="Test 1",
    )
    record_revocation_entry(
        target_type="CAPABILITY",
        target_id="cap_102",
        tenant_id="tenant-alpha",
        reason="Test 2",
    )

    journal_path = Path(os.environ["PRIVGUARD_REVOCATION_JOURNAL_PATH"])
    lines = [json.loads(line) for line in journal_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    # Tamper with first entry's target_id
    lines[0]["target_id"] = "cap_MODIFIED"
    tampered_text = "\n".join(json.dumps(item) for item in lines) + "\n"
    journal_path.write_text(tampered_text, encoding="utf-8")

    is_valid, msg = verify_journal_integrity()
    assert is_valid is False
    assert "tampered" in msg.lower() or "broken" in msg.lower()


@pytest.mark.asyncio
async def test_reconciliation_replays_revocations_into_db(db_session, test_app_record):
    mgr = CapabilityManager()

    # Create capability grant in database
    grant, _ = await mgr.issue_capability(
        db=db_session,
        agent_id="test-agent-reconcile",
        task_id="test-task-reconcile",
        app_id=test_app_record.id,
        tool_name="read_file",
        ttl_seconds=3600,
    )
    assert grant.is_revoked is False

    # Record revocation in the independent journal outside the DB
    record_revocation_entry(
        target_type="CAPABILITY",
        target_id=grant.id,
        tenant_id=test_app_record.id,
        reason="User requested revocation before DB snapshot",
    )

    # Replay journal against the database (simulating post-restore reconciliation)
    reconciled_count = await replay_revocations_into_db(db_session)
    assert reconciled_count == 1

    # Verify DB record is now revoked
    await db_session.refresh(grant)
    assert grant.is_revoked is True

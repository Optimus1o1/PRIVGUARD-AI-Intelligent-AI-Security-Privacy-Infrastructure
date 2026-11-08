"""Unit tests for Anti-Resurrection Memory Recovery and Independent Erasure Ledger.
Verifies:
1. Durable persistence and cryptographic hash chaining of erasure tombstones.
2. Immediate rejection (fail-closed) of resurrected memory reads when tombstone exists.
3. Post-recovery database reconciliation actively scrubbing resurrected pre-erasure ciphertexts.
"""

import json
import os
from pathlib import Path
import pytest
from sqlalchemy import select

from app.database.models import MemoryRecord
from app.core.exceptions import MemoryNotFoundError
from app.memory.vault import memory_vault
from app.recovery.erasure_ledger import (
    record_erasure_tombstone,
    is_memory_tombstoned,
    verify_ledger_integrity,
    reconcile_database_erasures,
    load_all_tombstones,
)


@pytest.fixture(autouse=True)
def isolate_erasure_ledger(tmp_path, monkeypatch):
    ledger_file = tmp_path / "erasure_tombstones.jsonl"
    monkeypatch.setenv("PRIVGUARD_ERASURE_LEDGER_PATH", str(ledger_file))
    # Reset in-memory cache
    import app.recovery.erasure_ledger as el
    el._TOMBSTONED_MEMORY_IDS.clear()
    el._CACHE_INITIALIZED = False
    yield


def test_erasure_ledger_hash_chain():
    t1 = record_erasure_tombstone(
        memory_id="mem_001",
        tenant_id="tenant-a",
        audit_digest="digest_1",
    )
    assert t1["sequence_number"] == 1
    assert t1["prev_hash"] == "GENESIS"

    t2 = record_erasure_tombstone(
        memory_id="mem_002",
        tenant_id="tenant-a",
        audit_digest="digest_2",
    )
    assert t2["sequence_number"] == 2
    assert t2["prev_hash"] == t1["tombstone_hash"]

    is_valid, msg = verify_ledger_integrity()
    assert is_valid is True
    assert "VALID" in msg


def test_erasure_ledger_tampering_detected():
    record_erasure_tombstone(
        memory_id="mem_101",
        tenant_id="tenant-a",
        audit_digest="digest_101",
    )
    record_erasure_tombstone(
        memory_id="mem_102",
        tenant_id="tenant-a",
        audit_digest="digest_102",
    )

    ledger_path = Path(os.environ["PRIVGUARD_ERASURE_LEDGER_PATH"])
    lines = [json.loads(line) for line in ledger_path.read_text(encoding="utf-8").splitlines() if line.strip()]

    # Tamper with memory_id in entry 1
    lines[0]["memory_id"] = "mem_TAMPERED"
    tampered_text = "\n".join(json.dumps(item) for item in lines) + "\n"
    ledger_path.write_text(tampered_text, encoding="utf-8")

    is_valid, msg = verify_ledger_integrity()
    assert is_valid is False
    assert "tampered" in msg.lower() or "broken" in msg.lower()


@pytest.mark.asyncio
async def test_anti_resurrection_fails_closed_on_tombstone(db_session, test_app_record):
    app_id = test_app_record.id
    owner_id = "user_dr_01"

    # 1. Create a memory in database
    mem = await memory_vault.create_memory(
        db=db_session,
        app_id=app_id,
        owner_id=owner_id,
        key="theme_preference",
        value="dark_mode",
        category="USER_PREFERENCES",
    )
    mem_id = mem.id

    # 2. Delete memory cleanly (writes tombstone to independent ledger)
    deleted = await memory_vault.delete_memory(
        db=db_session,
        app_id=app_id,
        owner_id=owner_id,
        memory_id=mem_id,
    )
    assert deleted is True
    assert is_memory_tombstoned(mem_id) is True

    # 3. Simulate disaster recovery: database was restored to an older snapshot
    # where the memory was still ACTIVE with valid encrypted content.
    record = (await db_session.execute(select(MemoryRecord).where(MemoryRecord.id == mem_id))).scalar_one()
    record.status = "ACTIVE"
    record.encrypted_content = "resurrected_ciphertext_mock"
    await db_session.commit()

    # 4. Attempt retrieval: MUST fail closed with MemoryNotFoundError
    with pytest.raises(MemoryNotFoundError):
        await memory_vault.get_memory(
            db=db_session,
            app_id=app_id,
            owner_id=owner_id,
            memory_id=mem_id,
        )


@pytest.mark.asyncio
async def test_reconciliation_scrubs_resurrected_records(db_session, test_app_record):
    app_id = test_app_record.id
    owner_id = "user_dr_02"

    # Create 2 memories in database
    m1 = await memory_vault.create_memory(
        db=db_session,
        app_id=app_id,
        owner_id=owner_id,
        key="editor_preference",
        value="vim_keys",
        category="USER_PREFERENCES",
    )
    m2 = await memory_vault.create_memory(
        db=db_session,
        app_id=app_id,
        owner_id=owner_id,
        key="locale_preference",
        value="en_US",
        category="USER_PREFERENCES",
    )

    # Record tombstone for m1 in the independent ledger (simulating deletion before crash)
    record_erasure_tombstone(
        memory_id=m1.id,
        tenant_id=app_id,
        audit_digest="audit_del_m1",
        reason="GDPR_DPDP_RIGHT_TO_ERASURE",
    )

    # Before reconciliation: m1 is active in database (resurrected)
    rec_m1 = (await db_session.execute(select(MemoryRecord).where(MemoryRecord.id == m1.id))).scalar_one()
    assert rec_m1.status == "ACTIVE"

    # Run reconciliation
    scrubbed = await reconcile_database_erasures(db_session)
    assert scrubbed == 1

    # Verify m1 is cryptographically scrubbed
    await db_session.refresh(rec_m1)
    assert rec_m1.status == "DELETED"
    assert rec_m1.encrypted_content == "[CRYPTOGRAPHICALLY_ERASED]"
    assert rec_m1.wrapped_dek == "[DEK_DESTROYED]"

    # Verify m2 was untouched
    rec_m2 = (await db_session.execute(select(MemoryRecord).where(MemoryRecord.id == m2.id))).scalar_one()
    assert rec_m2.status == "ACTIVE"
    assert rec_m2.encrypted_content != "[CRYPTOGRAPHICALLY_ERASED]"

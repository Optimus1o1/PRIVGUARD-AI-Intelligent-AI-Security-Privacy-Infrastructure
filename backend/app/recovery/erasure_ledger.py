"""Independent, Append-Only Durable Erasure Ledger for Anti-Resurrection.

Moon Sanctum Labs - Decode. Build. Evolve.

Maintains an immutable, append-only ledger of cryptographic erasure tombstones
outside the PostgreSQL backup and restore domain.
On disaster recovery, this ledger is reconciled against the restored database
to guarantee that an older database snapshot NEVER resurrects intentionally
deleted personal data (GDPR Art. 17 / DPDP Sec. 12).
"""

import hashlib
import json
import logging
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import MemoryRecord, MemoryVersion
from app.recovery.security_epoch import get_current_security_epoch

logger = logging.getLogger("privguard.recovery.erasure_ledger")

DEFAULT_ERASURE_LEDGER_PATH = Path("var/recovery/erasure_tombstones.jsonl")

# In-memory fast cache of tombstoned memory IDs
_TOMBSTONED_MEMORY_IDS: set[str] = set()
_CACHE_INITIALIZED = False


def _get_ledger_path() -> Path:
    env_path = os.getenv("PRIVGUARD_ERASURE_LEDGER_PATH")
    if env_path:
        return Path(env_path)
    return DEFAULT_ERASURE_LEDGER_PATH


def record_erasure_tombstone(
    memory_id: str,
    tenant_id: str,
    audit_digest: str,
    reason: str = "GDPR_DPDP_RIGHT_TO_ERASURE",
    operator: str = "system",
    metadata: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Appends an immutable cryptographic erasure tombstone to the independent ledger.

    Guarantees durable persistence via fsync before returning.
    Contains strictly minimal pseudonymous identifiers (no raw names or prompt text).

    Args:
        memory_id: UUID / identifier of the erased memory.
        tenant_id: Tenant owning the memory.
        audit_digest: SHA-256 fingerprint of the deletion audit event.
        reason: Regulatory / operational rationale.
        operator: Identity requesting erasure.
        metadata: Optional context metadata.

    Returns:
        The written tombstone record.
    """
    global _TOMBSTONED_MEMORY_IDS
    ledger_path = _get_ledger_path()
    ledger_path.parent.mkdir(parents=True, exist_ok=True)

    prev_hash = "GENESIS"
    sequence_number = 1

    if ledger_path.exists() and ledger_path.stat().st_size > 0:
        try:
            with open(ledger_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
                if lines:
                    last_entry = json.loads(lines[-1])
                    prev_hash = last_entry.get("tombstone_hash", "GENESIS")
                    sequence_number = int(last_entry.get("sequence_number", 0)) + 1
        except Exception as exc:
            logger.error("Failed to read last erasure tombstone: %s", exc)

    tombstone_id = f"tomb_{uuid.uuid4().hex[:16]}"
    now_utc = datetime.now(timezone.utc).isoformat()
    current_epoch = get_current_security_epoch()

    tombstone = {
        "tombstone_id": tombstone_id,
        "sequence_number": sequence_number,
        "memory_id": memory_id,
        "tenant_id": tenant_id,
        "erasure_epoch": current_epoch,
        "erased_at": now_utc,
        "audit_digest": audit_digest,
        "reason": reason,
        "operator": operator,
        "metadata": metadata or {},
        "prev_hash": prev_hash,
    }

    # Deterministic canonical serialization for hashing
    payload_str = json.dumps(tombstone, sort_keys=True, separators=(",", ":"))
    tombstone_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
    tombstone["tombstone_hash"] = tombstone_hash

    # Write and fsync durably
    line_to_write = json.dumps(tombstone) + "\n"
    with open(ledger_path, "a", encoding="utf-8") as f:
        f.write(line_to_write)
        f.flush()
        os.fsync(f.fileno())

    # Update in-memory set
    _TOMBSTONED_MEMORY_IDS.add(memory_id)

    logger.info(
        "ERASURE TOMBSTONE COMMITTED: seq=%d memory=%s epoch=%d [hash=%s]",
        sequence_number,
        memory_id,
        current_epoch,
        tombstone_hash[:8],
    )
    return tombstone


def load_all_tombstones() -> dict[str, dict[str, Any]]:
    """Loads all tombstones from the ledger, mapping memory_id -> tombstone."""
    global _TOMBSTONED_MEMORY_IDS, _CACHE_INITIALIZED
    ledger_path = _get_ledger_path()
    if not ledger_path.exists():
        _CACHE_INITIALIZED = True
        return {}

    tombstones: dict[str, dict[str, Any]] = {}
    with open(ledger_path, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if line_str:
                try:
                    data = json.loads(line_str)
                    mid = data.get("memory_id")
                    if mid:
                        tombstones[mid] = data
                        _TOMBSTONED_MEMORY_IDS.add(mid)
                except Exception as exc:
                    logger.warning("Skipping corrupted erasure tombstone line: %s", exc)

    _CACHE_INITIALIZED = True
    return tombstones


def is_memory_tombstoned(memory_id: str) -> bool:
    """Checks whether a memory ID has a durable erasure tombstone recorded.

    Used by retrieval paths to fail closed even if a restored database snapshot
    contains pre-erasure ciphertext.
    """
    global _CACHE_INITIALIZED, _TOMBSTONED_MEMORY_IDS
    if not _CACHE_INITIALIZED:
        load_all_tombstones()
    return memory_id in _TOMBSTONED_MEMORY_IDS


def verify_ledger_integrity() -> tuple[bool, str]:
    """Cryptographically verifies the hash-chain integrity of the erasure ledger."""
    ledger_path = _get_ledger_path()
    if not ledger_path.exists():
        return True, "EMPTY_LEDGER"

    entries: list[dict[str, Any]] = []
    with open(ledger_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                entries.append(json.loads(line.strip()))

    expected_prev = "GENESIS"
    for i, entry in enumerate(entries):
        expected_seq = i + 1
        if entry.get("sequence_number") != expected_seq:
            return False, f"Sequence number mismatch at index {i}: expected {expected_seq}, got {entry.get('sequence_number')}"

        if entry.get("prev_hash") != expected_prev:
            return False, f"Hash chain broken at seq {entry.get('sequence_number')}: prev_hash mismatch"

        recorded_hash = entry.get("tombstone_hash")
        raw_entry = {k: v for k, v in entry.items() if k != "tombstone_hash"}
        calc_payload = json.dumps(raw_entry, sort_keys=True, separators=(",", ":"))
        actual_hash = hashlib.sha256(calc_payload.encode("utf-8")).hexdigest()
        if actual_hash != recorded_hash:
            return False, f"Tombstone hash tampered at seq {entry.get('sequence_number')}: {actual_hash} != {recorded_hash}"

        expected_prev = recorded_hash

    return True, f"VALID ({len(entries)} tombstones verified)"


async def reconcile_database_erasures(db: AsyncSession) -> int:
    """Reconciles restored database records against the independent erasure ledger.

    Any memory record or historical version present in the restored database that
    matches an erasure tombstone is immediately scrubbed to prevent resurrection.

    Args:
        db: SQLAlchemy async session.

    Returns:
        Count of memory records scrubbed during reconciliation.
    """
    is_valid, msg = verify_ledger_integrity()
    if not is_valid:
        raise RuntimeError(f"Cannot reconcile erasures with corrupted ledger: {msg}")

    tombstones = load_all_tombstones()
    if not tombstones:
        logger.info("No erasure tombstones present. Reconciliation complete.")
        return 0

    scrubbed_count = 0
    tombstoned_ids = list(tombstones.keys())

    # 1. Reconcile MemoryRecord table
    stmt = select(MemoryRecord).where(MemoryRecord.id.in_(tombstoned_ids))
    res = await db.execute(stmt)
    records = res.scalars().all()

    for record in records:
        if record.status != "DELETED" or record.encrypted_content != "[CRYPTOGRAPHICALLY_ERASED]":
            logger.warning(
                "ANTI-RESURRECTION RECONCILIATION: Scrubbing resurrected memory record %s",
                record.id,
            )
            record.status = "DELETED"
            record.encrypted_content = "[CRYPTOGRAPHICALLY_ERASED]"
            record.wrapped_dek = "[DEK_DESTROYED]"
            record.nonce = "[WIPED]"
            record.dek_nonce = "[WIPED]"
            scrubbed_count += 1

    # 2. Reconcile MemoryVersion historical snapshots
    stmt_ver = select(MemoryVersion).where(MemoryVersion.memory_id.in_(tombstoned_ids))
    res_ver = await db.execute(stmt_ver)
    versions = res_ver.scalars().all()

    for ver in versions:
        if ver.encrypted_content != "[CRYPTOGRAPHICALLY_ERASED]":
            ver.encrypted_content = "[CRYPTOGRAPHICALLY_ERASED]"
            ver.wrapped_dek = "[DEK_DESTROYED]"
            ver.nonce = "[WIPED]"
            ver.dek_nonce = "[WIPED]"

    await db.commit()
    logger.info("ERASURE RECONCILIATION COMPLETE: Scrubbed %d resurrected memories.", scrubbed_count)
    return scrubbed_count


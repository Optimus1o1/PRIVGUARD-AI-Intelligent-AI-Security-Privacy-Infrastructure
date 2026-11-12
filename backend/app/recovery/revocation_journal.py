"""Independent, Durable Append-Only Revocation Journal.

Moon Sanctum Labs - Decode. Build. Evolve.

Maintains an immutable, cryptographically hash-chained log of all revocations
(capabilities, agents, approvals) outside the PostgreSQL backup and restore domain.
On disaster recovery, this journal is replayed to ensure no revocation is lost
even if the database was restored to a point in time before the revocation occurred.
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

from app.database.models import Agent, ApprovalRequest, CapabilityGrant
from app.recovery.security_epoch import get_current_security_epoch

logger = logging.getLogger("privguard.recovery.revocation_journal")

DEFAULT_JOURNAL_PATH = Path("var/recovery/revocation_journal.log")


def _get_journal_path() -> Path:
    env_path = os.getenv("PRIVGUARD_REVOCATION_JOURNAL_PATH")
    if env_path:
        return Path(env_path)
    return DEFAULT_JOURNAL_PATH


def record_revocation_entry(
    target_type: str,
    target_id: str,
    tenant_id: str,
    reason: str,
    operator: str = "system",
    metadata: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """Appends a revocation record to the independent, hash-chained journal.

    This function blocks until the entry is durably written and fsynced to disk.

    Args:
        target_type: 'CAPABILITY', 'AGENT', or 'APPROVAL'.
        target_id: Identifier of the revoked entity.
        tenant_id: Tenant owning the entity.
        reason: Operational reason for revocation.
        operator: Identity requesting the revocation.
        metadata: Optional additional context.

    Returns:
        The written journal entry dictionary.
    """
    journal_path = _get_journal_path()
    journal_path.parent.mkdir(parents=True, exist_ok=True)

    # Determine previous hash and sequence number
    prev_hash = "GENESIS"
    sequence_number = 1

    if journal_path.exists() and journal_path.stat().st_size > 0:
        try:
            with open(journal_path, "r", encoding="utf-8") as f:
                lines = [line.strip() for line in f if line.strip()]
                if lines:
                    last_entry = json.loads(lines[-1])
                    prev_hash = last_entry.get("entry_hash", "GENESIS")
                    sequence_number = int(last_entry.get("sequence_number", 0)) + 1
        except Exception as exc:
            logger.error("Failed to read last journal entry: %s", exc)

    entry_id = f"rev_{uuid.uuid4().hex[:16]}"
    now_utc = datetime.now(timezone.utc).isoformat()
    current_epoch = get_current_security_epoch()

    entry = {
        "entry_id": entry_id,
        "sequence_number": sequence_number,
        "security_epoch": current_epoch,
        "timestamp": now_utc,
        "target_type": target_type.upper(),
        "target_id": target_id,
        "tenant_id": tenant_id,
        "reason": reason,
        "operator": operator,
        "metadata": metadata or {},
        "prev_hash": prev_hash,
    }

    # Deterministic canonical serialization for hashing
    payload_str = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    entry_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
    entry["entry_hash"] = entry_hash

    # Write and fsync durably
    line_to_write = json.dumps(entry) + "\n"
    with open(journal_path, "a", encoding="utf-8") as f:
        f.write(line_to_write)
        f.flush()
        os.fsync(f.fileno())

    logger.info(
        "REVOCATION JOURNAL COMMITTED: seq=%d type=%s target=%s epoch=%d [hash=%s]",
        sequence_number,
        target_type,
        target_id,
        current_epoch,
        entry_hash[:8],
    )
    return entry


def load_all_revocations() -> list[dict[str, Any]]:
    """Loads and returns all records from the revocation journal."""
    journal_path = _get_journal_path()
    if not journal_path.exists():
        return []

    entries: list[dict[str, Any]] = []
    with open(journal_path, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if line_str:
                try:
                    entries.append(json.loads(line_str))
                except Exception as exc:
                    logger.warning("Skipping corrupted journal line: %s", exc)
    return entries


def verify_journal_integrity() -> tuple[bool, str]:
    """Cryptographically verifies the hash-chain integrity of the revocation journal.

    Returns:
        (True, 'VALID') if authentic, or (False, error_reason) if broken.
    """
    entries = load_all_revocations()
    if not entries:
        return True, "EMPTY_JOURNAL"

    expected_prev = "GENESIS"
    for i, entry in enumerate(entries):
        # 1. Check sequence number
        expected_seq = i + 1
        if entry.get("sequence_number") != expected_seq:
            return (
                False,
                f"Sequence number mismatch at index {i}: expected {expected_seq}, got {entry.get('sequence_number')}",
            )

        # 2. Check previous hash continuity
        if entry.get("prev_hash") != expected_prev:
            return (
                False,
                f"Hash chain broken at seq {entry.get('sequence_number')}: prev_hash does not match previous entry",
            )

        # 3. Check entry hash computation
        recorded_hash = entry.get("entry_hash")
        raw_entry = {k: v for k, v in entry.items() if k != "entry_hash"}
        calc_payload = json.dumps(raw_entry, sort_keys=True, separators=(",", ":"))
        actual_hash = hashlib.sha256(calc_payload.encode("utf-8")).hexdigest()
        if actual_hash != recorded_hash:
            return (
                False,
                f"Entry hash tampered at seq {entry.get('sequence_number')}: computed {actual_hash} != {recorded_hash}",
            )

        expected_prev = recorded_hash

    return True, f"VALID ({len(entries)} entries verified)"


async def replay_revocations_into_db(db: AsyncSession, redis_client: Any = None) -> int:
    """Replays the independent revocation journal against the restored PostgreSQL database.

    Enforces that every revoked capability, agent, or approval remains revoked,
    even if the database was restored to an earlier point-in-time.

    Args:
        db: SQLAlchemy async session.
        redis_client: Optional async Redis client to update live revocation cache.

    Returns:
        Count of replayed revocation records.
    """
    is_valid, msg = verify_journal_integrity()
    if not is_valid:
        raise RuntimeError(f"Cannot replay corrupted revocation journal: {msg}")

    entries = load_all_revocations()
    replayed_count = 0

    for entry in entries:
        target_type = entry.get("target_type")
        target_id = entry.get("target_id")
        tenant_id = entry.get("tenant_id")
        reason = entry.get("reason", "DISASTER_RECOVERY_REPLAY")

        if target_type == "CAPABILITY":
            stmt = select(CapabilityGrant).where(CapabilityGrant.id == target_id)
            res = await db.execute(stmt)
            grant = res.scalar_one_or_none()
            if grant:
                grant.is_revoked = True
                grant.revocation_reason = reason
                replayed_count += 1
            if redis_client:
                try:
                    redis_key = f"revocations:{tenant_id}:{target_id}"
                    await redis_client.set(redis_key, "REVOKED", ex=86400 * 30)
                except Exception as exc:
                    logger.warning("Failed to update Redis for revoked capability %s: %s", target_id, exc)

        elif target_type == "AGENT":
            stmt = select(Agent).where(Agent.id == target_id)
            res = await db.execute(stmt)
            agent = res.scalar_one_or_none()
            if agent:
                agent.status = "REVOKED"
                replayed_count += 1
            if redis_client:
                try:
                    redis_key = f"revocations:{tenant_id}:agent:{target_id}"
                    await redis_client.set(redis_key, "REVOKED", ex=86400 * 30)
                except Exception as exc:
                    logger.warning("Failed to update Redis for revoked agent %s: %s", target_id, exc)

        elif target_type == "APPROVAL":
            stmt = select(ApprovalRequest).where(ApprovalRequest.id == target_id)
            res = await db.execute(stmt)
            appr = res.scalar_one_or_none()
            if appr:
                appr.status = "REVOKED"
                replayed_count += 1

    await db.commit()
    logger.info("REVOCATION REPLAY COMPLETED: Replayed %d records into database.", replayed_count)
    return replayed_count

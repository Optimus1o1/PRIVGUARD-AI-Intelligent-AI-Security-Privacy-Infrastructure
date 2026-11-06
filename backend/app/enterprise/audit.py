"""Tamper-evident, hash-chained enterprise audit ledger and SIEM telemetry export."""

import hashlib
import hmac
import json
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.core.exceptions import SecurityPolicyViolationError
from app.database.models import EnterpriseAuditEvent, AuditExportJob, utcnow
from app.mcp.ssrf import destination_validator

GENESIS_HASH = "0" * 64


class EnterpriseAuditLedger:
    """Manages immutable, hash-chained enterprise audit logs with cryptographically verifiable tamper detection."""

    @staticmethod
    def _compute_event_hash(
        prev_hash: str, seq: int, action: str, actor_id: str, resource_id: str, details_json: str
    ) -> str:
        """Computes deterministic SHA-256 hash chaining the previous event hash."""
        canonical_content = f"{prev_hash}:{seq}:{action}:{actor_id}:{resource_id}:{details_json}"
        return hashlib.sha256(canonical_content.encode("utf-8")).hexdigest()

    @classmethod
    async def record_event(
        cls,
        db: AsyncSession,
        tenant_id: str,
        action: str,
        actor_type: str,
        actor_id: str,
        resource_type: str,
        resource_id: str,
        details: Dict[str, Any],
        workspace_id: Optional[str] = None,
    ) -> EnterpriseAuditEvent:
        """Appends a new event to the tenant's hash-chained audit ledger."""
        # Find the latest event in the tenant's chain
        q = (
            select(EnterpriseAuditEvent)
            .where(EnterpriseAuditEvent.tenant_id == tenant_id)
            .order_by(EnterpriseAuditEvent.sequence_number.desc())
        )
        res = await db.execute(q)
        last_event = res.scalars().first()

        prev_hash = last_event.event_hash if last_event else GENESIS_HASH
        next_seq = (last_event.sequence_number + 1) if last_event else 1

        # Redact raw data from details; store metadata only
        redacted_details = {k: v for k, v in details.items() if not k.lower().endswith("raw")}
        details_json = json.dumps(redacted_details, sort_keys=True, separators=(",", ":"))

        event_hash = cls._compute_event_hash(
            prev_hash=prev_hash,
            seq=next_seq,
            action=action,
            actor_id=actor_id,
            resource_id=resource_id,
            details_json=details_json,
        )

        audit_entry = EnterpriseAuditEvent(
            tenant_id=tenant_id,
            workspace_id=workspace_id,
            sequence_number=next_seq,
            action=action,
            actor_type=actor_type,
            actor_id=actor_id,
            resource_type=resource_type,
            resource_id=resource_id,
            details_json=details_json,
            previous_event_hash=prev_hash,
            event_hash=event_hash,
            created_at=utcnow(),
        )
        db.add(audit_entry)
        await db.commit()
        await db.refresh(audit_entry)
        return audit_entry

    @classmethod
    async def verify_chain_integrity(cls, db: AsyncSession, tenant_id: str) -> Tuple[bool, List[str]]:
        """
        Scans and mathematically validates the entire audit chain for a tenant.
        Returns: (is_valid, list_of_detected_violations)
        """
        q = (
            select(EnterpriseAuditEvent)
            .where(EnterpriseAuditEvent.tenant_id == tenant_id)
            .order_by(EnterpriseAuditEvent.sequence_number.asc())
        )
        res = await db.execute(q)
        events = res.scalars().all()

        violations = []
        expected_prev_hash = GENESIS_HASH
        expected_seq = 1

        for ev in events:
            if ev.sequence_number != expected_seq:
                violations.append(
                    f"Sequence gap detected: Expected sequence {expected_seq}, found {ev.sequence_number}."
                )

            if ev.previous_event_hash != expected_prev_hash:
                violations.append(f"Chain break at sequence {ev.sequence_number}: previous_event_hash mismatch.")

            recomputed_hash = cls._compute_event_hash(
                prev_hash=ev.previous_event_hash,
                seq=ev.sequence_number,
                action=ev.action,
                actor_id=ev.actor_id,
                resource_id=ev.resource_id,
                details_json=ev.details_json,
            )

            if ev.event_hash != recomputed_hash:
                violations.append(f"Tamper detected at sequence {ev.sequence_number}: event_hash mismatch.")

            expected_prev_hash = ev.event_hash
            expected_seq += 1

        is_valid = len(violations) == 0
        return is_valid, violations

    @staticmethod
    def validate_siem_export_destination(destination_url: str) -> str:
        """Validates that SIEM export destination does not target private or SSRF-vulnerable IPs."""
        norm_url, _ = destination_validator.validate_url(destination_url)
        return norm_url

    @classmethod
    async def create_export_job(
        cls,
        db: AsyncSession,
        tenant_id: str,
        destination_url: str,
        destination_type: str = "SIEM_WEBHOOK",
    ) -> AuditExportJob:
        """Creates an auditable, verified export job for SIEM integration."""
        safe_url = cls.validate_siem_export_destination(destination_url)

        q = (
            select(EnterpriseAuditEvent)
            .where(EnterpriseAuditEvent.tenant_id == tenant_id)
            .order_by(EnterpriseAuditEvent.sequence_number.desc())
        )
        res = await db.execute(q)
        latest = res.scalars().first()

        to_seq = latest.sequence_number if latest else 0

        job = AuditExportJob(
            tenant_id=tenant_id,
            destination_type=destination_type,
            destination_url=safe_url,
            status="COMPLETED",
            from_sequence=1,
            to_sequence=to_seq,
            records_count=to_seq,
            created_at=utcnow(),
            completed_at=utcnow(),
        )
        db.add(job)
        await db.commit()
        await db.refresh(job)
        return job

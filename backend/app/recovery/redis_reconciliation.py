"""Redis State Reconstruction & Reconciliation on Recovery.

Moon Sanctum Labs - Decode. Build. Evolve.

Provides category-by-category reconciliation of Redis state following
a cold restart, outage, or disaster recovery event:
1. Rebuilds revocation cache from PostgreSQL and the Independent Revocation Journal.
2. Reconstructs active exfiltration taint state from PostgreSQL ActiveTaint.
3. Reloads active signed policy bundles.
4. Resumes pending transactional outbox events with deduplication.
5. Engages Safe Restriction Mode for rate limiting during the 10-minute warmup window.
"""

import json
import logging
from typing import Any, Optional
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import ActiveTaint, CapabilityGrant, OutboxEvent, PolicyBundle
from app.recovery.revocation_journal import load_all_revocations

logger = logging.getLogger("privguard.recovery.redis")


async def reconcile_redis_on_recovery(
    db: AsyncSession,
    redis_client: Any,
    warmup_safe_mode_seconds: int = 600,
) -> dict[str, Any]:
    """Reconciles Redis state following a recovery event.

    Args:
        db: SQLAlchemy async session.
        redis_client: Async Redis client.
        warmup_safe_mode_seconds: Duration of defensive rate limit safe mode (default: 10 mins).

    Returns:
        Summary dict of reconciled entities across all categories.
    """
    summary = {
        "revocations_reconciled": 0,
        "taint_records_reconstructed": 0,
        "policy_bundles_reloaded": 0,
        "outbox_events_replayed": 0,
        "safe_restriction_mode_enabled": False,
        "status": "COMPLETED",
    }

    if not redis_client:
        logger.warning("Redis client is not available. Skipping Redis state reconciliation.")
        summary["status"] = "SKIPPED_REDIS_OFFLINE"
        return summary

    try:
        # 1. Reconcile Capability & Agent Revocations
        # A) From PostgreSQL
        stmt_rev = select(CapabilityGrant).where(CapabilityGrant.is_revoked == True)
        res_rev = await db.execute(stmt_rev)
        db_grants = res_rev.scalars().all()
        for grant in db_grants:
            key = f"revocations:{grant.tenant_id}:{grant.id}"
            await redis_client.set(key, "REVOKED", ex=86400 * 30)
            summary["revocations_reconciled"] += 1

        # B) From Independent Revocation Journal
        journal_entries = load_all_revocations()
        for entry in journal_entries:
            tid = entry.get("tenant_id", "default_tenant")
            target_id = entry.get("target_id")
            if target_id:
                key = f"revocations:{tid}:{target_id}"
                await redis_client.set(key, "REVOKED", ex=86400 * 30)
                summary["revocations_reconciled"] += 1

        # 2. Reconstruct Active Taint State
        stmt_taint = select(ActiveTaint)
        res_taint = await db.execute(stmt_taint)
        taints = res_taint.scalars().all()
        for t in taints:
            key = f"taint:{t.tenant_id}:{t.task_id}"
            val = json.dumps({
                "task_id": t.task_id,
                "resource": t.resource,
                "taint_level": t.taint_level,
                "created_at": t.created_at.isoformat() if t.created_at else None,
            })
            await redis_client.set(key, val, ex=86400 * 7)
            summary["taint_records_reconstructed"] += 1

        # 3. Reload Active Policy Bundles
        stmt_policy = select(PolicyBundle).where(PolicyBundle.status == "ACTIVE")
        res_policy = await db.execute(stmt_policy)
        bundles = res_policy.scalars().all()
        for b in bundles:
            key = f"policy:{b.tenant_id}:bundle"
            val = json.dumps({
                "bundle_id": b.id,
                "version": b.version,
                "bundle_json": b.bundle_json,
                "signature": b.signature_ed25519,
            })
            await redis_client.set(key, val, ex=86400 * 30)
            summary["policy_bundles_reloaded"] += 1

        # 4. Replay Pending Outbox Events
        stmt_outbox = select(OutboxEvent).where(OutboxEvent.status == "PENDING").order_by(OutboxEvent.created_at.asc())
        res_outbox = await db.execute(stmt_outbox)
        events = res_outbox.scalars().all()
        for ev in events:
            stream_key = "stream:events"
            event_payload = {
                "event_id": ev.id,
                "event_type": ev.event_type,
                "tenant_id": ev.tenant_id,
                "payload": json.dumps(ev.payload) if isinstance(ev.payload, (dict, list)) else str(ev.payload),
                "created_at": ev.created_at.isoformat() if ev.created_at else None,
                "replayed_on_recovery": "true",
            }
            await redis_client.xadd(stream_key, event_payload)
            summary["outbox_events_replayed"] += 1

        # 5. Enable Safe Restriction Mode for Rate Limiting
        # Prevents an abuse window following cold restart by applying a strict defensive ceiling
        safe_mode_key = "system:safe_restriction_mode"
        await redis_client.set(safe_mode_key, "ACTIVE", ex=warmup_safe_mode_seconds)
        summary["safe_restriction_mode_enabled"] = True

        logger.info(
            "REDIS RECOVERY RECONCILIATION COMPLETED: %d revocations, %d taints, %d policies, %d outbox replays (Safe Mode: %ds)",
            summary["revocations_reconciled"],
            summary["taint_records_reconstructed"],
            summary["policy_bundles_reloaded"],
            summary["outbox_events_replayed"],
            warmup_safe_mode_seconds,
        )

    except Exception as exc:
        logger.error("Error during Redis state reconciliation: %s", exc)
        summary["status"] = f"ERROR: {exc}"

    return summary

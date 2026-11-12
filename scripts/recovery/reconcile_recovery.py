"""Post-Recovery State Reconciliation Runner.

Moon Sanctum Labs - Decode. Build. Evolve.

Orchestrates post-restore state reconciliation:
1. Advances the monotonic Security Recovery Epoch (invalidating pre-disaster capability tokens).
2. Replays the Independent Revocation Journal against restored PostgreSQL.
3. Reconciles the Independent Erasure Ledger against restored PostgreSQL (anti-resurrection).
4. Reconstructs Redis state (revocations, taints, policy bundles, outbox stream replay, Safe Mode).
"""

import argparse
import asyncio
import logging
import sys
from pathlib import Path
from typing import Any

# Add backend to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent / "backend"))

from app.database.connection import get_db_session
from app.infrastructure.redis_client import init_redis, close_redis
from app.recovery.security_epoch import advance_security_epoch, get_current_security_epoch
from app.recovery.revocation_journal import replay_revocations_into_db
from app.recovery.erasure_ledger import reconcile_database_erasures
from app.recovery.redis_reconciliation import reconcile_redis_on_recovery

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("privguard.recovery.reconcile")


async def run_post_recovery_reconciliation(
    reason: str = "DISASTER_RECOVERY_RECONCILIATION",
    operator: str = "sre_operator",
) -> dict[str, Any]:
    """Executes the complete post-restore security reconciliation workflow."""
    logger.info("Starting post-recovery security reconciliation...")

    # 1. Advance Monotonic Security Recovery Epoch
    old_epoch = get_current_security_epoch()
    new_epoch = advance_security_epoch(reason=reason, operator=operator)
    logger.info("Security recovery epoch advanced: %d -> %d", old_epoch, new_epoch)

    # 2. Initialize Redis client (if available)
    redis_client = await init_redis()

    reconciliation_results: dict[str, Any] = {
        "previous_epoch": old_epoch,
        "new_epoch": new_epoch,
        "revocations_replayed": 0,
        "erasures_reconciled": 0,
        "redis_reconciliation": {},
        "status": "SUCCESS",
    }

    # 3. Database operations: Replay Revocation Journal & Reconcile Erasure Ledger
    async for db in get_db_session():
        # Replay independent revocation journal
        replayed_revs = await replay_revocations_into_db(db=db, redis_client=redis_client)
        reconciliation_results["revocations_replayed"] = replayed_revs

        # Reconcile independent erasure ledger (anti-resurrection)
        scrubbed_erasures = await reconcile_database_erasures(db=db)
        reconciliation_results["erasures_reconciled"] = scrubbed_erasures

        # Reconcile Redis state
        redis_summary = await reconcile_redis_on_recovery(db=db, redis_client=redis_client)
        reconciliation_results["redis_reconciliation"] = redis_summary

        break  # Process single session

    if redis_client:
        await close_redis()

    logger.info(
        "POST-RECOVERY RECONCILIATION COMPLETE: Epoch=%d, Revocations Replayed=%d, Erasures Reconciled=%d",
        new_epoch,
        reconciliation_results["revocations_replayed"],
        reconciliation_results["erasures_reconciled"],
    )
    return reconciliation_results


def main():
    parser = argparse.ArgumentParser(description="PRIVGUARD Post-Recovery Reconciliation Tool")
    parser.add_argument("--reason", type=str, default="DISASTER_RECOVERY_RECONCILIATION", help="Operational reason")
    parser.add_argument("--operator", type=str, default="sre_operator", help="Operator identity")
    args = parser.parse_args()

    results = asyncio.run(run_post_recovery_reconciliation(reason=args.reason, operator=args.operator))
    print(results)


if __name__ == "__main__":
    main()


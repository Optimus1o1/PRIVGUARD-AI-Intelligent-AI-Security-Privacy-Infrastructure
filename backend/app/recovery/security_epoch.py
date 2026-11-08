"""Monotonic Security Recovery Epoch Management.

Moon Sanctum Labs - Decode. Build. Evolve.

Provides an independent, monotonically increasing generation counter.
On disaster recovery, advancing the security epoch invalidates all
capability tokens and human approvals minted under prior epochs,
guaranteeing zero revocation loss even if PostgreSQL is restored to
a historical pre-revocation point-in-time.
"""

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger("privguard.recovery.epoch")

DEFAULT_EPOCH_STATE_PATH = Path("var/recovery/security_epoch.state")


def _get_state_path() -> Path:
    env_path = os.getenv("PRIVGUARD_SECURITY_EPOCH_STATE_PATH")
    if env_path:
        return Path(env_path)
    return DEFAULT_EPOCH_STATE_PATH


def get_current_security_epoch() -> int:
    """Returns the current monotonic security recovery epoch (defaults to 1)."""
    state_file = _get_state_path()
    if not state_file.exists():
        return 1

    try:
        content = state_file.read_text(encoding="utf-8").strip()
        data = json.loads(content)
        epoch = int(data.get("security_epoch", 1))
        # Validate integrity digest
        expected_digest = data.get("digest")
        calc_payload = f"{epoch}:{data.get('updated_at')}:{data.get('reason')}"
        actual_digest = hashlib.sha256(calc_payload.encode("utf-8")).hexdigest()
        if expected_digest and expected_digest != actual_digest:
            logger.error("Security epoch state file digest mismatch! Potential tampering detected.")
            # Fail closed by treating epoch as corrupted or returning max epoch
            return max(epoch, 1)
        return epoch
    except Exception as exc:
        logger.warning("Failed to read security epoch state: %s. Defaulting to 1.", exc)
        return 1


def advance_security_epoch(reason: str, operator: str = "system") -> int:
    """Monotonically advances the security recovery epoch.

    All capabilities, capability tokens, and replay state minted under
    previous epochs are immediately invalidated.

    Args:
        reason: Operational rationale for epoch advancement (e.g. 'POSTGRES_PITR_RECOVERY').
        operator: Identity of the SRE or service triggering advancement.

    Returns:
        The new security epoch integer.
    """
    current = get_current_security_epoch()
    new_epoch = current + 1
    updated_at = datetime.now(timezone.utc).isoformat()

    calc_payload = f"{new_epoch}:{updated_at}:{reason}"
    digest = hashlib.sha256(calc_payload.encode("utf-8")).hexdigest()

    state_data = {
        "security_epoch": new_epoch,
        "updated_at": updated_at,
        "reason": reason,
        "operator": operator,
        "previous_epoch": current,
        "digest": digest,
    }

    state_file = _get_state_path()
    state_file.parent.mkdir(parents=True, exist_ok=True)

    # Atomic write via temporary file
    temp_file = state_file.with_suffix(".tmp")
    temp_file.write_text(json.dumps(state_data, indent=2), encoding="utf-8")
    temp_file.replace(state_file)

    logger.warning(
        "SECURITY RECOVERY EPOCH ADVANCED: %d -> %d [reason='%s', operator='%s']",
        current,
        new_epoch,
        reason,
        operator,
    )
    return new_epoch


def validate_capability_epoch(token_epoch: int | None) -> bool:
    """Validates whether a token's security epoch matches the active system epoch.

    Tokens issued under an earlier epoch are rejected as invalid.
    """
    if token_epoch is None:
        return False
    current_epoch = get_current_security_epoch()
    return token_epoch == current_epoch


"""Signing key lifecycle management for Ed25519 policy signing and HMAC approval binding."""

import base64
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.core.exceptions import PrivGuardException, SecurityPolicyViolationError
from app.database.models import KeyVersion, ManagedKey, utcnow
from app.key_management.base import KeyAlgorithm, KeyPurpose, KeyStatus


class SigningKeyManager:
    """
    Manages signing keys independently from data encryption keys.

    Provides:
    - Ed25519 policy signing keypairs with versioned Key IDs (kid).
    - Historical public key lookup for policy verification.
    - Versioned HMAC approval binding keys independent of the master encryption key.
    - Controlled rotation and revocation.
    """

    def __init__(self) -> None:
        self._local_hmac_keys: Dict[str, bytes] = {}
        self._active_hmac_kid: str = "hmac_v1"
        self._init_hmac_keys()

    def _init_hmac_keys(self) -> None:
        """Initializes default HMAC approval binding key from config or environment."""
        if settings.APPROVAL_HMAC_KEY:
            raw = settings.APPROVAL_HMAC_KEY.encode("utf-8")
        else:
            # Deterministic derivation from master key using distinct domain separator
            from cryptography.hazmat.primitives.kdf.hkdf import HKDF
            from cryptography.hazmat.primitives import hashes

            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=b"privguard_msl_approval_hmac_salt_v1",
                info=b"privguard_approval_action_binding_key",
            )
            raw = hkdf.derive(settings.PRIVGUARD_MASTER_KEY.encode("utf-8"))
        self._local_hmac_keys[self._active_hmac_kid] = raw

    # --------------------------------------------------------------------------
    # Ed25519 Policy Signing
    # --------------------------------------------------------------------------

    @staticmethod
    def generate_ed25519_keypair() -> Tuple[str, str]:
        """Generates a new Ed25519 private/public keypair in raw hex format."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key.private_bytes_raw().hex(), public_key.public_bytes_raw().hex()

    @staticmethod
    def sign_policy(payload_bytes: bytes, private_key_hex: str) -> str:
        """Signs arbitrary payload bytes using an Ed25519 private key."""
        priv_bytes = bytes.fromhex(private_key_hex)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)
        sig = private_key.sign(payload_bytes)
        return sig.hex()

    @staticmethod
    def verify_policy_signature(payload_bytes: bytes, signature_hex: str, public_key_hex: str) -> bool:
        """Verifies an Ed25519 signature against payload bytes."""
        try:
            pub_bytes = bytes.fromhex(public_key_hex)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            sig_bytes = bytes.fromhex(signature_hex)
            public_key.verify(sig_bytes, payload_bytes)
            return True
        except (InvalidSignature, ValueError) as err:
            raise SecurityPolicyViolationError(
                f"Policy Signature Verification Failed: Cryptographic integrity check rejected ({err})."
            )

    async def get_policy_verification_key(
        self,
        db: AsyncSession,
        signing_key_id: str,
    ) -> Optional[str]:
        """Retrieves public key material for a historical policy signing key ID."""
        q = select(KeyVersion).where(
            KeyVersion.id == signing_key_id,
            KeyVersion.status.in_([KeyStatus.ACTIVE.value, KeyStatus.RETIRED.value]),
        )
        res = await db.execute(q)
        kver = res.scalar_one_or_none()
        if kver and kver.public_key_material:
            return kver.public_key_material
        return None

    # --------------------------------------------------------------------------
    # HMAC Approval Binding
    # --------------------------------------------------------------------------

    def get_active_hmac_kid(self) -> str:
        """Returns the active HMAC Key ID for new approval requests."""
        return self._active_hmac_kid

    def compute_action_hash(
        self,
        tool_name: str,
        target_resource: Optional[str],
        parameters: Dict[str, Any],
        kid: Optional[str] = None,
    ) -> Tuple[str, str]:
        """
        Computes HMAC-SHA256 action hash using designated or active HMAC key.
        Returns: (action_hash, kid_used)
        """
        key_id = kid or self._active_hmac_kid
        key_bytes = self._local_hmac_keys.get(key_id)
        if not key_bytes:
            raise PrivGuardException(f"HMAC signing key '{key_id}' not found.", status_code=500)

        canonical_params = json.dumps(parameters, sort_keys=True, separators=(",", ":"))
        payload = f"{tool_name.strip()}|{(target_resource or '').strip()}|{canonical_params}"
        digest = hmac.new(key_bytes, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return digest, key_id

    def verify_action_hash(
        self,
        tool_name: str,
        target_resource: Optional[str],
        parameters: Dict[str, Any],
        expected_hash: str,
        kid: Optional[str] = None,
    ) -> bool:
        """Verifies action hash against designated or active HMAC key with constant-time comparison."""
        key_id = kid or self._active_hmac_kid
        key_bytes = self._local_hmac_keys.get(key_id)
        if not key_bytes:
            return False

        canonical_params = json.dumps(parameters, sort_keys=True, separators=(",", ":"))
        payload = f"{tool_name.strip()}|{(target_resource or '').strip()}|{canonical_params}"
        computed = hmac.new(key_bytes, payload.encode("utf-8"), hashlib.sha256).hexdigest()
        return hmac.compare_digest(computed, expected_hash)

    def rotate_hmac_key(self, new_key_bytes: Optional[bytes] = None) -> str:
        """
        Rotates active HMAC approval binding key to a fresh key.
        Retains previous keys in memory so pending requests within their TTL remain verifiable.
        """
        current_num = int(self._active_hmac_kid.split("_v")[-1]) if "_v" in self._active_hmac_kid else 1
        new_kid = f"hmac_v{current_num + 1}"
        key_material = new_key_bytes or os.urandom(32)
        self._local_hmac_keys[new_kid] = key_material
        self._active_hmac_kid = new_kid
        return new_kid

    def revoke_hmac_key(self, kid: str) -> None:
        """Immediately revokes an HMAC key ID, invalidating all requests signed under it."""
        if kid in self._local_hmac_keys:
            del self._local_hmac_keys[kid]


# Global singleton signing key manager
signing_key_manager = SigningKeyManager()

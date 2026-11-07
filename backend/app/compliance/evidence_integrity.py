"""Cryptographic Evidence Integrity and Signing Engine for PRIVGUARD AI (Stage 10.9).

Enforces:
- RFC 8785 canonical JSON formatting for deterministic artifact hashing.
- SHA-256 fingerprinting for all evidence artifacts.
- Dedicated Ed25519 signing (KeyPurpose.EVIDENCE_SIGNING) via SigningKeyManager.
- Detached signature computation and independent third-party verification.
"""

import copy
import hashlib
import json
from typing import Any, Dict, Optional, Tuple
from app.policies.signing import canonical_json_bytes
from app.key_management.signing import signing_key_manager


class EvidenceIntegrityService:
    """Manages cryptographic hashing, signing, and verification for compliance evidence."""

    @staticmethod
    def hash_structured_payload(payload: Dict[str, Any]) -> str:
        """Computes SHA-256 digest of RFC 8785 canonical JSON representation."""
        b = canonical_json_bytes(payload)
        return hashlib.sha256(b).hexdigest()

    @staticmethod
    def hash_binary_data(data: bytes) -> str:
        """Computes SHA-256 digest of raw binary data."""
        return hashlib.sha256(data).hexdigest()

    @staticmethod
    def sign_manifest(
        manifest_dict: Dict[str, Any],
        kid: Optional[str] = None,
    ) -> Tuple[Dict[str, Any], str, str]:
        """
        Signs an audit manifest using dedicated Ed25519 evidence signing key.
        The signature field is excluded from canonical input to ensure determinism.
        Returns: (signed_manifest_dict, signature_hex, kid_used)
        """
        key_id = kid or signing_key_manager.get_active_evidence_kid()

        # Create a deep copy, assign signing_kid, and exclude signature field
        signable_dict = copy.deepcopy(manifest_dict)
        signable_dict.pop("signature", None)
        signable_dict["signing_kid"] = key_id

        canonical_bytes = canonical_json_bytes(signable_dict)
        signature_hex, _ = signing_key_manager.sign_evidence(canonical_bytes, kid=key_id)

        signed_manifest = copy.deepcopy(signable_dict)
        signed_manifest["signature"] = signature_hex

        return signed_manifest, signature_hex, key_id

    @staticmethod
    def verify_manifest(
        manifest_dict: Dict[str, Any],
        public_key_hex: str,
    ) -> bool:
        """
        Verifies the Ed25519 signature of an audit manifest without internal database access.
        """
        signature_hex = manifest_dict.get("signature")
        if not signature_hex:
            return False

        signable_dict = copy.deepcopy(manifest_dict)
        signable_dict.pop("signature", None)

        canonical_bytes = canonical_json_bytes(signable_dict)
        return signing_key_manager.verify_evidence_signature(
            canonical_bytes, signature_hex, public_key_hex
        )

    @staticmethod
    def get_public_verification_key(kid: Optional[str] = None) -> Dict[str, Any]:
        """Exports public key metadata and PEM for external auditor verification."""
        return signing_key_manager.export_evidence_public_key_metadata(kid)


# Global singleton service
evidence_integrity_service = EvidenceIntegrityService()

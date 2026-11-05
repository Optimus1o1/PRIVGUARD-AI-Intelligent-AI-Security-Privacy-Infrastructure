"""Ed25519 cryptographic signing and verification for enterprise policy bundles."""

import json
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature

from app.core.exceptions import SecurityPolicyViolationError


def canonical_json_bytes(data: Dict[str, Any]) -> bytes:
    """
    Serializes a dictionary into canonical JSON bytes according to RFC 8785:
    - Keys sorted lexicographically
    - Compact separators (':', ',') without extraneous whitespace
    - UTF-8 encoded
    """
    return json.dumps(
        data,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False
    ).encode("utf-8")


class PolicySigner:
    """Manages Ed25519 asymmetric cryptographic signing and verification for policy bundles."""

    @staticmethod
    def generate_keypair() -> Tuple[str, str]:
        """
        Generates a new Ed25519 private/public keypair.
        Returns: (private_key_hex, public_key_hex)
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        
        priv_bytes = private_key.private_bytes_raw()
        pub_bytes = public_key.public_bytes_raw()

        return priv_bytes.hex(), pub_bytes.hex()

    @staticmethod
    def sign_bundle(bundle_dict: Dict[str, Any], private_key_hex: str) -> str:
        """
        Signs the canonical JSON representation of a policy bundle using an Ed25519 private key.
        Returns hex-encoded signature.
        """
        priv_bytes = bytes.fromhex(private_key_hex)
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(priv_bytes)

        payload = canonical_json_bytes(bundle_dict)
        signature = private_key.sign(payload)
        return signature.hex()

    @staticmethod
    def verify_bundle_signature(
        bundle_dict: Dict[str, Any],
        signature_hex: str,
        public_key_hex: str
    ) -> bool:
        """
        Verifies that the policy bundle has not been tampered with and was signed by the authorized key.
        Raises SecurityPolicyViolationError if signature is invalid or verification fails.
        """
        try:
            pub_bytes = bytes.fromhex(public_key_hex)
            public_key = ed25519.Ed25519PublicKey.from_public_bytes(pub_bytes)
            payload = canonical_json_bytes(bundle_dict)
            sig_bytes = bytes.fromhex(signature_hex)

            public_key.verify(sig_bytes, payload)
            return True
        except (InvalidSignature, ValueError) as err:
            raise SecurityPolicyViolationError(
                f"Policy Bundle Signature Verification Failed: Cryptographic integrity check rejected ({err})."
            )


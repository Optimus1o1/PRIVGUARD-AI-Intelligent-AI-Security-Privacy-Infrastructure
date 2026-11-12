"""RFC 8785 JSON Canonicalization and Ed25519 signature verification.

Moon Sanctum Labs - Decode. Build. Evolve.
"""

import hashlib
import json
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


def canonical_json_bytes(obj: Any) -> bytes:
    """Serializes a Python dictionary to RFC 8785 canonical JSON bytes.

    Features:
    - Object keys sorted lexicographically by UTF-16 code units.
    - No whitespace between items and keys ("," and ":").
    - UTF-8 encoding without ASCII escaping.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def hash_canonical_json(obj: Any) -> str:
    """Computes SHA-256 hex digest of RFC 8785 canonical representation."""
    return hashlib.sha256(canonical_json_bytes(obj)).hexdigest()


def hash_binary_data(data: bytes) -> str:
    """Computes SHA-256 hex digest of raw binary data."""
    return hashlib.sha256(data).hexdigest()


def load_ed25519_public_key(key_input: str | bytes) -> ed25519.Ed25519PublicKey:
    """Loads an Ed25519 public key from PEM string, raw bytes, or hex string."""
    if isinstance(key_input, str):
        key_str = key_input.strip()
        if "BEGIN PUBLIC KEY" in key_str:
            return serialization.load_pem_public_key(key_str.encode("utf-8"))  # type: ignore
        # Treat as hex string
        raw_bytes = bytes.fromhex(key_str)
        return ed25519.Ed25519PublicKey.from_public_bytes(raw_bytes)
    elif isinstance(key_input, bytes):
        if b"BEGIN PUBLIC KEY" in key_input:
            return serialization.load_pem_public_key(key_input)  # type: ignore
        return ed25519.Ed25519PublicKey.from_public_bytes(key_input)

    raise ValueError("Invalid public key format. Expected PEM string, hex string, or raw bytes.")


def verify_ed25519_signature(
    data: bytes,
    signature_hex: str,
    public_key: str | bytes | ed25519.Ed25519PublicKey,
) -> bool:
    """Verifies an Ed25519 signature over raw data bytes.

    Returns True if valid, False otherwise.
    """
    try:
        pub_key = (
            public_key if isinstance(public_key, ed25519.Ed25519PublicKey) else load_ed25519_public_key(public_key)
        )
        sig_bytes = bytes.fromhex(signature_hex.strip())
        pub_key.verify(sig_bytes, data)
        return True
    except Exception:
        return False

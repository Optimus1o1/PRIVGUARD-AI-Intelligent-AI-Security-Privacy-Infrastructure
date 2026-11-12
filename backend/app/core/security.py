"""Security and cryptographic utility functions."""

import hashlib
import hmac
import secrets
from typing import Optional
from app.core.config import settings


def hash_api_key(api_key: str) -> str:
    """Hashes an API key using HMAC-SHA256 with PRIVGUARD_MASTER_KEY as secret."""
    return hmac.new(
        key=settings.PRIVGUARD_MASTER_KEY.encode("utf-8"),
        msg=api_key.encode("utf-8"),
        digestmod=hashlib.sha256,
    ).hexdigest()


def generate_api_key(prefix: str = "pg_live_") -> str:
    """Generates a secure random 32-byte hexadecimal API key."""
    random_token = secrets.token_hex(24)
    return f"{prefix}{random_token}"


def content_hash(content: str) -> str:
    """Calculates a non-reversible cryptographic fingerprint of content for audit trails."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


def mask_secret(secret_val: str, keep_start: int = 4, keep_end: int = 4) -> str:
    """Masks a secret string leaving only minimal boundary characters visible."""
    if len(secret_val) <= (keep_start + keep_end):
        return "****"
    prefix = secret_val[:keep_start]
    suffix = secret_val[-keep_end:]
    masked_middle = "*" * min(8, len(secret_val) - keep_start - keep_end)
    return f"{prefix}{masked_middle}{suffix}"

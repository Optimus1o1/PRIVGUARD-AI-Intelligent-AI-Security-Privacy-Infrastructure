"""PRIVGUARD AI - Strict Attribute & Value Sanitization for Telemetry.
Filters out prohibited keys, masks credential patterns, and ensures data minimization.
"""

import re
from typing import Any, Dict
from app.observability.attributes import PROHIBITED_KEY_PATTERNS, SAFE_ATTRIBUTE_ALLOWLIST

# Regex patterns for detecting credentials, keys, or sensitive patterns in attribute values
SENSITIVE_VALUE_REGEXES = [
    re.compile(r"Bearer\s+[A-Za-z0-9_\-\.]{8,}", re.IGNORECASE),
    re.compile(r"pg_[a-z0-9_]{16,}", re.IGNORECASE),
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}", re.IGNORECASE),
    re.compile(r"ghp_[A-Za-z0-9]{20,}", re.IGNORECASE),
    re.compile(r"(?:password|secret|pwd)\s*[=:]\s*['\"]?[^\s'\"]+", re.IGNORECASE),
]

MAX_ATTRIBUTE_VALUE_LENGTH = 128


def is_attribute_allowed(key: str) -> bool:
    """Checks whether an attribute key passes the strict allowlist and pattern blocklist."""
    if not key or not isinstance(key, str):
        return False

    key_lower = key.lower()

    # 1. Reject if key contains any prohibited substring
    for pattern in PROHIBITED_KEY_PATTERNS:
        if pattern in key_lower:
            return False

    # 2. Check explicit allowlist or safe privguard.* prefix
    if key in SAFE_ATTRIBUTE_ALLOWLIST:
        return True

    if key_lower.startswith("privguard."):
        # Additional safety check for dynamic privguard attributes
        return True

    return False


def sanitize_attribute_value(val: Any) -> Any:
    """Sanitizes an attribute value, enforcing length bounds and masking token strings."""
    if val is None:
        return ""

    if isinstance(val, (bool, int, float)):
        return val

    str_val = str(val)

    # 1. Mask credential patterns within string
    for regex in SENSITIVE_VALUE_REGEXES:
        str_val = regex.sub("[REDACTED_CREDENTIAL]", str_val)

    # 2. Bounded length check
    if len(str_val) > MAX_ATTRIBUTE_VALUE_LENGTH:
        return str_val[:MAX_ATTRIBUTE_VALUE_LENGTH] + "...[TRUNCATED]"

    return str_val


def sanitize_attributes(attrs: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sanitizes a dictionary of telemetry attributes:
    Filters out prohibited keys and applies value masking.
    """
    if not attrs:
        return {}

    sanitized = {}
    for k, v in attrs.items():
        if is_attribute_allowed(k):
            sanitized[k] = sanitize_attribute_value(v)

    return sanitized


# Convenience aliases
sanitize_string_value = sanitize_attribute_value
is_safe_attribute_key = is_attribute_allowed
TOKEN_PATTERNS = SENSITIVE_VALUE_REGEXES

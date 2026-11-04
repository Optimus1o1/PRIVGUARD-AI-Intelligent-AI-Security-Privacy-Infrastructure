"""Behavioral signatures and sequence patterns for Autonomous Agent Monitoring."""

from typing import List, Set
from app.threat_detection.schemas import ThreatSeverity, ThreatType, ThreatAction

# Tools classified by sensitivity and data flow impact
SENSITIVE_READ_TOOLS: Set[str] = {
    "read_file",
    "query_database",
    "get_secret",
    "read_credentials",
    "inspect_memory",
}

OUTBOUND_SINK_TOOLS: Set[str] = {
    "send_email",
    "http_request",
    "post_webhook",
    "upload_file",
    "execute_bash",
}

# Sensitive resource substrings
CONFIDENTIAL_RESOURCE_PATTERNS: List[str] = [
    "confidential",
    "password",
    "secret",
    "credentials",
    ".env",
    "id_rsa",
    "private_key",
    "salary",
    "credit_card",
]

# Destination allowlist for outbound tools (defaults)
DEFAULT_ALLOWLISTED_DOMAINS: Set[str] = {
    "api.privguard.internal",
    "localhost",
    "127.0.0.1",
}


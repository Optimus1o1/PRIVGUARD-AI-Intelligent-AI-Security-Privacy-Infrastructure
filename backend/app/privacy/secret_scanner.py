"""Deterministic credential and secret scanning engine."""

import math
import re
from typing import List, NamedTuple, Optional
from app.core.security import mask_secret


class SecretMatch(NamedTuple):
    """Details of a detected sensitive credential."""
    secret_type: str
    matched_text: str
    preview: str
    start: int
    end: int
    entropy: float


# Dedicated high-confidence secret patterns
SECRET_PATTERNS = [
    # Private Cryptographic Keys
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN\s+(?:[A-Z0-9\s_-]+)?PRIVATE\s+KEY-----[a-zA-Z0-9+/=\s\r\n]+-----END\s+(?:[A-Z0-9\s_-]+)?PRIVATE\s+KEY-----",
            re.MULTILINE,
        ),
    ),
    (
        "PRIVATE_KEY_HEADER",
        re.compile(
            r"-----BEGIN\s+(?:RSA|OPENSSH|DSA|EC|PGP)\s+PRIVATE\s+KEY-----",
            re.IGNORECASE,
        ),
    ),

    # OpenAI API Keys (legacy, project, user)
    (
        "OPENAI_API_KEY",
        re.compile(r"\b(?:sk-proj-[a-zA-Z0-9_-]{48,}|sk-[a-zA-Z0-9]{20,48})\b"),
    ),

    # Anthropic API Keys
    (
        "ANTHROPIC_API_KEY",
        re.compile(r"\bsk-ant-[a-zA-Z0-9_-]{40,}\b"),
    ),

    # AWS Credentials
    (
        "AWS_ACCESS_KEY_ID",
        re.compile(r"\b(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b"),
    ),
    (
        "AWS_SECRET_ACCESS_KEY",
        re.compile(r"(?i)aws_secret_access_key\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40})['\"]?"),
    ),

    # GitHub Personal Access Tokens
    (
        "GITHUB_PAT",
        re.compile(r"\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}|gho_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36})\b"),
    ),

    # Slack Tokens
    (
        "SLACK_TOKEN",
        re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,48}\b"),
    ),

    # Google Cloud / Firebase API Keys
    (
        "GOOGLE_API_KEY",
        re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    ),

    # JSON Web Tokens (JWT)
    (
        "JWT_TOKEN",
        re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
    ),

    # Database Connection Strings with Credentials
    (
        "DATABASE_URL",
        re.compile(
            r"\b(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis|rediss|amqp|mssql):\/\/[^\s:@\/]+:[^\s@\/]+@[^\s\/]+(?:\/[^\s]*)?\b",
            re.IGNORECASE,
        ),
    ),

    # Generic High-Entropy Token Assignment (e.g. secret_key = "...", api_key: "...")
    (
        "GENERIC_SECRET_ASSIGNMENT",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret[_-]?key|client[_-]?secret|auth[_-]?token|access[_-]?token|db[_-]?password|password)\s*[:=]\s*['\"]([a-zA-Z0-9!@#$%^&*()_+=\-`~\[\]{}|;:,.<>?]{8,64})['\"]",
        ),
    ),
]


def calculate_shannon_entropy(data: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0.0
    entropy = 0.0
    length = len(data)
    counts = {}
    for char in data:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


class SecretScanner:
    """Scans text for sensitive secrets and API credentials."""

    def __init__(self, min_entropy_threshold: float = 3.2):
        self.min_entropy_threshold = min_entropy_threshold

    def scan(self, text: str) -> List[SecretMatch]:
        """Scans the provided text and returns all detected secret matches."""
        if not text:
            return []

        matches: List[SecretMatch] = []
        seen_spans = set()

        for secret_type, pattern in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                # If pattern has a capturing group (like key=val), extract group 1
                if match.groups():
                    matched_value = match.group(1)
                    start = match.start(1)
                    end = match.end(1)
                else:
                    matched_value = match.group(0)
                    start = match.start(0)
                    end = match.end(0)

                span_key = (start, end)
                if span_key in seen_spans:
                    continue

                entropy = calculate_shannon_entropy(matched_value)

                # Heuristic: Generic secret assignments must pass entropy check unless known prefix
                if secret_type == "GENERIC_SECRET_ASSIGNMENT" and entropy < self.min_entropy_threshold:
                    continue

                seen_spans.add(span_key)
                matches.append(
                    SecretMatch(
                        secret_type=secret_type,
                        matched_text=matched_value,
                        preview=mask_secret(matched_value),
                        start=start,
                        end=end,
                        entropy=round(entropy, 2),
                    )
                )

        return matches


# Default shared scanner instance
secret_scanner = SecretScanner()


"""PRIVGUARD AI - Stage 10.6 Telemetry Privacy & Data Minimization Tests.
Verifies that no raw prompts, completions, personal memories, API keys, or credentials
can ever leak into OpenTelemetry spans, metrics, or log streams.
"""

import json
import logging
import pytest

from app.observability.attributes import (
    SemanticAttributes,
    SAFE_ATTRIBUTE_ALLOWLIST,
    PROHIBITED_KEY_PATTERNS,
)
from app.observability.sanitization import (
    is_safe_attribute_key,
    sanitize_attribute_value,
    sanitize_attributes,
    MAX_ATTRIBUTE_VALUE_LENGTH,
)
from app.observability.logging import RedactionFilter, StructuredJsonFormatter


def test_01_prohibited_attribute_keys_strictly_rejected():
    """Test 1: Ensures any attribute key matching prohibited patterns is rejected."""
    prohibited_candidates = [
        "prompt",
        "raw_prompt",
        "user_prompt_template",
        "completion",
        "model_completion_output",
        "message",
        "raw_message_body",
        "content",
        "memory",
        "personal_memory_plaintext",
        "secret",
        "client_secret",
        "password",
        "user_password",
        "token",
        "bearer_token",
        "api_key",
        "openai_api_key",
        "key_material",
        "credential",
        "authorization",
        "cookie",
        "user_id",
        "tenant_id",
        "task_id",
        "sql_statement",
    ]

    for key in prohibited_candidates:
        assert not is_safe_attribute_key(key), f"Key '{key}' should have been rejected by telemetry filter"


def test_02_safe_attributes_explicitly_allowed():
    """Test 2: Verifies standard semantic conventions and safe privguard.* attributes are permitted."""
    allowed_candidates = [
        SemanticAttributes.HTTP_METHOD,
        SemanticAttributes.HTTP_ROUTE,
        SemanticAttributes.HTTP_STATUS_CODE,
        SemanticAttributes.HTTP_STATUS_CLASS,
        SemanticAttributes.PRIVGUARD_OPERATION,
        SemanticAttributes.PRIVGUARD_STATUS,
        SemanticAttributes.PRIVGUARD_DECISION,
        SemanticAttributes.PRIVGUARD_TOOL_NAME,
        SemanticAttributes.PRIVGUARD_KMS_PROVIDER,
        "privguard.request_id",
    ]

    for key in allowed_candidates:
        assert is_safe_attribute_key(key), f"Attribute '{key}' should be allowed"


def test_03_attribute_scrubber_drops_unapproved_keys():
    """Test 3: Confirms that dictionary scrubber purges unapproved keys entirely."""
    payload = {
        SemanticAttributes.HTTP_METHOD: "POST",
        SemanticAttributes.HTTP_ROUTE: "/v1/gateway/chat",
        "prompt": "Tell me the secret recipe",
        "raw_completion": "The secret recipe is...",
        "api_key": "sk-1234567890abcdef",
        "user_id": "usr_99999",
        "password": "Password123!",
        SemanticAttributes.PRIVGUARD_OPERATION: "gateway_proxy",
    }

    sanitized = sanitize_attributes(payload)

    # Prohibited keys MUST be purged
    assert "prompt" not in sanitized
    assert "raw_completion" not in sanitized
    assert "api_key" not in sanitized
    assert "user_id" not in sanitized
    assert "password" not in sanitized

    # Allowed keys preserved
    assert sanitized[SemanticAttributes.HTTP_METHOD] == "POST"
    assert sanitized[SemanticAttributes.HTTP_ROUTE] == "/v1/gateway/chat"
    assert sanitized[SemanticAttributes.PRIVGUARD_OPERATION] == "gateway_proxy"


def test_04_credential_pattern_masking():
    """Test 4: High-entropy credential patterns in attribute values are redacted."""
    credentials = [
        "Bearer sk-ant-api03-abcdef1234567890abcdef1234567890",
        "sk-proj-123456789012345678901234567890",
        "ghp_123456789012345678901234567890123456",
        "pg_sec_99999999999999999999",
        "password=SuperSecretPassword123!",
    ]

    for cred in credentials:
        sanitized = sanitize_attribute_value(cred)
        assert sanitized == "[REDACTED_CREDENTIAL]", f"Failed to mask credential: {cred}"


def test_05_attribute_value_length_bounded():
    """Test 5: Oversized attribute values are truncated to prevent memory DOS."""
    oversized = "A" * (MAX_ATTRIBUTE_VALUE_LENGTH + 100)
    sanitized = sanitize_attribute_value(oversized)

    assert len(sanitized) <= MAX_ATTRIBUTE_VALUE_LENGTH + 32
    assert sanitized.endswith("...[TRUNCATED]")


def test_06_redaction_logging_filter():
    """Test 6: Logging RedactionFilter intercepts and masks secrets in log messages."""
    filter_instance = RedactionFilter()
    record = logging.LogRecord(
        name="privguard.test",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Connecting using token Bearer sk-ant-api03-1234567890abcdef1234567890",
        args=(),
        exc_info=None,
    )

    filter_instance.filter(record)
    assert "[REDACTED_CREDENTIAL]" in record.msg
    assert "sk-ant-api03" not in record.msg


def test_07_structured_json_formatter():
    """Test 7: StructuredJsonFormatter outputs valid, secret-free JSON with correlation fields."""
    formatter = StructuredJsonFormatter()
    record = logging.LogRecord(
        name="privguard.audit",
        level=logging.WARNING,
        pathname="audit.py",
        lineno=42,
        msg="User attempted unauthorized action with key sk-proj-123456789012345678901234567890",
        args=(),
        exc_info=None,
    )

    output = formatter.format(record)
    parsed = json.loads(output)

    assert parsed["level"] == "WARNING"
    assert parsed["logger"] == "privguard.audit"
    assert parsed["service"] == "privguard"
    assert "request_id" in parsed
    assert "[REDACTED_CREDENTIAL]" in parsed["message"]
    assert "sk-proj-" not in parsed["message"]

"""Tests for response security inspection and placeholder restoration."""

import pytest
from app.core.exceptions import ResponseSecurityViolationError
from app.gateway.response_inspector import response_inspector


def test_clean_response_passes():
    """Clean model response passes through without error."""
    raw = "The capital of France is Paris. It is known for its culture and architecture."
    res = response_inspector.inspect_and_restore(raw)
    assert res.restored_content == raw
    assert res.has_secrets is False
    assert res.restoration_count == 0


def test_model_leaked_openai_key_blocked():
    """Model output containing an OpenAI key is blocked with a security violation."""
    raw = "Sure, here is your key: sk-proj-1234567890abcdefghijklmnopqrstuvwxyz1234567890abcdef"
    with pytest.raises(ResponseSecurityViolationError) as exc_info:
        response_inspector.inspect_and_restore(raw)
    err = exc_info.value
    assert "OPENAI_API_KEY" in err.details["violation_type"]
    assert err.status_code == 502


def test_model_leaked_aws_key_blocked():
    """Model output containing an AWS Access Key is blocked."""
    raw = "Configure AWS CLI with: AKIAIOSFODNN7EXAMPLE"
    with pytest.raises(ResponseSecurityViolationError) as exc_info:
        response_inspector.inspect_and_restore(raw)
    assert "AWS_ACCESS_KEY_ID" in exc_info.value.details["violation_type"]


def test_model_leaked_private_key_blocked():
    """Model output containing a private key is blocked."""
    raw = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----"
    with pytest.raises(ResponseSecurityViolationError) as exc_info:
        response_inspector.inspect_and_restore(raw)
    assert "PRIVATE_KEY" in exc_info.value.details["violation_type"]


def test_pii_placeholder_restoration():
    """Reversible placeholders like <EMAIL_1> are restored in model output."""
    raw = "Confirmation sent to <EMAIL_1>. Please verify account <ACCOUNT_NUMBER_1>."
    mapping = {
        "<EMAIL_1>": "aniket@example.com",
        "<ACCOUNT_NUMBER_1>": "9876543210",
    }
    res = response_inspector.inspect_and_restore(raw, request_mapping=mapping)
    assert res.restored_content == "Confirmation sent to aniket@example.com. Please verify account 9876543210."
    assert res.restoration_count == 2

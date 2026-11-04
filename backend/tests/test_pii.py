"""Tests for PII detection and reversible pseudonymization."""

import pytest
from app.privacy.pii_detector import pii_detector, validate_luhn
from app.privacy.redactor import redactor
from app.privacy.pipeline import inspection_pipeline


def test_luhn_algorithm_validation():
    # Valid Visa card sample (4012888888881881)
    assert validate_luhn("4012888888881881") is True
    # Invalid card number
    assert validate_luhn("4012888888881882") is False


def test_email_and_phone_detection():
    text = "Send an email to aniket@example.com or reach me at +1 415-555-2671."
    matches = pii_detector.detect(text)
    types = [m.entity_type for m in matches]
    assert "EMAIL" in types
    assert "PHONE_NUMBER" in types


def test_redaction_and_reversible_restoration():
    text = "Send confirmation to alice@example.com regarding order #100."
    matches = pii_detector.detect(text)
    spans = [(m.entity_type, m.start, m.end, m.text) for m in matches]

    result = redactor.redact(text, spans)
    assert "<EMAIL_1>" in result.redacted_text
    assert "alice@example.com" not in result.redacted_text
    assert result.mapping["<EMAIL_1>"] == "alice@example.com"

    # Restore
    restored = redactor.restore(result.redacted_text, result.mapping)
    assert restored == text


def test_pipeline_redaction_flow():
    text = "Please invoice john.doe@acme.org for account 12345678."
    verdict = inspection_pipeline.inspect_text(text)
    assert verdict.is_blocked is False
    assert verdict.action.value == "REDACT"
    assert "<EMAIL_1>" in verdict.sanitized_text
    assert "john.doe@acme.org" not in verdict.sanitized_text
    assert verdict.entity_counts.get("EMAIL") == 1

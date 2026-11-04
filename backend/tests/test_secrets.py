"""Tests for credential and secret scanner."""

import pytest
from app.privacy.secret_scanner import secret_scanner
from app.privacy.pipeline import inspection_pipeline


def test_openai_key_detected():
    text = "Here is my key: sk-proj-abCdefGhIjKlMnOpQrStUvWxYz1234567890abcdefGhIjKlMnOpQrStUvWx"
    matches = secret_scanner.scan(text)
    assert len(matches) >= 1
    assert matches[0].secret_type == "OPENAI_API_KEY"
    assert "sk-" in matches[0].preview
    assert matches[0].preview != matches[0].matched_text  # Must be masked!


def test_anthropic_key_detected():
    text = "Use this anthropic key: sk-ant-api03-abcdef1234567890abcdef1234567890abcdef1234"
    matches = secret_scanner.scan(text)
    assert len(matches) >= 1
    assert matches[0].secret_type == "ANTHROPIC_API_KEY"


def test_aws_access_key_detected():
    text = "AWS credentials: AKIAIOSFODNN7EXAMPLE and secret"
    matches = secret_scanner.scan(text)
    assert any(m.secret_type == "AWS_ACCESS_KEY_ID" for m in matches)


def test_github_pat_detected():
    text = "Deploy token: ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    matches = secret_scanner.scan(text)
    assert any(m.secret_type == "GITHUB_PAT" for m in matches)


def test_database_url_detected():
    text = "Connect to postgresql://admin:superSecretP@ss123@db.prod.internal:5432/customers"
    matches = secret_scanner.scan(text)
    assert any(m.secret_type == "DATABASE_URL" for m in matches)


def test_private_key_header_detected():
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0\n-----END RSA PRIVATE KEY-----"
    matches = secret_scanner.scan(text)
    assert any("PRIVATE_KEY" in m.secret_type for m in matches)


def test_pipeline_hard_blocks_on_secret():
    text = "Please summarize: my secret token is ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    verdict = inspection_pipeline.inspect_text(text)
    assert verdict.is_blocked is True
    assert verdict.action.value == "BLOCK"
    assert verdict.category.value == "CRITICAL"
    assert verdict.risk_level.value == "CRITICAL"
    assert len(verdict.detected_secrets) >= 1

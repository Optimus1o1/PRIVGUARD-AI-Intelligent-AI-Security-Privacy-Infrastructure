"""Tests for deterministic policy engine."""

import pytest
from app.policies.engine import policy_engine
from app.policies.schemas import PolicyAction


def test_secrets_always_blocked():
    decision = policy_engine.evaluate(category="CRITICAL", has_secrets=True)
    assert decision.action == PolicyAction.BLOCK
    assert decision.risk_level == "CRITICAL"
    assert decision.allow_execution is False


def test_personal_data_redacted_by_default():
    decision = policy_engine.evaluate(category="PERSONAL", has_secrets=False)
    assert decision.action == PolicyAction.REDACT
    assert decision.risk_level == "MEDIUM"
    assert decision.allow_execution is True


def test_confidential_requires_approval():
    decision = policy_engine.evaluate(category="CONFIDENTIAL", has_secrets=False)
    assert decision.action == PolicyAction.REQUIRE_APPROVAL
    assert decision.risk_level == "HIGH"
    assert decision.allow_execution is False


def test_public_allowed():
    decision = policy_engine.evaluate(category="PUBLIC", has_secrets=False)
    assert decision.action == PolicyAction.ALLOW
    assert decision.risk_level == "LOW"
    assert decision.allow_execution is True


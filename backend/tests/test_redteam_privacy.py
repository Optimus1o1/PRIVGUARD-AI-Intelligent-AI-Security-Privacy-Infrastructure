"""
Assessment C: Privacy Engine, PII & Secret Redaction Bypasses Red-Teaming Tests.
Validates PII minimization, credit card validation, secret hard-blocking, and placeholder anti-tampering.
"""

import pytest
import httpx
from tests.fixtures.tenant_fixtures import (
    TENANT_ALPHA_API_KEY,
    setup_multi_tenant_staging,
)
from app.privacy.classifier import DataCategory, RiskLevel
from app.privacy.redactor import DataRedactor
from app.privacy.pipeline import inspection_pipeline


@pytest.mark.asyncio
async def test_secrets_hard_blocked_never_soft_redacted(client: httpx.AsyncClient, db_session):
    """
    CRITICAL INVARIANT:
    Credentials (OpenAI, AWS, GitHub, Private Keys, DB URLs) must be HARD-BLOCKED.
    They must never be softened into reversible placeholders.
    """
    await setup_multi_tenant_staging(db_session)

    secrets_to_test = [
        ("OpenAI Key", "sk-proj-abc1234567890abcdef1234567890abcdef"),
        ("Anthropic Key", "sk-ant-api03-abcdef1234567890abcdef1234567890abcdef"),
        ("AWS Access Key", "AKIAIOSFODNN7EXAMPLE"),
        ("GitHub Token", "ghp_1234567890abcdefghijklmnopqrstuvwxyz"),
        ("Database URL", "postgresql://admin:superSecretPass123@prod-db.internal:5432/corp"),
        ("Private Key Header", "-----BEGIN RSA PRIVATE KEY-----"),
    ]

    for name, secret in secrets_to_test:
        res = await client.post(
            "/v1/privacy/inspect",
            headers={"X-API-Key": TENANT_ALPHA_API_KEY},
            json={"text": f"Here is the service configuration with {name}: {secret}"},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["is_blocked"] is True, f"{name} was not marked as is_blocked=True"
        assert data["action"] == "BLOCK", f"{name} action was {data['action']}, expected BLOCK"
        assert data["category"] == "CRITICAL"
        assert data["risk_level"] == "CRITICAL"


@pytest.mark.asyncio
async def test_pii_soft_redacted_with_reversible_tokens(client: httpx.AsyncClient, db_session):
    """
    Verifies that personal identifiers (email, phone, credit card) are
    replaced with reversible cryptographic placeholders.
    """
    await setup_multi_tenant_staging(db_session)

    sample_text = (
        "Send confirmation to alice.johnson@corp.org and call +1-555-0199 regarding card 4532-0150-1234-5678."
    )

    res = await client.post(
        "/v1/privacy/redact",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"text": sample_text, "reversible": True},
    )
    assert res.status_code == 200
    data = res.json()
    sanitized = data["sanitized_text"]

    # Original PII must not appear in sanitized text
    assert "alice.johnson@corp.org" not in sanitized
    assert "+1-555-0199" not in sanitized
    assert "4532-0150-1234-5678" not in sanitized

    # Reversible placeholders must appear
    assert "<EMAIL_" in sanitized
    assert "<PHONE_" in sanitized

    # Mapping must contain exact original items
    mapping = data["mapping"]
    assert any("alice.johnson@corp.org" in orig for orig in mapping.values())


@pytest.mark.asyncio
async def test_placeholder_spoofing_collision_attack():
    """
    Red team attack: Attacker submits text that already contains artificial '<EMAIL_1>' placeholders
    hoping to hijack the de-redaction process or leak another user's address.
    """
    deredactor = DataRedactor()
    legitimate_mapping = {"<EMAIL_1>": "legitimate_ceo@alpha.com"}

    # Attacker tries to include a spoofed placeholder
    attacker_input = "Hello <EMAIL_1>, also here is another forged <EMAIL_2>."

    restored = deredactor.restore(attacker_input, legitimate_mapping)
    # Legitimate placeholder is restored
    assert "legitimate_ceo@alpha.com" in restored
    # Forged placeholder with no mapping remains unchanged (no crash, no unauthorized mapping)
    assert "<EMAIL_2>" in restored


@pytest.mark.asyncio
async def test_audit_logs_contain_no_raw_pii_or_secrets(client: httpx.AsyncClient, db_session):
    """Verifies the Zero-Content Audit guarantee: audit records store only cryptographic fingerprints."""
    await setup_multi_tenant_staging(db_session)

    secret = "sk-ant-api03-abcdef1234567890abcdef1234567890abcdef"
    pii = "aniket.nandi@kolkata-enterprise.org"

    # Ingress inspection of prompt containing secret and PII
    await client.post(
        "/v1/privacy/inspect",
        headers={"X-API-Key": TENANT_ALPHA_API_KEY},
        json={"text": f"User {pii} provided token {secret}"},
    )

    # Query audit ledger
    res = await client.get("/v1/audit/events", headers={"X-API-Key": TENANT_ALPHA_API_KEY})
    assert res.status_code == 200
    events = res.json()
    assert len(events) > 0

    for evt in events:
        evt_str = str(evt)
        assert secret not in evt_str, "Secret leaked in audit event!"
        assert pii not in evt_str, "Raw PII leaked in audit event!"
        assert evt.get("content_fingerprint") is not None, "Missing SHA-256 content fingerprint in audit"

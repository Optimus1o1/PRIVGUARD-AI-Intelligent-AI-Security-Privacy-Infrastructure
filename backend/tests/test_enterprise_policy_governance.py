"""Adversarial security tests for Policy Governance, Ed25519 Signing, and Downgrade Defense (Tests 24-32)."""

import json
import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.exceptions import AuthorizationError, SecurityPolicyViolationError
from app.database.models import Organization, PolicyBundle, utcnow
from app.policies.signing import PolicySigner, canonical_json_bytes
from app.policies.governance import PolicyGovernanceManager

ORG_POLICY_TEST = "org_policy_test_tenant"


@pytest_asyncio.fixture
async def setup_policy_org(db_session: AsyncSession):
    org = Organization(
        id=ORG_POLICY_TEST,
        slug="policy-test",
        name="Policy Test Org",
        status="ACTIVE",
    )
    db_session.add(org)
    await db_session.commit()


def test_24_ed25519_valid_signature_verification():
    """Test 24: Correctly signed policy bundle verifies successfully."""
    priv_hex, pub_hex = PolicySigner.generate_keypair()
    bundle = {
        "organization_id": ORG_POLICY_TEST,
        "version": 1,
        "rules": [{"target": "EMAIL_ADDRESS", "action": "REDACT"}],
    }
    signature = PolicySigner.sign_bundle(bundle, priv_hex)
    assert PolicySigner.verify_bundle_signature(bundle, signature, pub_hex) is True


def test_25_tampered_bundle_payload_fails_verification():
    """Test 25: Any tampering with bundle content breaks Ed25519 signature verification."""
    priv_hex, pub_hex = PolicySigner.generate_keypair()
    bundle = {
        "organization_id": ORG_POLICY_TEST,
        "version": 1,
        "rules": [{"target": "EMAIL_ADDRESS", "action": "REDACT"}],
    }
    signature = PolicySigner.sign_bundle(bundle, priv_hex)

    # Tampering: attacker changes REDACT to ALLOW
    tampered_bundle = {
        "organization_id": ORG_POLICY_TEST,
        "version": 1,
        "rules": [{"target": "EMAIL_ADDRESS", "action": "ALLOW"}],
    }

    with pytest.raises(SecurityPolicyViolationError, match="Cryptographic integrity check rejected"):
        PolicySigner.verify_bundle_signature(tampered_bundle, signature, pub_hex)


def test_26_corrupted_signature_fails_verification():
    """Test 26: Corrupted or forged signature bytes are rejected."""
    priv_hex, pub_hex = PolicySigner.generate_keypair()
    bundle = {"organization_id": ORG_POLICY_TEST, "version": 1}
    bad_signature = "00" * 64

    with pytest.raises(SecurityPolicyViolationError):
        PolicySigner.verify_bundle_signature(bundle, bad_signature, pub_hex)


@pytest.mark.asyncio
async def test_27_policy_downgrade_rejected(db_session: AsyncSession, setup_policy_org):
    """Test 27: Enforces anti-downgrade defense; lower version cannot replace higher active version."""
    # Create bundle v1 and v2
    bundle_v1 = await PolicyGovernanceManager.create_policy_bundle(
        db=db_session,
        organization_id=ORG_POLICY_TEST,
        rules=[{"target": "EMAIL_ADDRESS", "action": "REDACT"}],
        created_by="usr_admin",
    )
    bundle_v2 = await PolicyGovernanceManager.create_policy_bundle(
        db=db_session,
        organization_id=ORG_POLICY_TEST,
        rules=[{"target": "EMAIL_ADDRESS", "action": "BLOCK"}],
        created_by="usr_admin",
    )

    # Deploy v2 as active
    await PolicyGovernanceManager.deploy_policy_bundle(
        db=db_session,
        bundle_id=bundle_v2.id,
        deployed_by="usr_admin",
    )

    # Attempt to deploy v1 (lower version) directly without rollback mechanism
    with pytest.raises(SecurityPolicyViolationError, match="Policy Downgrade Rejected"):
        await PolicyGovernanceManager.deploy_policy_bundle(
            db=db_session,
            bundle_id=bundle_v1.id,
            deployed_by="usr_admin",
        )


@pytest.mark.asyncio
async def test_28_authorized_rollback_succeeds(db_session: AsyncSession, setup_policy_org):
    """Test 28: Explicit rollback safely activates previous signed policy."""
    # Create bundle v1 and v2
    bundle_v1 = await PolicyGovernanceManager.create_policy_bundle(
        db=db_session,
        organization_id=ORG_POLICY_TEST,
        rules=[{"target": "EMAIL_ADDRESS", "action": "REDACT"}],
        created_by="usr_admin",
    )
    bundle_v2 = await PolicyGovernanceManager.create_policy_bundle(
        db=db_session,
        organization_id=ORG_POLICY_TEST,
        rules=[{"target": "EMAIL_ADDRESS", "action": "BLOCK"}],
        created_by="usr_admin",
    )

    # Deploy v2 as active
    await PolicyGovernanceManager.deploy_policy_bundle(
        db=db_session,
        bundle_id=bundle_v2.id,
        deployed_by="usr_admin",
    )

    # Rollback to v1 via explicit rollback method
    rolled_back = await PolicyGovernanceManager.rollback_policy(
        db=db_session,
        target_bundle_id=bundle_v1.id,
        deployed_by="usr_admin",
    )
    assert rolled_back.status == "ACTIVE"
    assert rolled_back.version == 1


def test_29_platform_guardrail_immutability():
    """Test 29: Org administrators cannot weaken or disable immutable platform guardrails."""
    # Attempting to set action ALLOW or DISABLE on ALL_SECRETS
    with pytest.raises(AuthorizationError, match="Platform Security Violation"):
        PolicyGovernanceManager.validate_policy_integrity({
            "rules": [{"target": "ALL_SECRETS", "action": "ALLOW"}]
        })

    with pytest.raises(AuthorizationError, match="Platform Security Violation"):
        PolicyGovernanceManager.validate_policy_integrity({
            "rules": [{"target": "SSRF_LOOPBACK", "action": "DISABLE"}]
        })


def test_30_deterministic_hierarchy_conflict_resolution():
    """Test 30: Deterministic conflict resolution enforces the most restrictive rule."""
    rules = [
        {"layer": "ORG_BASELINE", "target": "PHONE_NUMBER", "action": "WARN"},
        {"layer": "WORKSPACE", "target": "PHONE_NUMBER", "action": "BLOCK"},
        {"layer": "APPLICATION", "target": "PHONE_NUMBER", "action": "REDACT"},
    ]
    resolved = PolicyGovernanceManager.resolve_effective_rule(rules)
    # BLOCK (restrictiveness 5) wins over REDACT (3) and WARN (2)
    assert resolved["action"] == "BLOCK"
    assert resolved["layer"] == "WORKSPACE"


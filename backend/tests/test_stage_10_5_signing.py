"""Stage 10.5 Signing Key Management Unit Tests.
Verifies Ed25519 policy signing keypairs, versioned kid lookup,
HMAC approval binding independence from master key, rotation, and revocation.
"""

import pytest
from app.core.exceptions import SecurityPolicyViolationError
from app.key_management.signing import SigningKeyManager


def test_ed25519_keypair_generation_signing_and_verification():
    """Verifies Ed25519 key generation, signature creation, and strict verification."""
    mgr = SigningKeyManager()
    priv_hex, pub_hex = mgr.generate_ed25519_keypair()
    payload = b'{"tenant_id": "org_moon_sanctum", "rules": ["no_exfil"]}'

    sig_hex = mgr.sign_policy(payload, priv_hex)
    assert sig_hex is not None
    assert len(sig_hex) == 128  # 64 bytes in hex

    # Verification passes with untouched payload
    assert mgr.verify_policy_signature(payload, sig_hex, pub_hex) is True

    # Tampered payload fails verification
    tampered_payload = b'{"tenant_id": "org_moon_sanctum", "rules": ["allow_all"]}'
    with pytest.raises(SecurityPolicyViolationError):
        mgr.verify_policy_signature(tampered_payload, sig_hex, pub_hex)


def test_hmac_approval_binding_and_rotation():
    """
    Verifies that HMAC approval action binding works with versioned kid,
    survives key rotation for in-flight requests, and adopts new kid for subsequent actions.
    """
    mgr = SigningKeyManager()
    tool = "execute_sql_query"
    target = "prod_db.users"
    params = {"query": "SELECT email FROM users LIMIT 10"}

    # Compute action hash under current active kid
    hash_v1, kid_v1 = mgr.compute_action_hash(tool, target, params)
    assert kid_v1 == mgr.get_active_hmac_kid()

    # Verification passes
    assert mgr.verify_action_hash(tool, target, params, hash_v1, kid=kid_v1) is True

    # Parameter tampering fails
    tampered_params = {"query": "DROP TABLE users;"}
    assert mgr.verify_action_hash(tool, target, tampered_params, hash_v1, kid=kid_v1) is False

    # Rotate HMAC key
    new_kid = mgr.rotate_hmac_key()
    assert new_kid != kid_v1
    assert mgr.get_active_hmac_kid() == new_kid

    # In-flight request signed with old kid remains verifiable
    assert mgr.verify_action_hash(tool, target, params, hash_v1, kid=kid_v1) is True

    # New action hash uses new kid
    hash_v2, kid_v2 = mgr.compute_action_hash(tool, target, params)
    assert kid_v2 == new_kid
    assert hash_v2 != hash_v1


def test_hmac_key_revocation():
    """Verifies that revoking an HMAC key ID immediately invalidates requests signed with it."""
    mgr = SigningKeyManager()
    tool = "delete_aws_bucket"
    target = "s3://sensitive-client-backups"
    params = {"force": True}

    hash_val, kid = mgr.compute_action_hash(tool, target, params)
    assert mgr.verify_action_hash(tool, target, params, hash_val, kid=kid) is True

    # Revoke key
    mgr.revoke_hmac_key(kid)

    # Subsequent verification must fail
    assert mgr.verify_action_hash(tool, target, params, hash_val, kid=kid) is False

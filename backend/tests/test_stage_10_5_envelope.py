"""Stage 10.5 Envelope Encryption Unit Tests.
Verifies V1 (legacy HKDF) vs V2 (KMS envelope) dual-mode encryption, unique DEKs,
tamper detection, context binding, and backward compatibility.
"""

import pytest
from app.core.exceptions import MemoryTamperingError
from app.memory.crypto import (
    envelope_encryption,
    EncryptedMemoryPayload,
)


def test_v2_envelope_encryption_and_decryption():
    """Verifies that V2 KMS encryption generates a wrapped DEK and decrypts cleanly."""
    plaintext = "Patient reported mild allergic reaction to penicillin."
    tenant_id = "tenant_hospital_a"
    owner_id = "doctor_99"
    memory_id = "mem_allergy_001"
    category = "HEALTH"

    payload = envelope_encryption.encrypt(
        plaintext=plaintext,
        owner_id=owner_id,
        memory_id=memory_id,
        category=category,
        encryption_format="V2",
        tenant_id=tenant_id,
    )

    assert payload.encryption_format == "V2"
    assert payload.wrapped_dek_b64 is not None
    assert payload.key_id is not None
    assert payload.ciphertext_b64 != plaintext
    assert payload.nonce_b64 != ""
    assert len(payload.content_fingerprint) == 64  # SHA-256 hex

    # Decrypt
    decrypted = envelope_encryption.decrypt(
        payload=payload,
        owner_id=owner_id,
        memory_id=memory_id,
        category=category,
        tenant_id=tenant_id,
    )
    assert decrypted == plaintext


def test_unique_dek_per_record():
    """Verifies that two encryptions of identical plaintext produce distinct DEKs and ciphertexts."""
    plaintext = "Identical sensitive string"
    tenant_id = "tenant_finance"
    owner_id = "trader_42"
    memory_id = "mem_tx_dup"
    category = "FINANCIAL"

    payload1 = envelope_encryption.encrypt(
        plaintext=plaintext,
        owner_id=owner_id,
        memory_id=memory_id,
        category=category,
        encryption_format="V2",
        tenant_id=tenant_id,
    )

    payload2 = envelope_encryption.encrypt(
        plaintext=plaintext,
        owner_id=owner_id,
        memory_id=memory_id,
        category=category,
        encryption_format="V2",
        tenant_id=tenant_id,
    )

    assert payload1.wrapped_dek_b64 != payload2.wrapped_dek_b64
    assert payload1.ciphertext_b64 != payload2.ciphertext_b64
    assert payload1.nonce_b64 != payload2.nonce_b64
    assert payload1.content_fingerprint == payload2.content_fingerprint


def test_aad_context_tampering_rejected():
    """Verifies that altering tenant_id, category, or owner_id fails authentication."""
    plaintext = "Restricted research data"
    tenant_id = "tenant_lab"
    owner_id = "researcher_1"
    memory_id = "mem_res_101"
    category = "BIOPHARMA"

    payload = envelope_encryption.encrypt(
        plaintext=plaintext,
        owner_id=owner_id,
        memory_id=memory_id,
        category=category,
        encryption_format="V2",
        tenant_id=tenant_id,
    )

    # 1. Tamper with tenant
    with pytest.raises(MemoryTamperingError):
        envelope_encryption.decrypt(
            payload=payload,
            owner_id=owner_id,
            memory_id=memory_id,
            category=category,
            tenant_id="tenant_malicious",
        )

    # 2. Tamper with owner
    with pytest.raises(MemoryTamperingError):
        envelope_encryption.decrypt(
            payload=payload,
            owner_id="researcher_hacker",
            memory_id=memory_id,
            category=category,
            tenant_id=tenant_id,
        )

    # 3. Tamper with category
    with pytest.raises(MemoryTamperingError):
        envelope_encryption.decrypt(
            payload=payload,
            owner_id=owner_id,
            memory_id=memory_id,
            category="PUBLIC",
            tenant_id=tenant_id,
        )


def test_ciphertext_tampering_rejected():
    """Verifies that bit-flipping ciphertext raises MemoryTamperingError."""
    plaintext = "Important contract clause"
    tenant_id = "tenant_legal"
    owner_id = "counsel_1"
    memory_id = "mem_legal_01"
    category = "LEGAL"

    payload = envelope_encryption.encrypt(
        plaintext=plaintext,
        owner_id=owner_id,
        memory_id=memory_id,
        category=category,
        encryption_format="V2",
        tenant_id=tenant_id,
    )

    # Mutate raw ciphertext bytes to strictly invalidate AES-GCM auth tag
    import base64
    raw_ct = bytearray(base64.b64decode(payload.ciphertext_b64))
    raw_ct[0] ^= 0xFF
    tampered_payload = payload._replace(ciphertext_b64=base64.b64encode(raw_ct).decode("ascii"))

    with pytest.raises(MemoryTamperingError):
        envelope_encryption.decrypt(
            payload=tampered_payload,
            owner_id=owner_id,
            memory_id=memory_id,
            category=category,
            tenant_id=tenant_id,
        )


def test_v1_legacy_backward_compatibility():
    """Verifies that V1 legacy HKDF records decrypt seamlessly with decrypt()."""
    plaintext = "Stage 7 legacy memory record"
    owner_id = "legacy_user_77"
    memory_id = "mem_v1_legacy"
    category = "USER_PREFERENCES"

    payload_v1 = envelope_encryption.encrypt(
        plaintext=plaintext,
        owner_id=owner_id,
        memory_id=memory_id,
        category=category,
        encryption_format="V1",
    )

    assert payload_v1.encryption_format == "V1"
    assert payload_v1.key_id is None

    # Decrypt transparently
    decrypted = envelope_encryption.decrypt(
        payload=payload_v1,
        owner_id=owner_id,
        memory_id=memory_id,
        category=category,
    )
    assert decrypted == plaintext

"""Tests for PRIVGUARD AI Memory Vault Cryptographic Envelope Encryption."""

import pytest
from app.core.exceptions import MemoryTamperingError
from app.memory.crypto import EnvelopeEncryption, EncryptedMemoryPayload
from app.memory.key_provider import LocalDevKeyProvider


@pytest.fixture
def crypto_service():
    key_prov = LocalDevKeyProvider()
    return EnvelopeEncryption(key_provider=key_prov)


def test_envelope_encryption_roundtrip(crypto_service):
    """Verifies that plaintext is encrypted and decrypted correctly."""
    owner_id = "user_alice_123"
    memory_id = "mem_001"
    category = "USER_PREFERENCES"
    plaintext = "Alice prefers dark mode, Python 3.12, and strict typing."

    payload = crypto_service.encrypt(
        plaintext=plaintext,
        owner_id=owner_id,
        memory_id=memory_id,
        category=category,
        key_version=1,
    )

    assert isinstance(payload, EncryptedMemoryPayload)
    assert payload.ciphertext_b64 != plaintext
    assert payload.key_version == 1
    assert payload.content_fingerprint is not None

    decrypted = crypto_service.decrypt(
        payload=payload,
        owner_id=owner_id,
        memory_id=memory_id,
        category=category,
    )
    assert decrypted == plaintext


def test_unique_dek_per_memory(crypto_service):
    """Verifies that identical plaintexts with different memory IDs produce different ciphertexts."""
    plaintext = "Identical preferences statement"
    owner_id = "user_alice"

    payload1 = crypto_service.encrypt(plaintext, owner_id, "mem_1", "USER_PREFERENCES")
    payload2 = crypto_service.encrypt(plaintext, owner_id, "mem_2", "USER_PREFERENCES")

    assert payload1.ciphertext_b64 != payload2.ciphertext_b64
    assert payload1.wrapped_dek_b64 != payload2.wrapped_dek_b64
    assert payload1.nonce_b64 != payload2.nonce_b64


def test_ciphertext_tampering_detection(crypto_service):
    """Verifies that tampered ciphertext raises MemoryTamperingError due to AES-GCM tag mismatch."""
    owner_id = "user_bob"
    memory_id = "mem_tamper"
    category = "PROJECT_CONTEXT"

    payload = crypto_service.encrypt("Confidential context", owner_id, memory_id, category)

    # Tamper with ciphertext by altering a base64 character
    tampered_b64 = "X" + payload.ciphertext_b64[1:]
    tampered_payload = EncryptedMemoryPayload(
        ciphertext_b64=tampered_b64,
        nonce_b64=payload.nonce_b64,
        wrapped_dek_b64=payload.wrapped_dek_b64,
        dek_nonce_b64=payload.dek_nonce_b64,
        key_version=payload.key_version,
        content_fingerprint=payload.content_fingerprint,
    )

    with pytest.raises(MemoryTamperingError):
        crypto_service.decrypt(tampered_payload, owner_id, memory_id, category)


def test_aad_mismatch_detection(crypto_service):
    """Verifies that AAD binding mismatch (wrong owner or wrong category) raises MemoryTamperingError."""
    owner_id = "user_carol"
    memory_id = "mem_aad"
    category = "WORK_CONTEXT"

    payload = crypto_service.encrypt("Carol's work context", owner_id, memory_id, category)

    # Attempt decrypt with wrong owner_id (cross-user ciphertext substitution)
    with pytest.raises(MemoryTamperingError):
        crypto_service.decrypt(payload, "user_mallory", memory_id, category)

    # Attempt decrypt with wrong category
    with pytest.raises(MemoryTamperingError):
        crypto_service.decrypt(payload, owner_id, memory_id, "PERSONAL_PREFERENCES")

    # Attempt decrypt with wrong memory_id
    with pytest.raises(MemoryTamperingError):
        crypto_service.decrypt(payload, owner_id, "mem_other", category)


def test_kek_rotation_rewrap(crypto_service):
    """Verifies that KEK rotation successfully re-wraps DEKs in O(1) without re-encrypting ciphertext."""
    owner_id = "user_dave"
    memory_id = "mem_rotate"
    category = "USER_PREFERENCES"
    plaintext = "Dave's persistent memory"

    payload = crypto_service.encrypt(plaintext, owner_id, memory_id, category, key_version=1)

    # Rotate KEK
    new_version, _ = crypto_service.key_provider.rotate_user_kek(owner_id)
    assert new_version == 2

    # Re-wrap DEK under new KEK
    new_wrapped, new_dek_nonce = crypto_service.rewrap_dek(
        wrapped_dek_b64=payload.wrapped_dek_b64,
        dek_nonce_b64=payload.dek_nonce_b64,
        owner_id=owner_id,
        memory_id=memory_id,
        old_version=1,
        new_version=2,
    )

    # Verify that updated payload can be decrypted with key_version=2
    updated_payload = EncryptedMemoryPayload(
        ciphertext_b64=payload.ciphertext_b64,  # Identical ciphertext on disk!
        nonce_b64=payload.nonce_b64,
        wrapped_dek_b64=new_wrapped,
        dek_nonce_b64=new_dek_nonce,
        key_version=2,
        content_fingerprint=payload.content_fingerprint,
    )

    decrypted = crypto_service.decrypt(updated_payload, owner_id, memory_id, category)
    assert decrypted == plaintext

"""Tests for Stage 10.5 Provider-Independent KMS Abstraction Layer."""

import pytest
from unittest.mock import MagicMock
from app.core.config import settings
from app.core.exceptions import PrivGuardException
from app.key_management.base import (
    KeyAlgorithm,
    KeyStatus,
    KMSCapabilities,
    KMSProviderType,
)
from app.key_management.manager import KMSManager
from app.key_management.providers.local import LocalKMSProvider
from app.key_management.providers.aws_kms import AWSKMSProvider


def test_local_kms_provider_wrap_unwrap():
    """Verifies that LocalKMSProvider wraps and unwraps a 256-bit DEK cleanly."""
    provider = LocalKMSProvider(master_key="test-master-key-32-chars-long-secret-key")
    key_id = "mem_kek_tenant_1"
    plaintext_dek = b"12345678901234567890123456789012"  # 32 bytes = 256 bits
    context = {"tenant_id": "tenant_1", "format": "v2"}

    wrapped = provider.wrap_key_sync(key_id, plaintext_dek, encryption_context=context)
    assert wrapped.wrapped_key != plaintext_dek
    assert wrapped.key_version == "1"
    assert wrapped.nonce is not None

    unwrapped = provider.unwrap_key_sync(
        key_id=key_id,
        wrapped_key=wrapped.wrapped_key,
        encryption_context=context,
        key_version=wrapped.key_version,
        nonce=wrapped.nonce,
    )
    assert unwrapped == plaintext_dek


def test_local_kms_context_tampering_rejected():
    """Verifies that tampering with encryption context causes KMS unwrap to fail."""
    provider = LocalKMSProvider(master_key="test-master-key-32-chars-long-secret-key")
    key_id = "mem_kek_tenant_1"
    plaintext_dek = b"12345678901234567890123456789012"
    context = {"tenant_id": "tenant_1", "format": "v2"}

    wrapped = provider.wrap_key_sync(key_id, plaintext_dek, encryption_context=context)

    # Attempt unwrap with mismatched tenant context
    tampered_context = {"tenant_id": "tenant_2", "format": "v2"}
    with pytest.raises(PrivGuardException) as exc_info:
        provider.unwrap_key_sync(
            key_id=key_id,
            wrapped_key=wrapped.wrapped_key,
            encryption_context=tampered_context,
            key_version=wrapped.key_version,
            nonce=wrapped.nonce,
        )
    assert exc_info.value.error_code == "KMS_UNWRAP_FAILED"


def test_local_kms_disabled_key_rejected():
    """Verifies that a disabled key cannot wrap or unwrap."""
    provider = LocalKMSProvider(master_key="test-master-key-32-chars-long-secret-key")
    key_id = "disabled_key_01"
    plaintext_dek = b"12345678901234567890123456789012"

    provider.disable_key(key_id)
    with pytest.raises(PrivGuardException) as exc:
        provider.wrap_key_sync(key_id, plaintext_dek)
    assert exc.value.error_code == "KEY_DISABLED"


def test_local_kms_rotation_and_rewrap():
    """Verifies KEK version rotation and client-side DEK rewrap."""
    provider = LocalKMSProvider(master_key="test-master-key-32-chars-long-secret-key")
    key_id = "rotation_key_01"
    plaintext_dek = b"12345678901234567890123456789012"
    context = {"tenant_id": "tenant_1"}

    # Wrap under v1
    wrapped_v1 = provider.wrap_key_sync(key_id, plaintext_dek, context)
    assert wrapped_v1.key_version == "1"

    # Rotate to v2
    new_ver = provider.rotate_key(key_id)
    assert new_ver == "2"

    # Rewrap DEK to v2
    rewrapped = provider.rewrap_key_sync(
        key_id=key_id,
        new_key_id=key_id,
        wrapped_key=wrapped_v1.wrapped_key,
        old_context=context,
        new_context=context,
        old_version="1",
        new_version="2",
        old_nonce=wrapped_v1.nonce,
    )
    assert rewrapped.key_version == "2"

    # Unwrap under v2
    unwrapped = provider.unwrap_key_sync(
        key_id=key_id,
        wrapped_key=rewrapped.wrapped_key,
        encryption_context=context,
        key_version="2",
        nonce=rewrapped.nonce,
    )
    assert unwrapped == plaintext_dek


def test_aws_kms_mock_provider_wrap_and_native_reencrypt():
    """Verifies AWS KMS provider adapter with native server-side ReEncrypt API call."""
    mock_boto = MagicMock()
    mock_boto.encrypt.return_value = {
        "CiphertextBlob": b"aws_encrypted_blob_v1",
        "KeyId": "arn:aws:kms:us-east-1:123456789012:key/test-kek-1",
    }
    mock_boto.decrypt.return_value = {
        "Plaintext": b"12345678901234567890123456789012",
        "KeyId": "arn:aws:kms:us-east-1:123456789012:key/test-kek-1",
    }
    mock_boto.re_encrypt.return_value = {
        "CiphertextBlob": b"aws_reencrypted_blob_v2",
        "KeyId": "arn:aws:kms:us-east-1:123456789012:key/test-kek-2",
    }
    mock_boto.describe_key.return_value = {
        "KeyMetadata": {
            "Arn": "arn:aws:kms:us-east-1:123456789012:key/test-kek-1",
            "Enabled": True,
            "KeyState": "Enabled",
        }
    }

    aws_provider = AWSKMSProvider(boto_client=mock_boto)
    assert aws_provider.capabilities.server_side_rewrap is True

    # 1. Wrap
    dek = b"12345678901234567890123456789012"
    wrapped = aws_provider.wrap_key_sync("test-kek-1", dek, {"tenant_id": "t1"})
    assert wrapped.wrapped_key == b"aws_encrypted_blob_v1"
    mock_boto.encrypt.assert_called_once()

    # 2. Native Server-Side ReEncrypt
    rewrapped = aws_provider.rewrap_key_sync(
        key_id="test-kek-1",
        new_key_id="test-kek-2",
        wrapped_key=wrapped.wrapped_key,
        old_context={"tenant_id": "t1"},
        new_context={"tenant_id": "t1"},
    )
    assert rewrapped.wrapped_key == b"aws_reencrypted_blob_v2"
    mock_boto.re_encrypt.assert_called_once()

    # 3. Unwrap
    unwrapped = aws_provider.unwrap_key_sync("test-kek-1", wrapped.wrapped_key, {"tenant_id": "t1"})
    assert unwrapped == dek
    mock_boto.decrypt.assert_called_once()


def test_production_rejects_local_kms_provider(monkeypatch):
    """Verifies that running in production with local KMS provider triggers immediate security denial."""
    monkeypatch.setattr(settings, "ENVIRONMENT", "production")
    monkeypatch.setattr(settings, "KMS_PROVIDER", "local")

    mgr = KMSManager()
    with pytest.raises(PrivGuardException) as exc_info:
        mgr.get_provider()
    assert exc_info.value.error_code == "PRODUCTION_LOCAL_KMS_PROHIBITED"

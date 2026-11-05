"""Local development KMS provider for testing and offline development."""

import os
from datetime import datetime, timezone
from typing import Dict, Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

from app.core.config import settings
from app.core.exceptions import PrivGuardException
from app.key_management.base import (
    KeyAlgorithm,
    KeyMetadata,
    KeyStatus,
    KMSCapabilities,
    KMSProvider,
    KMSProviderType,
    WrappedKeyResult,
)


class LocalKMSProvider(KMSProvider):
    """
    Local development KMS provider.
    Derives versioned AES-256 KEKs from master_key using HKDF-SHA256 and wraps DEKs using AES-256-GCM.
    
    SECURITY INVARIANT:
    Strictly prohibited in production environments.
    """

    SALT = b"privguard_msl_kms_local_salt_v2"

    def __init__(self, master_key: Optional[str] = None) -> None:
        self.master_key = (master_key or settings.PRIVGUARD_MASTER_KEY).encode("utf-8")
        self._key_versions: Dict[str, int] = {}
        self._disabled_keys: Dict[str, bool] = {}

    @property
    def provider_type(self) -> KMSProviderType:
        return KMSProviderType.LOCAL

    @property
    def capabilities(self) -> KMSCapabilities:
        return KMSCapabilities(
            server_side_rewrap=False,
            asymmetric_signing=False,
            versioning=True,
            client_side_envelope=True,
        )

    def _derive_kek(self, key_id: str, version: int) -> bytes:
        """Derives a 256-bit KEK for a specific key_id and version."""
        info = f"privguard_kms_kek:{key_id}:v{version}".encode("utf-8")
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.SALT,
            info=info,
        )
        return hkdf.derive(self.master_key)

    def _build_context_aad(self, key_id: str, version: str, context: Optional[Dict[str, str]]) -> bytes:
        """Serializes non-secret encryption context into AAD bytes."""
        context_str = ""
        if context:
            context_str = ",".join(f"{k}={v}" for k, v in sorted(context.items()))
        return f"{key_id}:v{version}:{context_str}".encode("utf-8")

    def wrap_key_sync(
        self,
        key_id: str,
        plaintext_key: bytes,
        encryption_context: Optional[Dict[str, str]] = None,
    ) -> WrappedKeyResult:
        if self._disabled_keys.get(key_id, False):
            raise PrivGuardException(f"KMS key '{key_id}' is disabled.", status_code=403, error_code="KEY_DISABLED")

        version = self._key_versions.get(key_id, 1)
        version_str = str(version)
        kek = self._derive_kek(key_id, version)

        nonce = os.urandom(12)
        aad = self._build_context_aad(key_id, version_str, encryption_context)
        aes = AESGCM(kek)
        wrapped = aes.encrypt(nonce, plaintext_key, aad)

        return WrappedKeyResult(
            wrapped_key=wrapped,
            key_version=version_str,
            nonce=nonce,
            provider="local",
        )

    def unwrap_key_sync(
        self,
        key_id: str,
        wrapped_key: bytes,
        encryption_context: Optional[Dict[str, str]] = None,
        key_version: Optional[str] = None,
        nonce: Optional[bytes] = None,
    ) -> bytes:
        if self._disabled_keys.get(key_id, False):
            raise PrivGuardException(f"KMS key '{key_id}' is disabled.", status_code=403, error_code="KEY_DISABLED")

        version_int = int(key_version) if key_version else self._key_versions.get(key_id, 1)
        version_str = str(version_int)
        kek = self._derive_kek(key_id, version_int)

        if not nonce:
            raise ValueError("LocalKMSProvider requires nonce for unwrapping")

        aad = self._build_context_aad(key_id, version_str, encryption_context)
        aes = AESGCM(kek)
        try:
            return aes.decrypt(nonce, wrapped_key, aad)
        except InvalidTag:
            raise PrivGuardException(
                f"KMS unwrap failed for key '{key_id}': integrity check rejected.",
                status_code=400,
                error_code="KMS_UNWRAP_FAILED",
            )

    def rewrap_key_sync(
        self,
        key_id: str,
        new_key_id: str,
        wrapped_key: bytes,
        old_context: Optional[Dict[str, str]] = None,
        new_context: Optional[Dict[str, str]] = None,
        old_version: Optional[str] = None,
        new_version: Optional[str] = None,
        old_nonce: Optional[bytes] = None,
    ) -> WrappedKeyResult:
        plaintext_key = self.unwrap_key_sync(
            key_id=key_id,
            wrapped_key=wrapped_key,
            encryption_context=old_context,
            key_version=old_version,
            nonce=old_nonce,
        )
        return self.wrap_key_sync(
            key_id=new_key_id,
            plaintext_key=plaintext_key,
            encryption_context=new_context,
        )

    def get_key_metadata(self, key_id: str) -> KeyMetadata:
        is_disabled = self._disabled_keys.get(key_id, False)
        status = KeyStatus.DISABLED if is_disabled else KeyStatus.ACTIVE
        version = str(self._key_versions.get(key_id, 1))
        return KeyMetadata(
            key_id=key_id,
            provider="local",
            key_version=version,
            status=status,
            algorithm=KeyAlgorithm.AES_256_GCM,
            created_at=datetime.now(timezone.utc).isoformat(),
            server_side_rewrap_supported=False,
        )

    def verify_key_access(self, key_id: str) -> bool:
        return not self._disabled_keys.get(key_id, False)

    def get_active_key_version(self, key_id: str) -> str:
        return str(self._key_versions.get(key_id, 1))

    def rotate_key(self, key_id: str) -> str:
        current = self._key_versions.get(key_id, 1)
        new_version = current + 1
        self._key_versions[key_id] = new_version
        return str(new_version)

    def disable_key(self, key_id: str) -> bool:
        self._disabled_keys[key_id] = True
        return True

    def enable_key(self, key_id: str) -> bool:
        self._disabled_keys[key_id] = False
        return True

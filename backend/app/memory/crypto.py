"""AES-256-GCM authenticated envelope encryption for the Secure Personal Memory Vault.
Supports versioned envelopes (V1 legacy HKDF and V2 external KMS KEK).
"""

import base64
import hashlib
import os
from typing import NamedTuple, Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from app.core.config import settings
from app.core.exceptions import MemoryTamperingError
from app.key_management.manager import KMSManager, kms_manager as default_kms_manager
from app.memory.key_provider import KeyProvider, default_key_provider


class EncryptedMemoryPayload(NamedTuple):
    """Encrypted envelope representation of a memory record."""

    ciphertext_b64: str
    nonce_b64: str
    wrapped_dek_b64: str
    dek_nonce_b64: str
    key_version: int
    content_fingerprint: str
    encryption_format: str = "V1"
    key_id: Optional[str] = None


class EnvelopeEncryption:
    """
    AES-256-GCM Envelope Encryption Engine.
    Each memory is encrypted with a unique Data Encryption Key (DEK).
    The DEK is wrapped under either:
    - V1: User KEK derived from PRIVGUARD_MASTER_KEY via HKDF-SHA256 (Stage 7).
    - V2: Enterprise KMS-managed KEK via provider-independent KMS abstraction (Stage 10.5).
    """

    def __init__(
        self,
        key_provider: Optional[KeyProvider] = None,
        kms_mgr: Optional[KMSManager] = None,
    ) -> None:
        self.key_provider = key_provider or default_key_provider
        self.kms_manager = kms_mgr or default_kms_manager

    @staticmethod
    def compute_fingerprint(plaintext: str) -> str:
        """Computes deterministic SHA-256 fingerprint of plaintext content."""
        return hashlib.sha256(plaintext.encode("utf-8")).hexdigest()

    @staticmethod
    def _b64e(data: bytes) -> str:
        return base64.b64encode(data).decode("ascii")

    @staticmethod
    def _b64d(data_str: str) -> bytes:
        return base64.b64decode(data_str.encode("ascii"))

    @staticmethod
    def _build_aad(memory_id: str, owner_id: str, category: str) -> bytes:
        """Constructs Authenticated Additional Data binding memory context for V1 records."""
        return f"{memory_id.strip()}:{owner_id.strip()}:{category.strip()}".encode("utf-8")

    @staticmethod
    def _build_v2_aad(tenant_id: str, owner_id: str, memory_id: str, category: str) -> bytes:
        """Constructs Authenticated Additional Data binding tenant and user context for V2 records."""
        return f"{tenant_id.strip()}:{owner_id.strip()}:{memory_id.strip()}:{category.strip()}:v2".encode("utf-8")

    def encrypt(
        self,
        plaintext: str,
        owner_id: str,
        memory_id: str,
        category: str,
        key_version: int = 1,
        tenant_id: str = "default_tenant",
        encryption_format: str = "V1",
        key_id: Optional[str] = None,
    ) -> EncryptedMemoryPayload:
        """
        Encrypts plaintext memory using a fresh 256-bit DEK.
        Wraps DEK under legacy KEK (V1) or KMS KEK (V2).
        """
        if not plaintext:
            raise ValueError("Cannot encrypt empty plaintext")

        # 1. Generate unique 256-bit DEK and 96-bit random nonce for content
        dek = AESGCM.generate_key(bit_length=256)
        content_nonce = os.urandom(12)
        fingerprint = self.compute_fingerprint(plaintext)
        aes_dek = AESGCM(dek)

        fmt_upper = (encryption_format or "V1").upper()

        if fmt_upper == "V2":
            # V2 KMS Envelope Encryption
            v2_aad = self._build_v2_aad(tenant_id, owner_id, memory_id, category)
            ciphertext = aes_dek.encrypt(content_nonce, plaintext.encode("utf-8"), v2_aad)

            target_key_id = key_id or settings.KMS_KEY_ID or f"mem_kek_{tenant_id}"
            wrapped_res = self.kms_manager.wrap_dek_sync(
                key_id=target_key_id,
                plaintext_dek=dek,
                tenant_id=tenant_id,
                format_version="v2",
            )

            wrapped_dek_b64 = self._b64e(wrapped_res.wrapped_key)
            dek_nonce_b64 = self._b64e(wrapped_res.nonce) if wrapped_res.nonce else ""
            key_ver_int = int(wrapped_res.key_version) if wrapped_res.key_version.isdigit() else key_version

            return EncryptedMemoryPayload(
                ciphertext_b64=self._b64e(ciphertext),
                nonce_b64=self._b64e(content_nonce),
                wrapped_dek_b64=wrapped_dek_b64,
                dek_nonce_b64=dek_nonce_b64,
                key_version=key_ver_int,
                content_fingerprint=fingerprint,
                encryption_format="V2",
                key_id=target_key_id,
            )

        else:
            # V1 Legacy HKDF Envelope Encryption (Stage 7 backwards-compatible)
            aad = self._build_aad(memory_id, owner_id, category)
            ciphertext = aes_dek.encrypt(content_nonce, plaintext.encode("utf-8"), aad)

            dek_nonce = os.urandom(12)
            user_kek = self.key_provider.get_user_kek(owner_id, key_version=key_version)
            aes_kek = AESGCM(user_kek)
            wrapped_dek = aes_kek.encrypt(dek_nonce, dek, f"wrapped_dek:{memory_id}:{key_version}".encode("utf-8"))

            return EncryptedMemoryPayload(
                ciphertext_b64=self._b64e(ciphertext),
                nonce_b64=self._b64e(content_nonce),
                wrapped_dek_b64=self._b64e(wrapped_dek),
                dek_nonce_b64=self._b64e(dek_nonce),
                key_version=key_version,
                content_fingerprint=fingerprint,
                encryption_format="V1",
                key_id=None,
            )

    def decrypt(
        self,
        payload: EncryptedMemoryPayload,
        owner_id: str,
        memory_id: str,
        category: str,
        tenant_id: str = "default_tenant",
    ) -> str:
        """
        Unwraps DEK using appropriate key provider (V1 HKDF vs V2 KMS),
        verifies authenticated data binding, and decrypts ciphertext.
        Raises MemoryTamperingError if any byte or context is altered.
        """
        try:
            fmt_upper = getattr(payload, "encryption_format", "V1").upper()

            if fmt_upper == "V2":
                # V2 KMS Decryption
                wrapped_dek = self._b64d(payload.wrapped_dek_b64)
                dek_nonce = self._b64d(payload.dek_nonce_b64) if payload.dek_nonce_b64 else None
                target_key = getattr(payload, "key_id", None) or settings.KMS_KEY_ID or f"mem_kek_{tenant_id}"

                dek = self.kms_manager.unwrap_dek_sync(
                    key_id=target_key,
                    wrapped_dek=wrapped_dek,
                    tenant_id=tenant_id,
                    format_version="v2",
                    key_version=str(payload.key_version),
                    nonce=dek_nonce,
                )

                content_nonce = self._b64d(payload.nonce_b64)
                ciphertext = self._b64d(payload.ciphertext_b64)
                aes_dek = AESGCM(dek)
                v2_aad = self._build_v2_aad(tenant_id, owner_id, memory_id, category)
                try:
                    plaintext_bytes = aes_dek.decrypt(content_nonce, ciphertext, v2_aad)
                except InvalidTag:
                    # Non-destructive migrated records retain original V1 content AAD
                    v1_aad = self._build_aad(memory_id, owner_id, category)
                    plaintext_bytes = aes_dek.decrypt(content_nonce, ciphertext, v1_aad)
                plaintext = plaintext_bytes.decode("utf-8")

            else:
                # V1 Legacy Decryption
                user_kek = self.key_provider.get_user_kek(owner_id, key_version=payload.key_version)
                aes_kek = AESGCM(user_kek)

                dek_nonce = self._b64d(payload.dek_nonce_b64)
                wrapped_dek = self._b64d(payload.wrapped_dek_b64)
                dek_aad = f"wrapped_dek:{memory_id}:{payload.key_version}".encode("utf-8")
                dek = aes_kek.decrypt(dek_nonce, wrapped_dek, dek_aad)

                content_nonce = self._b64d(payload.nonce_b64)
                ciphertext = self._b64d(payload.ciphertext_b64)
                aad = self._build_aad(memory_id, owner_id, category)
                aes_dek = AESGCM(dek)
                plaintext_bytes = aes_dek.decrypt(content_nonce, ciphertext, aad)
                plaintext = plaintext_bytes.decode("utf-8")

            # Verify content integrity against fingerprint
            if payload.content_fingerprint:
                actual_fingerprint = self.compute_fingerprint(plaintext)
                if actual_fingerprint != payload.content_fingerprint:
                    raise MemoryTamperingError(memory_id)

            return plaintext

        except InvalidTag:
            raise MemoryTamperingError(memory_id)
        except Exception as e:
            if isinstance(e, MemoryTamperingError):
                raise
            raise MemoryTamperingError(memory_id)

    def rewrap_dek(
        self,
        wrapped_dek_b64: str,
        dek_nonce_b64: str,
        owner_id: str,
        memory_id: str,
        old_version: int,
        new_version: int,
    ) -> Tuple[str, str]:
        """
        V1 Legacy KEK rotation: unwraps DEK under old KEK and rewraps under new KEK.
        Ciphertext remains untouched.
        """
        try:
            old_kek = self.key_provider.get_user_kek(owner_id, key_version=old_version)
            aes_old = AESGCM(old_kek)
            old_nonce = self._b64d(dek_nonce_b64)
            wrapped_dek = self._b64d(wrapped_dek_b64)
            old_aad = f"wrapped_dek:{memory_id}:{old_version}".encode("utf-8")
            dek = aes_old.decrypt(old_nonce, wrapped_dek, old_aad)

            new_kek = self.key_provider.get_user_kek(owner_id, key_version=new_version)
            aes_new = AESGCM(new_kek)
            new_nonce = os.urandom(12)
            new_aad = f"wrapped_dek:{memory_id}:{new_version}".encode("utf-8")
            new_wrapped = aes_new.encrypt(new_nonce, dek, new_aad)

            return self._b64e(new_wrapped), self._b64e(new_nonce)

        except InvalidTag:
            raise MemoryTamperingError(memory_id)


# Global singleton encryption engine
envelope_encryption = EnvelopeEncryption()

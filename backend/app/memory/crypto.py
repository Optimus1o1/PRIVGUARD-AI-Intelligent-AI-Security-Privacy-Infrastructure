"""AES-256-GCM authenticated envelope encryption for the Secure Personal Memory Vault."""

import base64
import hashlib
import os
from typing import NamedTuple, Optional, Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

from app.core.exceptions import MemoryTamperingError
from app.memory.key_provider import KeyProvider, default_key_provider


class EncryptedMemoryPayload(NamedTuple):
    """Encrypted envelope representation of a memory record."""
    ciphertext_b64: str
    nonce_b64: str
    wrapped_dek_b64: str
    dek_nonce_b64: str
    key_version: int
    content_fingerprint: str


class EnvelopeEncryption:
    """
    AES-256-GCM Envelope Encryption Engine.
    Each memory is encrypted with a unique Data Encryption Key (DEK).
    The DEK is wrapped (encrypted) under the user's Key Encryption Key (KEK).
    """

    def __init__(self, key_provider: Optional[KeyProvider] = None) -> None:
        self.key_provider = key_provider or default_key_provider

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
        """Constructs Authenticated Additional Data binding memory context."""
        return f"{memory_id.strip()}:{owner_id.strip()}:{category.strip()}".encode("utf-8")

    def encrypt(
        self,
        plaintext: str,
        owner_id: str,
        memory_id: str,
        category: str,
        key_version: int = 1,
    ) -> EncryptedMemoryPayload:
        """
        Encrypts plaintext memory using a fresh DEK and wraps the DEK under the user's KEK.
        """
        if not plaintext:
            raise ValueError("Cannot encrypt empty plaintext")

        # 1. Generate unique 256-bit DEK and 96-bit (12-byte) random nonces
        dek = AESGCM.generate_key(bit_length=256)
        content_nonce = os.urandom(12)
        dek_nonce = os.urandom(12)

        # 2. Encrypt plaintext with DEK and AAD
        aad = self._build_aad(memory_id, owner_id, category)
        aes_dek = AESGCM(dek)
        ciphertext = aes_dek.encrypt(content_nonce, plaintext.encode("utf-8"), aad)

        # 3. Retrieve user KEK and wrap DEK
        user_kek = self.key_provider.get_user_kek(owner_id, key_version=key_version)
        aes_kek = AESGCM(user_kek)
        wrapped_dek = aes_kek.encrypt(dek_nonce, dek, f"wrapped_dek:{memory_id}:{key_version}".encode("utf-8"))

        # 4. Content fingerprint
        fingerprint = self.compute_fingerprint(plaintext)

        return EncryptedMemoryPayload(
            ciphertext_b64=self._b64e(ciphertext),
            nonce_b64=self._b64e(content_nonce),
            wrapped_dek_b64=self._b64e(wrapped_dek),
            dek_nonce_b64=self._b64e(dek_nonce),
            key_version=key_version,
            content_fingerprint=fingerprint,
        )

    def decrypt(
        self,
        payload: EncryptedMemoryPayload,
        owner_id: str,
        memory_id: str,
        category: str,
    ) -> str:
        """
        Unwraps DEK using user KEK, verifies authenticated data, and decrypts ciphertext.
        Raises MemoryTamperingError if any byte or metadata is altered.
        """
        try:
            # 1. Retrieve user KEK for key version
            user_kek = self.key_provider.get_user_kek(owner_id, key_version=payload.key_version)
            aes_kek = AESGCM(user_kek)

            # 2. Unwrap DEK
            dek_nonce = self._b64d(payload.dek_nonce_b64)
            wrapped_dek = self._b64d(payload.wrapped_dek_b64)
            dek_aad = f"wrapped_dek:{memory_id}:{payload.key_version}".encode("utf-8")
            dek = aes_kek.decrypt(dek_nonce, wrapped_dek, dek_aad)

            # 3. Decrypt ciphertext with unwrapped DEK
            content_nonce = self._b64d(payload.nonce_b64)
            ciphertext = self._b64d(payload.ciphertext_b64)
            aad = self._build_aad(memory_id, owner_id, category)
            aes_dek = AESGCM(dek)
            plaintext_bytes = aes_dek.decrypt(content_nonce, ciphertext, aad)
            plaintext = plaintext_bytes.decode("utf-8")

            # 4. Verify integrity against content fingerprint if present
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
        Rotates KEK version by unwrapping DEK under old KEK and wrapping under new KEK.
        Ciphertext remains untouched, achieving O(1) key rotation per memory.
        """
        try:
            # 1. Unwrap with old KEK
            old_kek = self.key_provider.get_user_kek(owner_id, key_version=old_version)
            aes_old = AESGCM(old_kek)
            old_nonce = self._b64d(dek_nonce_b64)
            wrapped_dek = self._b64d(wrapped_dek_b64)
            old_aad = f"wrapped_dek:{memory_id}:{old_version}".encode("utf-8")
            dek = aes_old.decrypt(old_nonce, wrapped_dek, old_aad)

            # 2. Rewrap with new KEK and fresh nonce
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

"""Key management provider abstraction and local development provider."""

import abc
import os
from typing import Dict, Tuple
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
from app.core.config import settings


class KeyProvider(abc.ABC):
    """Abstract interface for Key-Encryption-Key (KEK) management."""

    @abc.abstractmethod
    def get_user_kek(self, owner_id: str, key_version: int = 1) -> bytes:
        """Retrieves or derives the 256-bit KEK for a specific user and version."""
        pass

    @abc.abstractmethod
    def rotate_user_kek(self, owner_id: str) -> Tuple[int, bytes]:
        """Rotates the user KEK to the next version and returns (new_version, new_kek)."""
        pass


class LocalDevKeyProvider(KeyProvider):
    """
    Deterministic cryptographic Key Provider using HKDF-SHA256.
    Derives per-user KEKs from PRIVGUARD_MASTER_KEY without persisting plaintext KEKs.
    """

    SALT = b"privguard_msl_memory_vault_salt_v1"

    def __init__(self, master_key: str = None) -> None:
        self.master_key = (master_key or settings.PRIVGUARD_MASTER_KEY).encode("utf-8")
        self._user_versions: Dict[str, int] = {}

    def get_user_kek(self, owner_id: str, key_version: int = 1) -> bytes:
        """Derives a 256-bit KEK for the given owner_id and version using HKDF-SHA256."""
        if not owner_id or not owner_id.strip():
            raise ValueError("owner_id must not be empty")

        clean_owner = owner_id.strip()
        info = f"privguard_memory_kek_v{key_version}:{clean_owner}".encode("utf-8")

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.SALT,
            info=info,
        )
        return hkdf.derive(self.master_key)

    def rotate_user_kek(self, owner_id: str) -> Tuple[int, bytes]:
        """Advances the key version for the user and generates the new KEK."""
        clean_owner = owner_id.strip()
        current_version = self._user_versions.get(clean_owner, 1)
        new_version = current_version + 1
        self._user_versions[clean_owner] = new_version
        new_kek = self.get_user_kek(clean_owner, key_version=new_version)
        return new_version, new_kek


# Global singleton key provider instance
default_key_provider = LocalDevKeyProvider()

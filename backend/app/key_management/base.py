"""Base classes, enums, and interfaces for provider-independent Key Management Services (KMS)."""

import abc
import asyncio
from enum import Enum
from typing import Dict, NamedTuple, Optional


class KMSProviderType(str, Enum):
    """Supported KMS provider backends."""

    LOCAL = "local"
    AWS_KMS = "aws_kms"
    GCP_KMS = "gcp_kms"
    AZURE_KEY_VAULT = "azure_key_vault"
    VAULT_TRANSIT = "vault_transit"


class KeyPurpose(str, Enum):
    """Cryptographic purpose classification."""

    MEMORY_ENCRYPTION = "MEMORY_ENCRYPTION"
    POLICY_SIGNING = "POLICY_SIGNING"
    APPROVAL_BINDING = "APPROVAL_BINDING"
    INTEGRATION_SECRETS = "INTEGRATION_SECRETS"
    EVIDENCE_SIGNING = "EVIDENCE_SIGNING"
    BACKUP_SIGNING = "BACKUP_SIGNING"


class KeyStatus(str, Enum):
    """Key lifecycle status state machine."""

    CREATED = "CREATED"
    ACTIVE = "ACTIVE"
    ROTATION_PENDING = "ROTATION_PENDING"
    ROTATING = "ROTATING"
    VERIFYING = "VERIFYING"
    RETIRED = "RETIRED"
    COMPROMISED = "COMPROMISED"
    DESTROYED = "DESTROYED"


class KeyAlgorithm(str, Enum):
    """Supported cryptographic algorithms."""

    AES_256_GCM = "AES_256_GCM"
    ED25519 = "ED25519"
    HMAC_SHA256 = "HMAC_SHA256"


class WrappedKeyResult(NamedTuple):
    """Result of wrapping a data encryption key (DEK)."""

    wrapped_key: bytes
    key_version: str
    nonce: Optional[bytes] = None
    provider: str = ""


class KeyMetadata(NamedTuple):
    """Descriptive metadata for a managed cryptographic key."""

    key_id: str
    provider: str
    key_version: str
    status: KeyStatus
    algorithm: KeyAlgorithm
    created_at: str
    server_side_rewrap_supported: bool


class KMSCapabilities(NamedTuple):
    """Explicit functional capabilities of a KMS provider."""

    server_side_rewrap: bool
    asymmetric_signing: bool
    versioning: bool
    client_side_envelope: bool


class KMSProvider(abc.ABC):
    """
    Abstract interface for provider-independent Key Management Service (KMS).
    Supports both synchronous and asynchronous operations to integrate seamlessly
    with synchronous cryptographic engines and async API handlers.
    """

    @property
    @abc.abstractmethod
    def provider_type(self) -> KMSProviderType:
        """Returns the KMS provider type."""
        pass

    @property
    @abc.abstractmethod
    def capabilities(self) -> KMSCapabilities:
        """Returns explicit capabilities supported by this provider."""
        pass

    @abc.abstractmethod
    def wrap_key_sync(
        self,
        key_id: str,
        plaintext_key: bytes,
        encryption_context: Optional[Dict[str, str]] = None,
    ) -> WrappedKeyResult:
        """Synchronously wraps a 256-bit plaintext DEK under the target KEK."""
        pass

    @abc.abstractmethod
    def unwrap_key_sync(
        self,
        key_id: str,
        wrapped_key: bytes,
        encryption_context: Optional[Dict[str, str]] = None,
        key_version: Optional[str] = None,
        nonce: Optional[bytes] = None,
    ) -> bytes:
        """Synchronously unwraps a wrapped DEK into plaintext key bytes."""
        pass

    @abc.abstractmethod
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
        """Synchronously rewraps an existing wrapped DEK under a new KEK or version."""
        pass

    async def wrap_key(
        self,
        key_id: str,
        plaintext_key: bytes,
        encryption_context: Optional[Dict[str, str]] = None,
    ) -> WrappedKeyResult:
        """Asynchronously wraps a 256-bit plaintext DEK."""
        return self.wrap_key_sync(key_id, plaintext_key, encryption_context)

    async def unwrap_key(
        self,
        key_id: str,
        wrapped_key: bytes,
        encryption_context: Optional[Dict[str, str]] = None,
        key_version: Optional[str] = None,
        nonce: Optional[bytes] = None,
    ) -> bytes:
        """Asynchronously unwraps a wrapped DEK."""
        return self.unwrap_key_sync(key_id, wrapped_key, encryption_context, key_version, nonce)

    async def rewrap_key(
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
        """Asynchronously rewraps an existing wrapped DEK."""
        return self.rewrap_key_sync(
            key_id, new_key_id, wrapped_key, old_context, new_context, old_version, new_version, old_nonce
        )

    @abc.abstractmethod
    def get_key_metadata(self, key_id: str) -> KeyMetadata:
        """Retrieves current metadata for the specified key."""
        pass

    @abc.abstractmethod
    def verify_key_access(self, key_id: str) -> bool:
        """Validates that PRIVGUARD has connectivity and authorization to use the key."""
        pass

    @abc.abstractmethod
    def get_active_key_version(self, key_id: str) -> str:
        """Returns the current active version identifier for writes."""
        pass

    @abc.abstractmethod
    def rotate_key(self, key_id: str) -> str:
        """Initiates key rotation in the provider and returns the newly active version identifier."""
        pass

    @abc.abstractmethod
    def disable_key(self, key_id: str) -> bool:
        """Disables the specified key."""
        pass

    @abc.abstractmethod
    def enable_key(self, key_id: str) -> bool:
        """Re-enables a previously disabled key."""
        pass

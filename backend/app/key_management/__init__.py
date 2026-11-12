"""Key Management Service (KMS) abstraction package."""

from app.key_management.base import (
    KeyAlgorithm,
    KeyMetadata,
    KeyPurpose,
    KeyStatus,
    KMSCapabilities,
    KMSProvider,
    KMSProviderType,
    WrappedKeyResult,
)
from app.key_management.manager import KMSManager, kms_manager
from app.key_management.registry import KMSRegistry

__all__ = [
    "KMSProviderType",
    "KeyPurpose",
    "KeyStatus",
    "KeyAlgorithm",
    "WrappedKeyResult",
    "KeyMetadata",
    "KMSCapabilities",
    "KMSProvider",
    "KMSManager",
    "kms_manager",
    "KMSRegistry",
]

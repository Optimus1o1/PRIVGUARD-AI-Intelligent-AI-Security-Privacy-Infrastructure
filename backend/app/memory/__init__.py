"""PRIVGUARD Secure Personal AI Memory Vault."""

from app.memory.crypto import (
    EncryptedMemoryPayload,
    EnvelopeEncryption,
    envelope_encryption,
)
from app.memory.key_provider import (
    KeyProvider,
    LocalDevKeyProvider,
    default_key_provider,
)
from app.memory.permissions import (
    MemoryPermissionEngine,
    memory_permission_engine,
)
from app.memory.retrieval import (
    MemoryRetrievalService,
    memory_retrieval_service,
)
from app.memory.validator import (
    ALLOWED_MEMORY_CATEGORIES,
    MemoryValidator,
    memory_validator,
)
from app.memory.vault import (
    MemoryVault,
    memory_vault,
)

__all__ = [
    "EncryptedMemoryPayload",
    "EnvelopeEncryption",
    "envelope_encryption",
    "KeyProvider",
    "LocalDevKeyProvider",
    "default_key_provider",
    "MemoryPermissionEngine",
    "memory_permission_engine",
    "MemoryRetrievalService",
    "memory_retrieval_service",
    "ALLOWED_MEMORY_CATEGORIES",
    "MemoryValidator",
    "memory_validator",
    "MemoryVault",
    "memory_vault",
]

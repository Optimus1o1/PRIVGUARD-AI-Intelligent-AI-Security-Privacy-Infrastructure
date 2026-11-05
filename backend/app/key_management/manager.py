"""Central coordinator and lifecycle manager for Key Management Service (KMS) operations."""

from typing import Any, Dict, Optional
from app.core.config import settings
from app.core.exceptions import PrivGuardException
from app.key_management.base import (
    KeyMetadata,
    KMSProvider,
    KMSProviderType,
    WrappedKeyResult,
)
from app.key_management.registry import KMSRegistry


class KMSManager:
    """
    Singleton coordinator managing active KMS providers, health checks,
    and delegating cryptographic key wrapping operations.
    """

    def __init__(self, provider: Optional[KMSProvider] = None) -> None:
        self._provider = provider
        self._metadata_cache: Dict[str, KeyMetadata] = {}

    def get_provider(self) -> KMSProvider:
        """Resolves and returns the configured KMS provider."""
        if self._provider is not None:
            return self._provider

        raw_type = settings.KMS_PROVIDER.lower().strip()
        try:
            ptype = KMSProviderType(raw_type)
        except ValueError:
            raise PrivGuardException(
                f"Unknown KMS_PROVIDER '{raw_type}'. Supported: {[p.value for p in KMSProviderType]}",
                status_code=500,
                error_code="INVALID_KMS_CONFIG",
            )

        # Enforce production invariant: never allow local provider in production
        is_production = settings.ENVIRONMENT.lower() in ("production", "prod")
        if is_production and ptype == KMSProviderType.LOCAL:
            raise PrivGuardException(
                "Security violation: Local KMS provider is strictly prohibited in production.",
                status_code=500,
                error_code="PRODUCTION_LOCAL_KMS_PROHIBITED",
            )

        provider_cls = KMSRegistry.get(ptype)
        if ptype == KMSProviderType.AWS_KMS:
            self._provider = provider_cls(
                region_name=settings.KMS_REGION,
                endpoint_url=settings.KMS_ENDPOINT,
            )
        elif ptype == KMSProviderType.LOCAL:
            self._provider = provider_cls(master_key=settings.PRIVGUARD_MASTER_KEY)
        else:
            self._provider = provider_cls()

        return self._provider

    def set_provider(self, provider: Optional[KMSProvider]) -> None:
        """Injects or resets the active KMS provider (used for testing)."""
        self._provider = provider
        self._metadata_cache.clear()

    def wrap_dek_sync(
        self,
        key_id: str,
        plaintext_dek: bytes,
        tenant_id: str,
        format_version: str = "v2",
        additional_context: Optional[Dict[str, str]] = None,
    ) -> WrappedKeyResult:
        """Synchronously wraps a 256-bit DEK under the specified KMS KEK."""
        provider = self.get_provider()
        context = {
            "tenant_id": tenant_id,
            "format": format_version,
            "resource": "memory",
        }
        if additional_context:
            for k, v in additional_context.items():
                if k not in ("plaintext", "password", "secret", "user_content"):
                    context[k] = str(v)

        return provider.wrap_key_sync(key_id, plaintext_dek, encryption_context=context)

    def unwrap_dek_sync(
        self,
        key_id: str,
        wrapped_dek: bytes,
        tenant_id: str,
        format_version: str = "v2",
        key_version: Optional[str] = None,
        nonce: Optional[bytes] = None,
        additional_context: Optional[Dict[str, str]] = None,
    ) -> bytes:
        """Synchronously unwraps a wrapped DEK into plaintext key bytes."""
        provider = self.get_provider()
        context = {
            "tenant_id": tenant_id,
            "format": format_version,
            "resource": "memory",
        }
        if additional_context:
            for k, v in additional_context.items():
                if k not in ("plaintext", "password", "secret", "user_content"):
                    context[k] = str(v)

        return provider.unwrap_key_sync(
            key_id=key_id,
            wrapped_key=wrapped_dek,
            encryption_context=context,
            key_version=key_version,
            nonce=nonce,
        )

    def rewrap_dek_sync(
        self,
        key_id: str,
        new_key_id: str,
        wrapped_dek: bytes,
        tenant_id: str,
        old_version: Optional[str] = None,
        new_version: Optional[str] = None,
        old_nonce: Optional[bytes] = None,
    ) -> WrappedKeyResult:
        """Synchronously rewraps a DEK from old KEK to new KEK."""
        provider = self.get_provider()
        old_context = {"tenant_id": tenant_id, "format": "v2", "resource": "memory"}
        new_context = {"tenant_id": tenant_id, "format": "v2", "resource": "memory"}

        return provider.rewrap_key_sync(
            key_id=key_id,
            new_key_id=new_key_id,
            wrapped_key=wrapped_dek,
            old_context=old_context,
            new_context=new_context,
            old_version=old_version,
            new_version=new_version,
            old_nonce=old_nonce,
        )

    async def wrap_dek(
        self,
        key_id: str,
        plaintext_dek: bytes,
        tenant_id: str,
        format_version: str = "v2",
        additional_context: Optional[Dict[str, str]] = None,
    ) -> WrappedKeyResult:
        return self.wrap_dek_sync(key_id, plaintext_dek, tenant_id, format_version, additional_context)

    async def unwrap_dek(
        self,
        key_id: str,
        wrapped_dek: bytes,
        tenant_id: str,
        format_version: str = "v2",
        key_version: Optional[str] = None,
        nonce: Optional[bytes] = None,
        additional_context: Optional[Dict[str, str]] = None,
    ) -> bytes:
        return self.unwrap_dek_sync(
            key_id, wrapped_dek, tenant_id, format_version, key_version, nonce, additional_context
        )

    async def rewrap_dek(
        self,
        key_id: str,
        new_key_id: str,
        wrapped_dek: bytes,
        tenant_id: str,
        old_version: Optional[str] = None,
        new_version: Optional[str] = None,
        old_nonce: Optional[bytes] = None,
    ) -> WrappedKeyResult:
        return self.rewrap_dek_sync(
            key_id, new_key_id, wrapped_dek, tenant_id, old_version, new_version, old_nonce
        )

    def verify_health(self, key_id: Optional[str] = None) -> bool:
        """Verifies operational connectivity to the active KMS provider."""
        try:
            provider = self.get_provider()
            target_key = key_id or settings.KMS_KEY_ID or "default_key"
            return provider.verify_key_access(target_key)
        except Exception:
            return False


# Global singleton KMS manager instance
kms_manager = KMSManager()

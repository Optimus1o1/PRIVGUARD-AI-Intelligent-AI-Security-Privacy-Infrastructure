"""Registry for KMS provider backends."""

from typing import Dict, Type
from app.core.exceptions import PrivGuardException
from app.key_management.base import KMSProvider, KMSProviderType
from app.key_management.providers.local import LocalKMSProvider
from app.key_management.providers.aws_kms import AWSKMSProvider
from app.key_management.providers.gcp_kms import GCPKMSProvider
from app.key_management.providers.azure_key_vault import AzureKeyVaultProvider
from app.key_management.providers.vault_transit import VaultTransitProvider


class KMSRegistry:
    """Central registry mapping provider types to provider classes."""

    _providers: Dict[KMSProviderType, Type[KMSProvider]] = {
        KMSProviderType.LOCAL: LocalKMSProvider,
        KMSProviderType.AWS_KMS: AWSKMSProvider,
        KMSProviderType.GCP_KMS: GCPKMSProvider,
        KMSProviderType.AZURE_KEY_VAULT: AzureKeyVaultProvider,
        KMSProviderType.VAULT_TRANSIT: VaultTransitProvider,
    }

    @classmethod
    def register(cls, provider_type: KMSProviderType, provider_cls: Type[KMSProvider]) -> None:
        cls._providers[provider_type] = provider_cls

    @classmethod
    def get(cls, provider_type: KMSProviderType) -> Type[KMSProvider]:
        if provider_type not in cls._providers:
            raise PrivGuardException(
                f"Unsupported KMS provider '{provider_type}'. Supported: {[p.value for p in cls._providers.keys()]}",
                status_code=400,
                error_code="UNSUPPORTED_KMS_PROVIDER",
            )
        return cls._providers[provider_type]

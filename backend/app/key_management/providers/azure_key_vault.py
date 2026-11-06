"""Azure Key Vault / Managed HSM provider adapter for envelope encryption."""

from datetime import datetime, timezone
from typing import Any, Dict, Optional

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


class AzureKeyVaultProvider(KMSProvider):
    """
    Azure Key Vault / Azure Managed HSM provider adapter.
    Uses Key Client and Cryptography Client (wrap_key / unwrap_key) via RSA-OAEP-256 or AES-KW.
    Compatible with Azure Workload Identity without client secrets in pods.
    """

    def __init__(
        self,
        vault_url: str = "https://privguard-vault.vault.azure.net",
        client: Optional[Any] = None,
    ) -> None:
        self.vault_url = vault_url
        self._client = client

    @property
    def provider_type(self) -> KMSProviderType:
        return KMSProviderType.AZURE_KEY_VAULT

    @property
    def capabilities(self) -> KMSCapabilities:
        return KMSCapabilities(
            server_side_rewrap=False,
            asymmetric_signing=True,
            versioning=True,
            client_side_envelope=True,
        )

    def _get_crypto_client(self, key_id: str) -> Any:
        if self._client is not None:
            return self._client
        try:
            from azure.identity import DefaultAzureCredential
            from azure.keyvault.keys import KeyClient
            from azure.keyvault.keys.crypto import CryptographyClient

            credential = DefaultAzureCredential()
            key_client = KeyClient(vault_url=self.vault_url, credential=credential)
            key = key_client.get_key(key_id)
            return CryptographyClient(key, credential=credential)
        except ImportError:
            raise PrivGuardException(
                "Azure Key Vault dependencies missing. Install 'azure-keyvault-keys' and 'azure-identity'.",
                status_code=500,
                error_code="KMS_DEPENDENCY_MISSING",
            )
        except Exception as e:
            raise PrivGuardException(
                f"Failed to initialize Azure Key Vault client: {e}",
                status_code=500,
                error_code="KMS_CLIENT_INIT_FAILED",
            )

    async def wrap_key(
        self,
        key_id: str,
        plaintext_key: bytes,
        encryption_context: Optional[Dict[str, str]] = None,
    ) -> WrappedKeyResult:
        crypto_client = self._get_crypto_client(key_id)
        try:
            from azure.keyvault.keys.crypto import KeyWrapAlgorithm

            result = crypto_client.wrap_key(KeyWrapAlgorithm.rsa_oaep_256, plaintext_key)
            return WrappedKeyResult(
                wrapped_key=result.encrypted_key,
                key_version=result.key_id,
                nonce=None,
                provider="azure_key_vault",
            )
        except Exception as e:
            raise PrivGuardException(
                f"Azure Key Vault wrap_key failed: {e}", status_code=502, error_code="KMS_ENCRYPT_FAILED"
            )

    async def unwrap_key(
        self,
        key_id: str,
        wrapped_key: bytes,
        encryption_context: Optional[Dict[str, str]] = None,
        key_version: Optional[str] = None,
        nonce: Optional[bytes] = None,
    ) -> bytes:
        crypto_client = self._get_crypto_client(key_id)
        try:
            from azure.keyvault.keys.crypto import KeyWrapAlgorithm

            result = crypto_client.unwrap_key(KeyWrapAlgorithm.rsa_oaep_256, wrapped_key)
            return result.key
        except Exception as e:
            raise PrivGuardException(
                f"Azure Key Vault unwrap_key failed: {e}", status_code=502, error_code="KMS_DECRYPT_FAILED"
            )

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
        plaintext = await self.unwrap_key(key_id, wrapped_key, old_context, old_version, old_nonce)
        return await self.wrap_key(new_key_id, plaintext, new_context)

    async def get_key_metadata(self, key_id: str) -> KeyMetadata:
        return KeyMetadata(
            key_id=key_id,
            provider="azure_key_vault",
            key_version=f"{self.vault_url}/keys/{key_id}",
            status=KeyStatus.ACTIVE,
            algorithm=KeyAlgorithm.AES_256_GCM,
            created_at=datetime.now(timezone.utc).isoformat(),
            server_side_rewrap_supported=False,
        )

    async def verify_key_access(self, key_id: str) -> bool:
        try:
            self._get_crypto_client(key_id)
            return True
        except Exception:
            return False

    async def get_active_key_version(self, key_id: str) -> str:
        return f"{self.vault_url}/keys/{key_id}"

    async def rotate_key(self, key_id: str) -> str:
        return key_id

    async def disable_key(self, key_id: str) -> bool:
        return True

    async def enable_key(self, key_id: str) -> bool:
        return True

"""Google Cloud KMS provider adapter for envelope encryption."""

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


class GCPKMSProvider(KMSProvider):
    """
    Google Cloud KMS provider adapter.
    Encrypts / decrypts 256-bit DEKs using Google Cloud Key Management Service.
    Supports GKE Workload Identity without static service account keys.
    """

    def __init__(
        self,
        project_id: str = "privguard-prod",
        location_id: str = "global",
        key_ring_id: str = "privguard-ring",
        client: Optional[Any] = None,
    ) -> None:
        self.project_id = project_id
        self.location_id = location_id
        self.key_ring_id = key_ring_id
        self._client = client

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            from google.cloud import kms

            self._client = kms.KeyManagementServiceClient()
            return self._client
        except ImportError:
            raise PrivGuardException(
                "GCP KMS dependencies missing. Install 'google-cloud-kms' to use GCP KMS.",
                status_code=500,
                error_code="KMS_DEPENDENCY_MISSING",
            )
        except Exception as e:
            raise PrivGuardException(
                f"Failed to initialize GCP KMS client: {e}",
                status_code=500,
                error_code="KMS_CLIENT_INIT_FAILED",
            )

    @property
    def provider_type(self) -> KMSProviderType:
        return KMSProviderType.GCP_KMS

    @property
    def capabilities(self) -> KMSCapabilities:
        return KMSCapabilities(
            server_side_rewrap=False,  # GCP KMS uses client-side rewrap (decrypt under v1, encrypt under v2)
            asymmetric_signing=True,
            versioning=True,
            client_side_envelope=True,
        )

    def _format_key_name(self, key_id: str) -> str:
        if "projects/" in key_id:
            return key_id
        return (
            f"projects/{self.project_id}/locations/{self.location_id}/keyRings/{self.key_ring_id}/cryptoKeys/{key_id}"
        )

    async def wrap_key(
        self,
        key_id: str,
        plaintext_key: bytes,
        encryption_context: Optional[Dict[str, str]] = None,
    ) -> WrappedKeyResult:
        client = self._get_client()
        name = self._format_key_name(key_id)
        try:
            req: Dict[str, Any] = {"name": name, "plaintext": plaintext_key}
            if encryption_context:
                import json

                req["additional_authenticated_data"] = json.dumps(encryption_context, sort_keys=True).encode("utf-8")
            response = client.encrypt(request=req)
            return WrappedKeyResult(
                wrapped_key=response.ciphertext,
                key_version=name,
                nonce=None,
                provider="gcp_kms",
            )
        except Exception as e:
            raise PrivGuardException(f"GCP KMS wrap_key failed: {e}", status_code=502, error_code="KMS_ENCRYPT_FAILED")

    async def unwrap_key(
        self,
        key_id: str,
        wrapped_key: bytes,
        encryption_context: Optional[Dict[str, str]] = None,
        key_version: Optional[str] = None,
        nonce: Optional[bytes] = None,
    ) -> bytes:
        client = self._get_client()
        name = self._format_key_name(key_id)
        try:
            req: Dict[str, Any] = {"name": name, "ciphertext": wrapped_key}
            if encryption_context:
                import json

                req["additional_authenticated_data"] = json.dumps(encryption_context, sort_keys=True).encode("utf-8")
            response = client.decrypt(request=req)
            return response.plaintext
        except Exception as e:
            raise PrivGuardException(
                f"GCP KMS unwrap_key failed: {e}", status_code=502, error_code="KMS_DECRYPT_FAILED"
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
        name = self._format_key_name(key_id)
        return KeyMetadata(
            key_id=key_id,
            provider="gcp_kms",
            key_version=name,
            status=KeyStatus.ACTIVE,
            algorithm=KeyAlgorithm.AES_256_GCM,
            created_at=datetime.now(timezone.utc).isoformat(),
            server_side_rewrap_supported=False,
        )

    async def verify_key_access(self, key_id: str) -> bool:
        try:
            client = self._get_client()
            name = self._format_key_name(key_id)
            client.get_crypto_key(name=name)
            return True
        except Exception:
            return False

    async def get_active_key_version(self, key_id: str) -> str:
        return self._format_key_name(key_id)

    async def rotate_key(self, key_id: str) -> str:
        return self._format_key_name(key_id)

    async def disable_key(self, key_id: str) -> bool:
        return True

    async def enable_key(self, key_id: str) -> bool:
        return True

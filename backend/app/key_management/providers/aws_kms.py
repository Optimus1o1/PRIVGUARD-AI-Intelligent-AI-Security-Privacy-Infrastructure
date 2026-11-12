"""AWS KMS provider adapter supporting envelope encryption and native server-side re-encryption."""

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


class AWSKMSProvider(KMSProvider):
    """
    AWS Key Management Service (KMS) provider adapter.

    Features:
    - Encrypt / Decrypt for 256-bit DEK wrapping.
    - Native server-side ReEncrypt (O(1) HSM rewrap without client-side plaintext exposure).
    - Compatible with AWS IAM Roles for Service Accounts (IRSA) without static credentials.
    - Optional boto3 integration with mocked fallback for deterministic CI.
    """

    def __init__(
        self,
        region_name: str = "us-east-1",
        endpoint_url: Optional[str] = None,
        boto_client: Optional[Any] = None,
    ) -> None:
        self.region_name = region_name
        self.endpoint_url = endpoint_url
        self._client = boto_client

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            import boto3

            self._client = boto3.client(
                "kms",
                region_name=self.region_name,
                endpoint_url=self.endpoint_url,
            )
            return self._client
        except ImportError:
            raise PrivGuardException(
                "AWS KMS dependencies missing. Install 'boto3' to use AWS KMS.",
                status_code=500,
                error_code="KMS_DEPENDENCY_MISSING",
            )
        except Exception as e:
            raise PrivGuardException(
                f"Failed to initialize AWS KMS client: {e}",
                status_code=500,
                error_code="KMS_CLIENT_INIT_FAILED",
            )

    @property
    def provider_type(self) -> KMSProviderType:
        return KMSProviderType.AWS_KMS

    @property
    def capabilities(self) -> KMSCapabilities:
        return KMSCapabilities(
            server_side_rewrap=True,  # AWS KMS supports native ReEncrypt API
            asymmetric_signing=True,
            versioning=True,
            client_side_envelope=True,
        )

    def wrap_key_sync(
        self,
        key_id: str,
        plaintext_key: bytes,
        encryption_context: Optional[Dict[str, str]] = None,
    ) -> WrappedKeyResult:
        client = self._get_client()
        params: Dict[str, Any] = {
            "KeyId": key_id,
            "Plaintext": plaintext_key,
        }
        if encryption_context:
            params["EncryptionContext"] = encryption_context

        try:
            response = client.encrypt(**params)
            ciphertext_blob = response["CiphertextBlob"]
            key_arn = response.get("KeyId", key_id)
            return WrappedKeyResult(
                wrapped_key=ciphertext_blob,
                key_version=key_arn,
                nonce=None,
                provider="aws_kms",
            )
        except Exception as e:
            raise PrivGuardException(
                f"AWS KMS wrap_key failed: {e}",
                status_code=502,
                error_code="KMS_ENCRYPT_FAILED",
            )

    def unwrap_key_sync(
        self,
        key_id: str,
        wrapped_key: bytes,
        encryption_context: Optional[Dict[str, str]] = None,
        key_version: Optional[str] = None,
        nonce: Optional[bytes] = None,
    ) -> bytes:
        client = self._get_client()
        params: Dict[str, Any] = {
            "CiphertextBlob": wrapped_key,
            "KeyId": key_id,
        }
        if encryption_context:
            params["EncryptionContext"] = encryption_context

        try:
            response = client.decrypt(**params)
            return response["Plaintext"]
        except Exception as e:
            raise PrivGuardException(
                f"AWS KMS unwrap_key failed: {e}",
                status_code=502,
                error_code="KMS_DECRYPT_FAILED",
            )

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
        client = self._get_client()
        params: Dict[str, Any] = {
            "CiphertextBlob": wrapped_key,
            "SourceKeyId": key_id,
            "DestinationKeyId": new_key_id,
        }
        if old_context:
            params["SourceEncryptionContext"] = old_context
        if new_context:
            params["DestinationEncryptionContext"] = new_context

        try:
            response = client.re_encrypt(**params)
            return WrappedKeyResult(
                wrapped_key=response["CiphertextBlob"],
                key_version=response.get("KeyId", new_key_id),
                nonce=None,
                provider="aws_kms",
            )
        except Exception as e:
            raise PrivGuardException(
                f"AWS KMS native re_encrypt failed: {e}",
                status_code=502,
                error_code="KMS_REWRAP_FAILED",
            )

    def get_key_metadata(self, key_id: str) -> KeyMetadata:
        client = self._get_client()
        try:
            resp = client.describe_key(KeyId=key_id)
            meta = resp.get("KeyMetadata", {})
            enabled = meta.get("Enabled", True)
            state = meta.get("KeyState", "Enabled")
            status = KeyStatus.ACTIVE if (enabled and state == "Enabled") else KeyStatus.DISABLED
            return KeyMetadata(
                key_id=key_id,
                provider="aws_kms",
                key_version=meta.get("Arn", key_id),
                status=status,
                algorithm=KeyAlgorithm.AES_256_GCM,
                created_at=str(meta.get("CreationDate", datetime.now(timezone.utc).isoformat())),
                server_side_rewrap_supported=True,
            )
        except Exception as e:
            raise PrivGuardException(
                f"AWS KMS describe_key failed for '{key_id}': {e}",
                status_code=502,
                error_code="KMS_METADATA_FAILED",
            )

    def verify_key_access(self, key_id: str) -> bool:
        try:
            meta = self.get_key_metadata(key_id)
            return meta.status == KeyStatus.ACTIVE
        except Exception:
            return False

    def get_active_key_version(self, key_id: str) -> str:
        meta = self.get_key_metadata(key_id)
        return meta.key_version

    def rotate_key(self, key_id: str) -> str:
        return key_id

    def disable_key(self, key_id: str) -> bool:
        client = self._get_client()
        try:
            client.disable_key(KeyId=key_id)
            return True
        except Exception as e:
            raise PrivGuardException(f"Failed to disable AWS KMS key: {e}", status_code=502)

    def enable_key(self, key_id: str) -> bool:
        client = self._get_client()
        try:
            client.enable_key(KeyId=key_id)
            return True
        except Exception as e:
            raise PrivGuardException(f"Failed to enable AWS KMS key: {e}", status_code=502)

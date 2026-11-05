"""Adapter for cloud-based external secret managers (AWS Secrets Manager / Vault)."""

from typing import Any, Dict, Optional


class ExternalSecretManagerProvider:
    """
    Adapter fetching secrets on-demand from enterprise secret managers
    (AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, or HashiCorp Vault).
    """

    def __init__(self, client: Optional[Any] = None) -> None:
        self._client = client
        self._cache: Dict[str, str] = {}

    def get_secret(self, secret_id: str) -> Optional[str]:
        if secret_id in self._cache:
            return self._cache[secret_id]
        if self._client is not None:
            try:
                res = self._client.get_secret_value(SecretId=secret_id)
                val = res.get("SecretString")
                if val:
                    self._cache[secret_id] = val
                    return val
            except Exception:
                return None
        return None

    def store_cached_secret(self, secret_id: str, value: str) -> None:
        self._cache[secret_id] = value

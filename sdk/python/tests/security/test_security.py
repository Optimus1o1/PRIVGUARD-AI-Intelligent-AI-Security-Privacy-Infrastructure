"""Security and credential-safety tests for PRIVGUARD SDK."""

from privguard_sdk.async_client import AsyncPrivGuardClient
from privguard_sdk.client import PrivGuardClient
from privguard_sdk.config import PrivGuardConfig
from privguard_sdk.exceptions import PrivGuardError


def test_repr_never_leaks_api_key():
    secret_key = "sk-super-secret-live-production-api-token-999"
    cfg = PrivGuardConfig(api_key=secret_key)
    client = PrivGuardClient(config=cfg)
    async_client = AsyncPrivGuardClient(config=cfg)

    # Invariants: The raw key must not appear in any representation
    assert secret_key not in repr(cfg)
    assert secret_key not in repr(client)
    assert secret_key not in repr(async_client)
    assert secret_key not in str(cfg)

    # Check masked token format
    assert "sk-s...-999" in repr(cfg)


def test_tls_verification_defaults_to_true():
    cfg = PrivGuardConfig()
    assert cfg.verify_ssl is True
    client = PrivGuardClient(config=cfg)
    assert client._transport._client.base_url.host == "localhost"


def test_follow_redirects_disabled_by_default_to_prevent_ssrf():
    client = PrivGuardClient(api_key="sk-test")
    # Invariant: follow_redirects must be False
    assert client._transport._client.follow_redirects is False

    async_client = AsyncPrivGuardClient(api_key="sk-test")
    assert async_client._transport._client.follow_redirects is False


def test_exception_representation_safety():
    err = PrivGuardError(
        message="Failure occurred",
        status_code=500,
        error_code="INTERNAL_ERROR",
        request_id="req_987",
        details={"hint": "Safe message"},
    )
    repr_str = repr(err)
    assert "INTERNAL_ERROR" in repr_str
    assert "req_987" in repr_str
    assert "retryable" in repr_str

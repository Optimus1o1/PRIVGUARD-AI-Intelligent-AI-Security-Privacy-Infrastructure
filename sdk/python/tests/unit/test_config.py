"""Unit tests for PRIVGUARD SDK configuration."""

from privguard_sdk.config import PrivGuardConfig


def test_default_config():
    config = PrivGuardConfig()
    assert config.base_url == "http://localhost:8000"
    assert config.max_retries == 3
    assert config.verify_ssl is True


def test_custom_config_and_trailing_slash_normalization():
    config = PrivGuardConfig(
        base_url="https://api.privguard.io/v1/",
        api_key="sk-test-secret-key-12345",
        tenant_id="tenant_omega",
        user_id="user_alice",
        workspace_id="ws_finance",
        max_retries=5,
    )
    assert config.base_url == "https://api.privguard.io/v1"
    assert config.api_key == "sk-test-secret-key-12345"
    assert config.tenant_id == "tenant_omega"

    headers = config.build_headers()
    assert headers["X-API-Key"] == "sk-test-secret-key-12345"
    assert headers["X-Tenant-ID"] == "tenant_omega"
    assert headers["X-User-ID"] == "user_alice"
    assert headers["X-Workspace-ID"] == "ws_finance"
    assert "privguard-python-sdk" in headers["User-Agent"]


def test_config_repr_masks_credentials():
    config = PrivGuardConfig(
        api_key="sk-very-secret-production-token-99999",
        tenant_id="tenant_secret",
    )
    repr_str = repr(config)
    assert "sk-very-secret-production-token-99999" not in repr_str
    assert "sk-v...9999" in repr_str

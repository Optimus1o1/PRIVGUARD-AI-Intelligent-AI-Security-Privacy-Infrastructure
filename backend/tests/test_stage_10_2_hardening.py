"""Stage 10.2 Security Hardening, Key Validation, Health Probes & Production Config Tests.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import os
import pytest
import httpx
from fastapi.testclient import TestClient
from pydantic import ValidationError
from app.core.config import Settings
from app.main import app


@pytest.fixture
def client():
    return TestClient(app)


def test_01_health_live_endpoint(client: TestClient):
    """Test 1: /health/live liveness probe returns process status without leaking internal state."""
    resp = client.get("/health/live")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "healthy"
    assert "version" in data
    assert "environment" in data


def test_02_health_ready_endpoint(client: TestClient):
    """Test 2: /health/ready readiness probe checks database connectivity."""
    resp = client.get("/health/ready")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ready"
    assert data["ready"] is True
    assert data["checks"]["database"] == "connected"


def test_03_legacy_health_aliases(client: TestClient):
    """Test 3: /health and /ready maintain backward-compatible aliases."""
    resp_health = client.get("/health")
    assert resp_health.status_code == 200
    assert resp_health.json()["status"] == "healthy"

    resp_ready = client.get("/ready")
    assert resp_ready.status_code == 200
    assert resp_ready.json()["status"] == "ready"


def test_04_cors_whitelisting_enforcement(client: TestClient):
    """Test 4: CORS responds with access-control-allow-origin only for whitelisted origins."""
    # Allowed origin: http://localhost:3000
    headers_allowed = {
        "Origin": "http://localhost:3000",
        "Access-Control-Request-Method": "POST",
    }
    resp_allowed = client.options("/v1/privacy/inspect", headers=headers_allowed)
    assert resp_allowed.headers.get("access-control-allow-origin") == "http://localhost:3000"

    # Disallowed origin: https://malicious-attacker.com
    headers_disallowed = {
        "Origin": "https://malicious-attacker.com",
        "Access-Control-Request-Method": "POST",
    }
    resp_disallowed = client.options("/v1/privacy/inspect", headers=headers_disallowed)
    assert resp_disallowed.headers.get("access-control-allow-origin") != "https://malicious-attacker.com"


def test_05_debug_admin_backdoor_removed(client: TestClient):
    """Test 5: Providing master key in DEBUG mode does NOT grant unauthenticated root admin access."""
    resp = client.get(
        "/v1/agents",
        headers={"X-API-Key": "change-me-in-production-min-32-chars-long-secret"},
    )
    # Must fail with 401 Unauthorized because the key is not in the database
    assert resp.status_code == 401
    assert "Invalid API key" in resp.json()["error"]["message"]


def test_06_production_rejects_debug_true():
    """Test 6: Settings fails closed when ENVIRONMENT=production and DEBUG=True."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            DEBUG=True,
            PRIVGUARD_MASTER_KEY="a" * 32,
            CORS_ALLOWED_ORIGINS=["https://app.privguard.internal"],
        )
    assert "DEBUG mode must be disabled in production" in str(exc_info.value)


def test_07_production_rejects_default_master_key():
    """Test 7: Settings fails closed when ENVIRONMENT=production and default placeholder is used."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            DEBUG=False,
            PRIVGUARD_MASTER_KEY="change-me-in-production-min-32-chars-long-secret",
            CORS_ALLOWED_ORIGINS=["https://app.privguard.internal"],
        )
    assert "not the default placeholder" in str(exc_info.value)


def test_08_production_rejects_short_master_key():
    """Test 8: Settings fails closed when ENVIRONMENT=production and key entropy is < 32 characters."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            DEBUG=False,
            PRIVGUARD_MASTER_KEY="short_key_12345",
            CORS_ALLOWED_ORIGINS=["https://app.privguard.internal"],
        )
    assert "at least 32 characters" in str(exc_info.value)


def test_09_production_rejects_cors_wildcard():
    """Test 9: Settings fails closed when ENVIRONMENT=production and CORS contains wildcard '*'."""
    with pytest.raises(ValidationError) as exc_info:
        Settings(
            ENVIRONMENT="production",
            DEBUG=False,
            PRIVGUARD_MASTER_KEY="a" * 32,
            CORS_ALLOWED_ORIGINS=["*"],
        )
    assert "CORS wildcard '*' origin is strictly prohibited in production" in str(exc_info.value)


def test_10_production_valid_configuration_succeeds():
    """Test 10: Valid production configuration passes all invariant checks."""
    s = Settings(
        ENVIRONMENT="production",
        DEBUG=False,
        PRIVGUARD_MASTER_KEY="vAl1d_Pr0d_M4st3r_K3y_WiTh_SufF1c13nt_EntR0py_32_Chars!",
        CORS_ALLOWED_ORIGINS=["https://app.privguard.internal"],
        KMS_PROVIDER="aws_kms",
        KMS_KEY_ID="arn:aws:kms:us-east-1:123456789012:key/test-kek",
    )
    assert s.ENVIRONMENT == "production"
    assert s.DEBUG is False
    assert len(s.PRIVGUARD_MASTER_KEY) >= 32
    assert s.KMS_PROVIDER == "aws_kms"


def test_11_secret_file_loading(tmp_path):
    """Test 11: Configuration loads credentials from secret files when *_FILE is specified."""
    secret_file = tmp_path / "master_key.txt"
    test_key = "secure_secret_loaded_from_container_file_32chars!"
    secret_file.write_text(test_key, encoding="utf-8")

    s = Settings(
        ENVIRONMENT="development",
        PRIVGUARD_MASTER_KEY_FILE=str(secret_file),
    )
    assert s.PRIVGUARD_MASTER_KEY == test_key

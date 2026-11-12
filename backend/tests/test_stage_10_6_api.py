"""PRIVGUARD AI - Stage 10.6 Observability, Metrics & Canary API Tests.
Verifies /metrics, /health/security, and /v1/monitoring/* endpoints.
"""

import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_01_metrics_endpoint():
    """Test 1: /metrics returns Prometheus format exposition text."""
    resp = client.get("/metrics")
    assert resp.status_code == 200
    assert "text/plain" in resp.headers["content-type"]
    text = resp.text

    assert "privguard_http_requests_total" in text
    assert "privguard_canary_status" in text


def test_02_health_security_endpoint():
    """Test 2: /health/security confirms cryptographic and policy engine integrity."""
    resp = client.get("/health/security")
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] == "healthy"
    assert data["security_ready"] is True
    assert "kms" in data["checks"]
    assert "database" in data["checks"]
    assert "policy_engine" in data["checks"]


def test_03_monitoring_overview_endpoint():
    """Test 3: /v1/monitoring/overview returns platform stats and SLIs."""
    resp = client.get("/v1/monitoring/overview")
    assert resp.status_code == 200
    data = resp.json()

    assert data["status"] in ("nominal", "degraded")
    assert "canary_summary" in data
    assert "slos" in data


def test_04_canaries_list_and_run_endpoints():
    """Test 4: /v1/monitoring/canaries and /run execute and return canary results."""
    # Run all on demand
    run_resp = client.post("/v1/monitoring/canaries/run")
    assert run_resp.status_code == 200
    run_data = run_resp.json()

    assert run_data["summary"]["total_canaries"] == 8
    assert len(run_data["canaries"]) == 8
    assert run_data["summary"]["healthy"] is True

    # List canaries
    list_resp = client.get("/v1/monitoring/canaries")
    assert list_resp.status_code == 200
    list_data = list_resp.json()
    assert len(list_data["canaries"]) == 8


def test_05_single_canary_status_endpoint():
    """Test 5: /v1/monitoring/canaries/{canary_name} returns detail for specific scenario."""
    resp = client.get("/v1/monitoring/canaries/gateway_protection")
    assert resp.status_code == 200
    data = resp.json()

    assert data["canary_name"] == "gateway_protection"
    assert data["passed"] is True
    assert data["severity"] == "critical"

    # 404 for unknown canary
    err_resp = client.get("/v1/monitoring/canaries/non_existent_canary")
    assert err_resp.status_code == 404


def test_06_slos_and_telemetry_endpoints():
    """Test 6: /v1/monitoring/slos, /gateway, /security, /alerts return structured telemetry."""
    # SLOs
    slo_resp = client.get("/v1/monitoring/slos")
    assert slo_resp.status_code == 200
    slos = slo_resp.json()
    assert "api_availability" in slos
    assert "gateway_latency_p95" in slos

    # Gateway telemetry
    gw_resp = client.get("/v1/monitoring/gateway")
    assert gw_resp.status_code == 200
    gw = gw_resp.json()
    assert "p95_latency_ms" in gw
    assert "provider_breakdown" in gw

    # Security telemetry
    sec_resp = client.get("/v1/monitoring/security")
    assert sec_resp.status_code == 200
    sec = sec_resp.json()
    assert "threat_detections_total" in sec
    assert "pii_entities_redacted" in sec

    # Alerts
    alt_resp = client.get("/v1/monitoring/alerts")
    assert alt_resp.status_code == 200
    alt = alt_resp.json()
    assert "firing_alerts" in alt

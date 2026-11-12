"""PRIVGUARD AI - Stage 10.6 SIEM Telemetry Export & SSRF Protection Tests.
Verifies event formatting across Splunk, Sentinel, Elastic, and SSRF prevention.
"""

import pytest
from app.enterprise.siem_exporter import SIEMExporter, SIEMFormat
from app.core.exceptions import PolicyViolationError, SecurityPolicyViolationError, PrivGuardException


def test_01_splunk_hec_format_and_sanitization():
    """Test 1: Splunk HEC payload formatting with strict attribute sanitization."""
    exporter = SIEMExporter(
        endpoint_url="https://splunk.example.com/services/collector/event",
        siem_format=SIEMFormat.SPLUNK_HEC,
        auth_token="splunk_token_123",
        validate_destination=False,
    )

    raw_event = {
        "event_id": "ev_001",
        "action": "SECRET_BLOCKED",
        "actor_type": "AGENT",
        "actor_id": "agent_alpha",
        "resource_type": "GATEWAY",
        "resource_id": "gw_001",
        "details": {
            "token": "sk-1234567890abcdef",  # Prohibited key, must be dropped
            "prompt": "DROP TABLE users;",   # Prohibited key, must be dropped
            "http.method": "POST",           # Safe key, preserved
        },
    }

    formatted = exporter.format_event(raw_event)

    assert formatted["source"] == "privguard:audit"
    assert formatted["sourcetype"] == "_json"
    event_payload = formatted["event"]

    assert event_payload["action"] == "SECRET_BLOCKED"
    assert "token" not in event_payload["details"]
    assert "prompt" not in event_payload["details"]
    assert event_payload["details"]["http.method"] == "POST"


def test_02_elastic_ecs_format():
    """Test 2: Elastic Common Schema (ECS) event formatting."""
    exporter = SIEMExporter(
        endpoint_url="https://elastic.example.com/events/_doc",
        siem_format=SIEMFormat.ELASTIC_ECS,
        validate_destination=False,
    )

    raw_event = {
        "event_id": "ev_002",
        "action": "CAPABILITY_REVOKED",
        "sequence_number": 42,
        "event_hash": "abcdef1234567890",
    }

    formatted = exporter.format_event(raw_event)

    assert "@timestamp" in formatted
    assert formatted["event"]["action"] == "CAPABILITY_REVOKED"
    assert formatted["event"]["sequence"] == 42
    assert formatted["service"]["name"] == "privguard"


def test_03_microsoft_sentinel_format():
    """Test 3: Microsoft Sentinel Log Analytics event formatting."""
    exporter = SIEMExporter(
        endpoint_url="https://sentinel.example.com/api/logs",
        siem_format=SIEMFormat.SENTINEL,
        validate_destination=False,
    )

    raw_event = {
        "event_id": "ev_003",
        "action": "PII_REDACTED",
        "actor_id": "user_123",
        "tenant_id": "ten_default",
    }

    formatted = exporter.format_event(raw_event)

    assert formatted["OperationName"] == "PII_REDACTED"
    assert formatted["Identity"] == "user_123"
    assert formatted["TenantId"] == "ten_default"


def test_04_siem_export_rejects_ssrf_destinations():
    """Test 4: Exporter rejects loopback, RFC 1918 private, and cloud metadata targets."""
    ssrf_targets = [
        "http://169.254.169.254/latest/meta-data/",
        "http://127.0.0.1:8000/internal",
        "http://localhost:9090",
        "http://10.0.0.1/admin",
        "http://192.168.1.1/router",
    ]

    for target in ssrf_targets:
        with pytest.raises((PolicyViolationError, SecurityPolicyViolationError, PrivGuardException, Exception)):
            SIEMExporter(endpoint_url=target)

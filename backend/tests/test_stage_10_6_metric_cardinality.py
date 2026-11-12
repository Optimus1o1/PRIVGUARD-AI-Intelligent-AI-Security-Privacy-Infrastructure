"""PRIVGUARD AI - Stage 10.6 Prometheus Metric Cardinality Tests.
Verifies strictly bounded metric labels and path normalization to prevent memory explosion.
"""

import re
import pytest

from app.observability.metrics import privguard_registry
from app.observability.middleware import normalize_route_path

PROHIBITED_METRIC_LABEL_NAMES = {
    "user_id",
    "tenant_id",
    "agent_id",
    "task_id",
    "memory_id",
    "request_id",
    "trace_id",
    "span_id",
    "email",
    "ip",
    "client_ip",
    "url",
    "full_url",
    "query_params",
    "prompt",
    "content",
    "message",
    "token",
}


def test_01_all_registered_metrics_have_bounded_labels():
    """Test 1: Audits every metric in privguard_registry to ensure zero high-cardinality labels."""
    metrics = list(privguard_registry.collect())
    assert len(metrics) > 0, "privguard_registry must contain registered metrics"

    for metric in metrics:
        # Check metric label names
        for sample in metric.samples:
            label_names = set(sample.labels.keys())
            prohibited_present = label_names.intersection(PROHIBITED_METRIC_LABEL_NAMES)
            assert not prohibited_present, (
                f"Metric '{metric.name}' contains prohibited high-cardinality labels: {prohibited_present}"
            )


def test_02_path_normalization_replaces_dynamic_identifiers():
    """Test 2: Verifies that UUIDs, numeric IDs, and entity prefixes are normalized to {id}."""
    test_cases = [
        ("/v1/agents/agent_01j98z7y6x5w4v3u2t1s/tasks", "/v1/agents/{id}/tasks"),
        ("/v1/memory/mem_999888777666/records", "/v1/memory/{id}/records"),
        ("/v1/keys/123e4567-e89b-12d3-a456-426614174000/rotate", "/v1/keys/{id}/rotate"),
        ("/v1/approvals/appr_123456/decision", "/v1/approvals/{id}/decision"),
        ("/v1/tasks/task_555444/status", "/v1/tasks/{id}/status"),
        ("/v1/organizations/org_999/members/42", "/v1/organizations/{id}/members/{id}"),
        ("/v1/monitoring/canaries/gateway_protection", "/v1/monitoring/canaries/{id}"),
        ("/health/live", "/health/live"),
        ("/metrics", "/metrics"),
    ]

    for raw_path, expected in test_cases:
        normalized = normalize_route_path(raw_path)
        assert normalized == expected, f"Path '{raw_path}' normalized to '{normalized}', expected '{expected}'"


def test_03_status_class_bucketing():
    """Test 3: HTTP status codes must be converted to status class (2xx, 4xx, 5xx)."""
    from app.observability.middleware import get_status_class

    assert get_status_class(200) == "2xx"
    assert get_status_class(201) == "2xx"
    assert get_status_class(400) == "4xx"
    assert get_status_class(401) == "4xx"
    assert get_status_class(403) == "4xx"
    assert get_status_class(404) == "4xx"
    assert get_status_class(500) == "5xx"
    assert get_status_class(503) == "5xx"

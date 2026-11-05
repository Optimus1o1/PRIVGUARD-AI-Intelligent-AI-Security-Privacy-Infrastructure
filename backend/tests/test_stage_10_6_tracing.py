"""PRIVGUARD AI - Stage 10.6 OpenTelemetry Tracing & Context Correlation Tests.
Verifies explicit span lifecycle, safe attribute attachment, and correlation propagation.
"""

import pytest
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.trace import StatusCode

from app.observability.correlation import (
    generate_request_id,
    get_current_request_id,
    set_current_request_id,
    reset_current_request_id,
    get_current_trace_id,
    get_current_span_id,
)
from app.observability.tracing import init_tracing, trace_span, get_tracer
from app.observability.attributes import SemanticAttributes


@pytest.fixture
def memory_exporter():
    """Initializes OpenTelemetry with an in-memory exporter for assertions."""
    exporter = InMemorySpanExporter()
    init_tracing(exporter=exporter)
    return exporter


def test_01_request_id_generation_and_context_propagation():
    """Test 1: Generates pg_req_ correlation IDs and maintains ContextVar propagation."""
    req_id = generate_request_id()
    assert req_id.startswith("pg_req_")
    assert len(req_id) == 23

    token = set_current_request_id(req_id)
    assert get_current_request_id() == req_id
    reset_current_request_id(token)


def test_02_trace_span_creates_spans_with_safe_attributes(memory_exporter):
    """Test 2: trace_span creates valid spans and strips prohibited attributes."""
    memory_exporter.clear()

    with trace_span(
        "privguard.test_operation",
        attributes={
            SemanticAttributes.HTTP_METHOD: "POST",
            SemanticAttributes.PRIVGUARD_OPERATION: "test_op",
            "prompt": "DROP TABLE users;",  # Must be stripped
            "api_key": "sk-1234567890abcdef",  # Must be stripped
        },
    ) as span:
        span.set_attribute(SemanticAttributes.PRIVGUARD_STATUS, "success")

    spans = memory_exporter.get_finished_spans()
    assert len(spans) == 1
    finished = spans[0]

    assert finished.name == "privguard.test_operation"
    assert finished.status.status_code == StatusCode.OK

    attrs = finished.attributes
    assert attrs[SemanticAttributes.HTTP_METHOD] == "POST"
    assert attrs[SemanticAttributes.PRIVGUARD_OPERATION] == "test_op"
    assert attrs[SemanticAttributes.PRIVGUARD_STATUS] == "success"

    # Strict privacy invariant: unapproved keys must NOT exist on span
    assert "prompt" not in attrs
    assert "api_key" not in attrs


def test_03_trace_span_records_exception_cleanly(memory_exporter):
    """Test 3: Exceptions in trace_span mark span as ERROR without leaking credentials."""
    memory_exporter.clear()

    with pytest.raises(ValueError):
        with trace_span("privguard.failing_operation") as span:
            raise ValueError("Database connection failed with password=SecretPassword123")

    spans = memory_exporter.get_finished_spans()
    assert len(spans) == 1
    finished = spans[0]

    assert finished.status.status_code == StatusCode.ERROR
    # Error description should record exception type name, not raw message with passwords
    assert finished.status.description == "ValueError"

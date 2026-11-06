"""PRIVGUARD AI - Distributed Request Correlation & Context Propagation.
Manages ContextVars for Request IDs, Trace IDs, and Span IDs across async task boundaries.
"""

import contextvars
import secrets
from typing import Optional
from opentelemetry import trace

# ContextVar for async-local request correlation
_request_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("current_request_id", default=None)


def generate_request_id() -> str:
    """Generates a high-entropy, cryptographically safe request correlation ID."""
    return f"pg_req_{secrets.token_hex(8)}"


def get_current_request_id() -> str:
    """Returns the active request correlation ID or generates a fallback ID."""
    req_id = _request_id_var.get()
    return req_id or "pg_req_standalone"


def set_current_request_id(request_id: str) -> contextvars.Token:
    """Sets the active request correlation ID for the current execution context."""
    return _request_id_var.set(request_id)


def reset_current_request_id(token: contextvars.Token) -> None:
    """Resets the request ID ContextVar."""
    _request_id_var.reset(token)


def get_current_trace_id() -> Optional[str]:
    """Retrieves the active 32-character hexadecimal OpenTelemetry Trace ID."""
    current_span = trace.get_current_span()
    if current_span and current_span.get_span_context().is_valid:
        return format(current_span.get_span_context().trace_id, "032x")
    return None


def get_current_span_id() -> Optional[str]:
    """Retrieves the active 16-character hexadecimal OpenTelemetry Span ID."""
    current_span = trace.get_current_span()
    if current_span and current_span.get_span_context().is_valid:
        return format(current_span.get_span_context().span_id, "016x")
    return None


def set_correlation_context(request_id: str) -> contextvars.Token:
    """Convenience alias for setting correlation context."""
    return set_current_request_id(request_id)


def clear_correlation_context() -> None:
    """Clears the current correlation context."""
    _request_id_var.set(None)

"""PRIVGUARD AI - Observability & Request Correlation HTTP Middleware.
Extracts trace context, manages trusted Request IDs, records request metrics,
and enforces path normalization for bounded metric cardinality.
"""

import re
import time
from typing import Callable
from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware
from opentelemetry import trace
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from opentelemetry.trace import StatusCode

from app.observability.correlation import (
    generate_request_id,
    set_current_request_id,
    reset_current_request_id,
    get_current_trace_id,
    get_current_span_id,
)
from app.observability.metrics import (
    HTTP_REQUESTS_TOTAL,
    HTTP_REQUEST_DURATION_SECONDS,
    HTTP_REQUESTS_IN_FLIGHT,
    HTTP_ERRORS_TOTAL,
)
from app.observability.tracing import get_tracer

# Regex patterns for identifying dynamic resource IDs in URL segments
UUID_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
PREFIXED_ID_REGEX = re.compile(
    r"^(?:mem|agent|task|prop|mperm|wsm|res|org|inv|mcpt|mcpr|sec|job|pg_req|pg_cap|hmac|app|appr)_[0-9a-zA-Z]+$"
)

CANARY_NAMES = {
    "gateway_protection",
    "secret_blocking",
    "agent_authorization",
    "capability_revocation",
    "prompt_injection",
    "memory_isolation",
    "mcp_security",
    "kms_availability",
}


def get_status_class(status_code: int) -> str:
    """Converts numeric HTTP status code to status class bucket (2xx, 4xx, 5xx)."""
    return f"{status_code // 100}xx"


def normalize_route_path(path: str) -> str:
    """
    Normalizes path segments to prevent Prometheus label cardinality explosion.
    Replaces dynamic UUIDs, hexadecimal keys, and resource IDs with '{id}'.
    """
    if not path or path == "/":
        return "/"

    segments = path.strip("/").split("/")
    normalized = []

    for i, seg in enumerate(segments):
        prev_seg = segments[i - 1] if i > 0 else ""
        if (
            UUID_REGEX.match(seg)
            or PREFIXED_ID_REGEX.match(seg)
            or seg.isdigit()
            or seg in CANARY_NAMES
            or (prev_seg == "canaries" and seg != "run")
        ):
            normalized.append("{id}")
        else:
            normalized.append(seg)

    return "/" + "/".join(normalized)


class ObservabilityMiddleware(BaseHTTPMiddleware):
    """
    FastAPI HTTP Middleware for:
    1. Request ID generation and async-local ContextVar binding.
    2. W3C distributed trace context propagation (traceparent).
    3. Root span lifecycle management and status code classification.
    4. Prometheus HTTP duration and throughput metric observation.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # 1. Establish Request Correlation ID
        incoming_req_id = request.headers.get("X-Request-ID")
        req_id = incoming_req_id.strip() if incoming_req_id else generate_request_id()
        token = set_current_request_id(req_id)

        # 2. Extract W3C Trace Context from incoming headers
        carrier = dict(request.headers)
        extracted_context = TraceContextTextMapPropagator().extract(carrier=carrier)

        # 3. Route normalization & metrics setup
        raw_path = request.url.path
        route = normalize_route_path(raw_path)
        method = request.method.upper()

        HTTP_REQUESTS_IN_FLIGHT.labels(method=method).inc()
        start_time = time.perf_counter()

        tracer = get_tracer("privguard.http")
        span_name = f"HTTP {method} {route}"

        try:
            with tracer.start_as_current_span(
                span_name,
                context=extracted_context,
                attributes={
                    "http.method": method,
                    "http.route": route,
                    "privguard.request_id": req_id,
                },
            ) as span:
                response = await call_next(request)

                duration = time.perf_counter() - start_time
                status_code = response.status_code
                status_class = f"{status_code // 100}xx"

                span.set_attribute("http.status_code", status_code)
                span.set_attribute("http.status_class", status_class)

                if status_code >= 500:
                    span.set_status(StatusCode.ERROR, description=f"HTTP_{status_code}")
                    HTTP_ERRORS_TOTAL.labels(method=method, route=route, error_type=f"HTTP_{status_code}").inc()
                else:
                    span.set_status(StatusCode.OK)

                # Record Prometheus metrics
                HTTP_REQUESTS_TOTAL.labels(method=method, route=route, status_class=status_class).inc()
                HTTP_REQUEST_DURATION_SECONDS.labels(method=method, route=route, status_class=status_class).observe(
                    duration
                )

                # Propagate correlation headers back to client
                response.headers["X-Request-ID"] = req_id
                trace_id = get_current_trace_id()
                if trace_id:
                    response.headers["X-Trace-ID"] = trace_id

                return response

        except Exception as exc:
            duration = time.perf_counter() - start_time
            HTTP_REQUESTS_TOTAL.labels(method=method, route=route, status_class="5xx").inc()
            HTTP_REQUEST_DURATION_SECONDS.labels(method=method, route=route, status_class="5xx").observe(duration)
            HTTP_ERRORS_TOTAL.labels(method=method, route=route, error_type=type(exc).__name__).inc()
            raise

        finally:
            HTTP_REQUESTS_IN_FLIGHT.labels(method=method).dec()
            reset_current_request_id(token)

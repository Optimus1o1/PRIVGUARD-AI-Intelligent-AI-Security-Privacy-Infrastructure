"""PRIVGUARD AI - Distributed Tracing Engine via OpenTelemetry.
Provides explicit span lifecycle helpers, safe attribute attachment, and context propagation.
"""

from contextlib import contextmanager
from typing import Any, Dict, Generator, Optional
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, SimpleSpanProcessor, SpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.trace import Span, StatusCode, Tracer

from app.core.config import settings
from app.observability.correlation import get_current_request_id
from app.observability.sanitization import sanitize_attributes

_is_initialized: bool = False
_provider: Optional[TracerProvider] = None


def init_tracing(exporter: Optional[SpanExporter] = None) -> TracerProvider:
    """Initializes the OpenTelemetry TracerProvider with appropriate resources and exporters."""
    global _is_initialized, _provider

    if _is_initialized and _provider:
        if exporter:
            _provider.add_span_processor(SimpleSpanProcessor(exporter))
        return _provider

    resource = Resource.create(
        {
            "service.name": settings.PROJECT_NAME,
            "service.version": settings.VERSION,
            "deployment.environment": settings.ENVIRONMENT,
        }
    )

    _provider = TracerProvider(resource=resource)

    if exporter:
        # SimpleSpanProcessor for deterministic test execution or custom exporter
        _provider.add_span_processor(SimpleSpanProcessor(exporter))
    else:
        # Check if an OTLP Collector endpoint is configured
        otlp_endpoint = getattr(settings, "OTEL_EXPORTER_OTLP_ENDPOINT", None)
        if otlp_endpoint:
            try:
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

                otlp_exporter = OTLPSpanExporter(endpoint=f"{otlp_endpoint.rstrip('/')}/v1/traces")
                _provider.add_span_processor(BatchSpanProcessor(otlp_exporter))
            except Exception:
                pass  # Fallback to in-process trace provider without crashing

    trace.set_tracer_provider(_provider)
    _is_initialized = True
    return _provider


def get_tracer(name: str = "privguard.core") -> Tracer:
    """Returns an OpenTelemetry Tracer instance."""
    if not _is_initialized:
        init_tracing()
    return trace.get_tracer(name, settings.VERSION)


@contextmanager
def trace_span(
    name: str,
    attributes: Optional[Dict[str, Any]] = None,
    tracer_name: str = "privguard.core",
) -> Generator[Span, None, None]:
    """
    Context manager creating an explicitly managed OpenTelemetry span.
    Guarantees:
    - Automatically attaches sanitized attributes.
    - Binds current request_id.
    - Sanitizes error messages so credentials/tokens do not leak in exception events.
    """
    tracer = get_tracer(tracer_name)
    safe_attrs = sanitize_attributes(attributes or {})
    safe_attrs["privguard.request_id"] = get_current_request_id()

    span = tracer.start_span(name, attributes=safe_attrs)
    with trace.use_span(span, end_on_exit=True, record_exception=False, set_status_on_exception=False):
        try:
            yield span
            if span.is_recording():
                span.set_status(StatusCode.OK)
        except Exception as exc:
            if span.is_recording():
                span.set_status(StatusCode.ERROR, description=type(exc).__name__)
                # Record sanitized exception event without raw message secrets
                span.add_event(
                    "exception",
                    attributes={"exception.type": type(exc).__name__},
                )
            raise


init_tracer_provider = init_tracing

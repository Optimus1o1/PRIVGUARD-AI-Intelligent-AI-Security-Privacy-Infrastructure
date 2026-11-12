"""PRIVGUARD AI - Observability Engine Setup & Lifecycle Hook.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import logging
from typing import Optional
from fastapi import FastAPI

from app.core.config import settings
from app.observability.logging import configure_structured_logging
from app.observability.middleware import ObservabilityMiddleware
from app.observability.tracing import get_tracer

logger = logging.getLogger("privguard.observability.setup")


def init_observability(app: FastAPI) -> None:
    """
    Initializes OpenTelemetry, Prometheus metrics registry, structured logging,
    and mounts ObservabilityMiddleware to the FastAPI application.
    """
    # 1. Configure structured JSON logging with sensitive data redaction
    log_level = logging.DEBUG if settings.DEBUG else logging.INFO
    configure_structured_logging(level=log_level)
    logger.info("Structured JSON logging initialized with redaction filter")

    # 2. Initialize OpenTelemetry TracerProvider
    tracer = get_tracer("privguard.app")
    logger.info("OpenTelemetry tracer provider initialized for service=privguard")

    # 3. Mount ObservabilityMiddleware
    # Place early in middleware chain so every request has correlation context and duration tracking
    app.add_middleware(ObservabilityMiddleware)
    logger.info("ObservabilityMiddleware mounted successfully")

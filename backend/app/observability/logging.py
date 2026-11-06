"""PRIVGUARD AI - Structured Logging with Sensitive Data Redaction.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from app.core.config import settings
from app.observability.correlation import (
    get_current_request_id,
    get_current_trace_id,
    get_current_span_id,
)
from app.observability.sanitization import (
    sanitize_string_value,
    sanitize_attributes,
    TOKEN_PATTERNS,
)


class RedactionFilter(logging.Filter):
    """Logging filter that redacts credentials and secrets from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = sanitize_string_value(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {
                    k: (sanitize_string_value(v) if isinstance(v, str) else v) for k, v in record.args.items()
                }
            elif isinstance(record.args, tuple):
                record.args = tuple(sanitize_string_value(arg) if isinstance(arg, str) else arg for arg in record.args)
        return True


class StructuredJsonFormatter(logging.Formatter):
    """JSON log formatter compliant with Loki and enterprise log aggregators."""

    def format(self, record: logging.LogRecord) -> str:
        # Format message string safely
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)

        # Redact message
        message = sanitize_string_value(message)

        log_data: Dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": message,
            "service": "privguard",
            "environment": getattr(settings, "ENVIRONMENT", "development"),
        }

        # Inject correlation identifiers if present
        request_id = get_current_request_id()
        if request_id:
            log_data["request_id"] = request_id

        trace_id = get_current_trace_id()
        if trace_id:
            log_data["trace_id"] = trace_id

        span_id = get_current_span_id()
        if span_id:
            log_data["span_id"] = span_id

        # Exception formatting
        if record.exc_info and record.exc_info[0]:
            log_data["exception"] = {
                "type": record.exc_info[0].__name__,
                "message": sanitize_string_value(str(record.exc_info[1])),
            }

        # Include sanitized extra attributes if present
        extras: Dict[str, Any] = {}
        for key, value in record.__dict__.items():
            if key not in {
                "name",
                "msg",
                "args",
                "levelname",
                "levelno",
                "pathname",
                "filename",
                "module",
                "exc_info",
                "exc_text",
                "stack_info",
                "lineno",
                "funcName",
                "created",
                "msecs",
                "relativeCreated",
                "thread",
                "threadName",
                "processName",
                "process",
                "message",
            }:
                if isinstance(value, (str, int, float, bool)):
                    extras[key] = sanitize_string_value(str(value)) if isinstance(value, str) else value

        if extras:
            safe_extras = sanitize_attributes(extras)
            if safe_extras:
                log_data["extra"] = safe_extras

        return json.dumps(log_data)


def configure_structured_logging(level: int = logging.INFO) -> None:
    """Configures structured JSON logging with redaction filter on privguard loggers."""
    root_logger = logging.getLogger()
    privguard_logger = logging.getLogger("privguard")
    privguard_logger.setLevel(level)

    handler = logging.StreamHandler()
    handler.setFormatter(StructuredJsonFormatter())
    handler.addFilter(RedactionFilter())

    # Avoid duplicate handlers if re-configured
    if not any(
        isinstance(h, logging.StreamHandler) and isinstance(h.formatter, StructuredJsonFormatter)
        for h in privguard_logger.handlers
    ):
        privguard_logger.addHandler(handler)
        privguard_logger.propagate = False

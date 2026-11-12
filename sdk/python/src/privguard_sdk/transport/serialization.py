"""Request and response serialization utilities for PRIVGUARD SDK.

Moon Sanctum Labs - Decode. Build. Evolve.
"""

import json
from typing import Any

from pydantic import BaseModel


def serialize_payload(payload: Any) -> dict[str, Any] | None:
    """Converts a Pydantic model, dictionary, or primitive to a JSON-serializable dict."""
    if payload is None:
        return None
    if isinstance(payload, BaseModel):
        return payload.model_dump(exclude_none=True)
    if isinstance(payload, dict):
        return {k: serialize_payload(v) for k, v in payload.items() if v is not None}
    if isinstance(payload, list):
        return [serialize_payload(i) for i in payload]
    return payload


def to_json_bytes(payload: Any) -> bytes:
    """Encodes a payload to compact UTF-8 JSON bytes."""
    serialized = serialize_payload(payload)
    return json.dumps(serialized, separators=(",", ":")).encode("utf-8")

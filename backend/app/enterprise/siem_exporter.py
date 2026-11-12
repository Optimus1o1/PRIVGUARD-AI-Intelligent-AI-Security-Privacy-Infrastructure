"""PRIVGUARD AI - Enterprise SIEM Telemetry & Security Event Exporter.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import json
import logging
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import httpx

from app.core.config import settings
from app.core.exceptions import PrivGuardException, SecurityPolicyViolationError
from app.mcp.ssrf import destination_validator
from app.observability.sanitization import sanitize_attributes, sanitize_string_value

logger = logging.getLogger("privguard.enterprise.siem")


class SIEMFormat(str, Enum):
    SPLUNK_HEC = "splunk_hec"
    SENTINEL = "microsoft_sentinel"
    ELASTIC_ECS = "elastic_ecs"
    GENERIC_WEBHOOK = "generic_webhook"


class SIEMExporter:
    """Exports sanitized enterprise audit and security telemetry to SIEM platforms."""

    def __init__(
        self,
        endpoint_url: str,
        siem_format: SIEMFormat = SIEMFormat.GENERIC_WEBHOOK,
        auth_token: Optional[str] = None,
        validate_destination: bool = True,
    ) -> None:
        if validate_destination:
            # Validate endpoint against SSRF
            norm_url, _ = destination_validator.validate_url(endpoint_url)
            self.endpoint_url = norm_url
        else:
            self.endpoint_url = endpoint_url
        self.siem_format = siem_format
        self.auth_token = auth_token

    def format_event(self, event_data: Dict[str, Any]) -> Dict[str, Any]:
        """Formats audit event according to target SIEM schema, ensuring strict sanitization."""
        # Sanitize event details
        sanitized_details = sanitize_attributes(event_data.get("details", {}))
        ts_iso = event_data.get("timestamp") or datetime.now(timezone.utc).isoformat()

        base_payload = {
            "event_id": event_data.get("event_id", ""),
            "timestamp": ts_iso,
            "tenant_id": event_data.get("tenant_id", ""),
            "action": event_data.get("action", ""),
            "actor_type": event_data.get("actor_type", ""),
            "actor_id": event_data.get("actor_id", ""),
            "resource_type": event_data.get("resource_type", ""),
            "resource_id": event_data.get("resource_id", ""),
            "event_hash": event_data.get("event_hash", ""),
            "sequence_number": event_data.get("sequence_number", 0),
            "details": sanitized_details,
            "service": "privguard",
            "environment": getattr(settings, "ENVIRONMENT", "development"),
        }

        if self.siem_format == SIEMFormat.SPLUNK_HEC:
            return {
                "time": datetime.fromisoformat(ts_iso).timestamp() if "T" in ts_iso else None,
                "host": "privguard-gateway",
                "source": "privguard:audit",
                "sourcetype": "_json",
                "event": base_payload,
            }

        elif self.siem_format == SIEMFormat.ELASTIC_ECS:
            return {
                "@timestamp": ts_iso,
                "event": {
                    "kind": "event",
                    "category": "security",
                    "type": "access",
                    "action": base_payload["action"],
                    "sequence": base_payload["sequence_number"],
                    "hash": base_payload["event_hash"],
                },
                "service": {"name": "privguard"},
                "privguard": base_payload,
            }

        elif self.siem_format == SIEMFormat.SENTINEL:
            return {
                "TimeGenerated": ts_iso,
                "OperationName": base_payload["action"],
                "Identity": base_payload["actor_id"],
                "IdentityType": base_payload["actor_type"],
                "TargetResource": base_payload["resource_id"],
                "TargetResourceType": base_payload["resource_type"],
                "TenantId": base_payload["tenant_id"],
                "SequenceNumber": base_payload["sequence_number"],
                "AuditHash": base_payload["event_hash"],
                "Properties": sanitized_details,
            }

        # Default Generic Webhook
        return base_payload

    async def export_event(self, event_data: Dict[str, Any]) -> bool:
        """Transmits a single sanitized event to the external SIEM endpoint."""
        payload = self.format_event(event_data)
        headers = {"Content-Type": "application/json"}
        if self.auth_token:
            if self.siem_format == SIEMFormat.SPLUNK_HEC:
                headers["Authorization"] = f"Splunk {self.auth_token}"
            else:
                headers["Authorization"] = f"Bearer {self.auth_token}"

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(self.endpoint_url, json=payload, headers=headers)
                if resp.status_code >= 400:
                    logger.warning(
                        "SIEM export failed with status %d at destination %s",
                        resp.status_code,
                        self.endpoint_url,
                    )
                    return False
                return True
        except Exception as exc:
            logger.error("SIEM export transmission error: %s", type(exc).__name__)
            return False

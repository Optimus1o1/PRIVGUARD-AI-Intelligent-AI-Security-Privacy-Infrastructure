"""Upstream Gateway Coordinator.
Coordinates request inspection, provider selection, response inspection, and audit logging.
"""

import time
import uuid
from typing import Any, AsyncIterator, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.exceptions import (
    PrivGuardException,
    ResponseSecurityViolationError,
    SecretDetectedError,
    UpstreamProviderError,
)
from app.database.models import Application
from app.gateway.response_inspector import response_inspector
from app.gateway.streaming import secure_stream_handler
from app.monitoring.audit import audit_logger
from app.privacy.pipeline import inspection_pipeline
from app.providers.registry import provider_registry


class UpstreamCoordinator:
    """Manages the full lifecycle of upstream LLM requests with bidirectional security."""

    def __init__(self):
        self.pipeline = inspection_pipeline
        self.provider_registry = provider_registry
        self.response_inspector = response_inspector
        self.stream_handler = secure_stream_handler

    async def execute_completion(
        self,
        payload: Dict[str, Any],
        current_app: Application,
        db: AsyncSession,
        request_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Executes a non-streaming chat completion with request & response security inspection."""
        req_id = request_id or f"pg_req_{uuid.uuid4().hex[:12]}"
        start_time = time.perf_counter()

        raw_messages = payload.get("messages", [])

        # 1. Ingress Request Inspection
        sanitized_messages, verdict, redaction_mapping = self.pipeline.inspect_messages(raw_messages)

        # 2. Hard Fail-Closed on Request Secrets
        if verdict.is_blocked:
            await audit_logger.log_event(
                db=db,
                request_id=req_id,
                app_id=current_app.id,
                event_type="SECRET_BLOCKED",
                action_taken="BLOCK",
                risk_level=verdict.risk_level.value,
                data_category=verdict.category.value,
                entity_counts=verdict.entity_counts,
                content_fingerprint=verdict.content_fingerprint,
                status="BLOCKED",
            )
            raise SecretDetectedError(
                secret_type=verdict.detected_secrets[0]["type"] if verdict.detected_secrets else "UNKNOWN",
                match_preview=verdict.detected_secrets[0]["preview"] if verdict.detected_secrets else "****",
                details={"request_id": req_id},
            )

        # 3. Audit Request Ingress
        event_type = "PII_REDACTED" if verdict.action.value == "REDACT" else "REQUEST_INSPECTED"
        await audit_logger.log_event(
            db=db,
            request_id=req_id,
            app_id=current_app.id,
            event_type=event_type,
            action_taken=verdict.action.value,
            risk_level=verdict.risk_level.value,
            data_category=verdict.category.value,
            entity_counts=verdict.entity_counts,
            content_fingerprint=verdict.content_fingerprint,
            status="SUCCESS",
        )

        # 4. Resolve Server-Side Provider (SSRF Prevention)
        model = payload.get("model", "default")
        provider = self.provider_registry.get_provider(model)

        upstream_payload = dict(payload)
        upstream_payload["messages"] = sanitized_messages

        # 5. Upstream Provider Execution
        try:
            provider_res = await provider.complete(upstream_payload)
        except PrivGuardException:
            raise
        except Exception as e:
            raise UpstreamProviderError(
                message="Upstream model provider encountered an internal communication error.",
                status_code=502,
                details={"error_type": type(e).__name__},
            )

        # 6. Response Inspection & Placeholder Restoration
        try:
            inspected = self.response_inspector.inspect_and_restore(
                raw_model_content=provider_res.content,
                request_mapping=redaction_mapping,
            )
        except ResponseSecurityViolationError as sec_err:
            # Audit Model Output Violation
            await audit_logger.log_event(
                db=db,
                request_id=req_id,
                app_id=current_app.id,
                event_type="RESPONSE_SECRET_BLOCKED",
                action_taken="BLOCK",
                risk_level="CRITICAL",
                data_category="CRITICAL",
                entity_counts={"MODEL_LEAKED_SECRET": 1},
                content_fingerprint=verdict.content_fingerprint,
                status="BLOCKED",
            )
            raise sec_err

        elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)

        # 7. Audit Safe Response Delivery
        await audit_logger.log_event(
            db=db,
            request_id=req_id,
            app_id=current_app.id,
            event_type="RESPONSE_DELIVERED",
            action_taken="ALLOW",
            risk_level="LOW",
            data_category="PUBLIC",
            entity_counts={"RESTORED_TOKENS": inspected.restoration_count},
            content_fingerprint=inspected.content_fingerprint,
            status="SUCCESS",
        )

        return {
            "id": req_id,
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": inspected.restored_content,
                    },
                    "finish_reason": provider_res.finish_reason or "stop",
                }
            ],
            "usage": provider_res.usage,
            "privguard_meta": {
                "request_id": req_id,
                "security_action": verdict.action.value,
                "data_category": verdict.category.value,
                "risk_level": verdict.risk_level.value,
                "entities_redacted": verdict.entity_counts,
                "tokens_restored": inspected.restoration_count,
                "latency_ms": elapsed_ms,
            },
        }

    async def execute_stream(
        self,
        payload: Dict[str, Any],
        current_app: Application,
        db: AsyncSession,
        request_id: Optional[str] = None,
    ) -> AsyncIterator[str]:
        """Executes a streaming chat completion with buffer-before-stream security inspection."""
        req_id = request_id or f"pg_req_{uuid.uuid4().hex[:12]}"

        raw_messages = payload.get("messages", [])

        # 1. Ingress Request Inspection
        sanitized_messages, verdict, redaction_mapping = self.pipeline.inspect_messages(raw_messages)

        # 2. Hard Fail-Closed on Request Secrets
        if verdict.is_blocked:
            await audit_logger.log_event(
                db=db,
                request_id=req_id,
                app_id=current_app.id,
                event_type="SECRET_BLOCKED",
                action_taken="BLOCK",
                risk_level=verdict.risk_level.value,
                data_category=verdict.category.value,
                entity_counts=verdict.entity_counts,
                content_fingerprint=verdict.content_fingerprint,
                status="BLOCKED",
            )
            raise SecretDetectedError(
                secret_type=verdict.detected_secrets[0]["type"] if verdict.detected_secrets else "UNKNOWN",
                match_preview=verdict.detected_secrets[0]["preview"] if verdict.detected_secrets else "****",
                details={"request_id": req_id},
            )

        # 3. Audit Request Ingress
        event_type = "PII_REDACTED" if verdict.action.value == "REDACT" else "REQUEST_INSPECTED"
        await audit_logger.log_event(
            db=db,
            request_id=req_id,
            app_id=current_app.id,
            event_type=event_type,
            action_taken=verdict.action.value,
            risk_level=verdict.risk_level.value,
            data_category=verdict.category.value,
            entity_counts=verdict.entity_counts,
            content_fingerprint=verdict.content_fingerprint,
            status="SUCCESS",
        )

        # 4. Resolve Provider
        model = payload.get("model", "default")
        provider = self.provider_registry.get_provider(model)

        upstream_payload = dict(payload)
        upstream_payload["messages"] = sanitized_messages

        # 5. Upstream Stream Generator
        raw_stream = provider.stream(upstream_payload)

        # 6. Process through Secure Buffered Stream Handler
        # Note: If model output contains secret, it raises ResponseSecurityViolationError during buffer phase!
        return self.stream_handler.process_stream(
            upstream_stream=raw_stream,
            request_mapping=redaction_mapping,
            model=model,
            request_id=req_id,
        )


# Shared upstream coordinator instance
upstream_coordinator = UpstreamCoordinator()

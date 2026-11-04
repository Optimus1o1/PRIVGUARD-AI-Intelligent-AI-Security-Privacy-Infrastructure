"""Unified Request Inspection Pipeline.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field
from app.core.exceptions import SecretDetectedError
from app.core.security import content_hash
from app.privacy.classifier import DataCategory, RiskLevel, classify_entities
from app.privacy.pii_detector import PIIMatch, pii_detector
from app.privacy.redactor import RedactionResult, redactor
from app.privacy.secret_scanner import SecretMatch, secret_scanner
from app.policies.engine import policy_engine
from app.policies.schemas import PolicyAction, PolicyDecision


class InspectionVerdict(BaseModel):
    """Full outcome of inspecting a payload."""
    original_text: str = Field(exclude=True)  # Never serialized in audit logs!
    sanitized_text: str
    action: PolicyAction
    category: DataCategory
    risk_level: RiskLevel
    is_blocked: bool
    blocking_reason: Optional[str] = None
    detected_secrets: List[Dict[str, Any]] = Field(default_factory=list)
    detected_pii: List[Dict[str, Any]] = Field(default_factory=list)
    entity_counts: Dict[str, int] = Field(default_factory=dict)
    redaction_mapping: Dict[str, str] = Field(default_factory=dict)
    content_fingerprint: str


class InspectionPipeline:
    """Orchestrates secret scanning, PII detection, classification, and policy enforcement."""

    def __init__(self):
        self.secret_scanner = secret_scanner
        self.pii_detector = pii_detector
        self.redactor = redactor
        self.policy_engine = policy_engine

    def inspect_text(self, text: str) -> InspectionVerdict:
        """
        Inspects raw text through the full defense-in-depth pipeline.
        Enforces fail-closed: secrets trigger immediate hard block.
        """
        fingerprint = content_hash(text)

        # 1. First Defense: Secret Scanning (Hard fail-closed)
        secret_matches = self.secret_scanner.scan(text)
        if secret_matches:
            first_secret = secret_matches[0]
            secrets_info = [
                {
                    "type": s.secret_type,
                    "preview": s.preview,
                    "start": s.start,
                    "end": s.end,
                    "entropy": s.entropy,
                }
                for s in secret_matches
            ]
            counts = {"SECRET": len(secret_matches)}
            for s in secret_matches:
                counts[s.secret_type] = counts.get(s.secret_type, 0) + 1

            return InspectionVerdict(
                original_text=text,
                sanitized_text="",
                action=PolicyAction.BLOCK,
                category=DataCategory.CRITICAL,
                risk_level=RiskLevel.CRITICAL,
                is_blocked=True,
                blocking_reason=f"Sensitive secret detected: {first_secret.secret_type} ({first_secret.preview})",
                detected_secrets=secrets_info,
                detected_pii=[],
                entity_counts=counts,
                redaction_mapping={},
                content_fingerprint=fingerprint,
            )

        # 2. Second Defense: PII Detection
        pii_matches = self.pii_detector.detect(text)
        detected_entity_names = [m.entity_type for m in pii_matches]

        # 3. Third Defense: Data Classification
        classification = classify_entities(detected_entity_names)

        # 4. Fourth Defense: Policy Decision
        decision = self.policy_engine.evaluate(
            category=classification.overall_category.value,
            has_secrets=False,
            detected_entities=detected_entity_names,
        )

        # 5. Action Execution (ALLOW / REDACT / BLOCK)
        if decision.action == PolicyAction.BLOCK:
            return InspectionVerdict(
                original_text=text,
                sanitized_text="",
                action=PolicyAction.BLOCK,
                category=classification.overall_category,
                risk_level=classification.highest_risk,
                is_blocked=True,
                blocking_reason=decision.reason,
                detected_secrets=[],
                detected_pii=[
                    {"type": m.entity_type, "start": m.start, "end": m.end}
                    for m in pii_matches
                ],
                entity_counts=classification.entity_counts,
                redaction_mapping={},
                content_fingerprint=fingerprint,
            )

        if decision.action == PolicyAction.REDACT and pii_matches:
            # Build spans for redactor: (type, start, end, raw_value)
            spans = [(m.entity_type, m.start, m.end, m.text) for m in pii_matches]
            redaction_res = self.redactor.redact(text, spans)

            return InspectionVerdict(
                original_text=text,
                sanitized_text=redaction_res.redacted_text,
                action=PolicyAction.REDACT,
                category=classification.overall_category,
                risk_level=classification.highest_risk,
                is_blocked=False,
                detected_secrets=[],
                detected_pii=[
                    {"type": m.entity_type, "start": m.start, "end": m.end}
                    for m in pii_matches
                ],
                entity_counts=redaction_res.entity_counts,
                redaction_mapping=redaction_res.mapping,
                content_fingerprint=fingerprint,
            )

        # Default: ALLOW
        return InspectionVerdict(
            original_text=text,
            sanitized_text=text,
            action=PolicyAction.ALLOW,
            category=classification.overall_category,
            risk_level=classification.highest_risk,
            is_blocked=False,
            detected_secrets=[],
            detected_pii=[],
            entity_counts=classification.entity_counts,
            redaction_mapping={},
            content_fingerprint=fingerprint,
        )

    def inspect_messages(
        self, messages: List[Dict[str, Any]]
    ) -> tuple[List[Dict[str, Any]], InspectionVerdict, Dict[str, str]]:
        """
        Inspects an entire array of chat completion messages.
        Returns (sanitized_messages, overall_verdict, aggregated_mapping).
        If any message triggers BLOCK, halts and returns blocked verdict immediately.
        """
        sanitized_messages: List[Dict[str, Any]] = []
        aggregated_mapping: Dict[str, str] = {}
        combined_entity_counts: Dict[str, int] = {}
        highest_risk = RiskLevel.LOW
        worst_category = DataCategory.PUBLIC
        action = PolicyAction.ALLOW

        for msg in messages:
            content = msg.get("content")
            if not isinstance(content, str):
                sanitized_messages.append(msg)
                continue

            verdict = self.inspect_text(content)

            # Fail immediately on first blocked message
            if verdict.is_blocked:
                return [], verdict, {}

            if verdict.action == PolicyAction.REDACT:
                action = PolicyAction.REDACT

            if verdict.risk_level.value > highest_risk.value:
                highest_risk = verdict.risk_level

            # Update mapping and counts
            aggregated_mapping.update(verdict.redaction_mapping)
            for k, v in verdict.entity_counts.items():
                combined_entity_counts[k] = combined_entity_counts.get(k, 0) + v

            sanitized_msg = dict(msg)
            sanitized_msg["content"] = verdict.sanitized_text
            sanitized_messages.append(sanitized_msg)

        overall_verdict = InspectionVerdict(
            original_text="[MULTI_MESSAGE_PAYLOAD]",
            sanitized_text="[SANITIZED_MULTI_MESSAGE]",
            action=action,
            category=worst_category,
            risk_level=highest_risk,
            is_blocked=False,
            entity_counts=combined_entity_counts,
            redaction_mapping=aggregated_mapping,
            content_fingerprint=content_hash(str(messages)),
        )

        return sanitized_messages, overall_verdict, aggregated_mapping


# Shared pipeline instance
inspection_pipeline = InspectionPipeline()


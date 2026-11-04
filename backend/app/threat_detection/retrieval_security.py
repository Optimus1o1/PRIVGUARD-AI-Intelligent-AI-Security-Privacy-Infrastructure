"""Retrieval & Vector Security Validator for RAG pipelines."""

import hashlib
from typing import List, Tuple
from app.threat_detection.schemas import (
    RetrievedDocumentChunk,
    ThreatAction,
    ThreatAssessment,
    ThreatSeverity,
    ThreatSignal,
    ThreatType,
)
from app.threat_detection.injection_detector import InjectionDetector


class RetrievalSecurityValidator:
    """Enforces tenant boundaries, cryptographic integrity, and poisoning defense on retrieved chunks."""

    def __init__(self, injection_detector: InjectionDetector) -> None:
        self.injection_detector = injection_detector

    def validate_chunk(
        self,
        chunk: RetrievedDocumentChunk,
        requesting_app_id: str,
    ) -> Tuple[bool, ThreatAssessment]:
        """Validates a retrieved knowledge base chunk prior to context injection."""
        signals: List[ThreatSignal] = []

        # 1. Enforce tenant boundary isolation
        if chunk.app_id != requesting_app_id:
            signals.append(
                ThreatSignal(
                    threat_type=ThreatType.CROSS_TENANT_ACCESS,
                    severity=ThreatSeverity.CRITICAL,
                    confidence=1.0,
                    rule_id="RAG_TENANT_ISOLATION_001",
                    description=(
                        f"Cross-tenant retrieval violation: Requesting app '{requesting_app_id}' "
                        f"attempted to retrieve chunk owned by '{chunk.app_id}'."
                    ),
                    indicators=[f"owner={chunk.app_id}", f"requester={requesting_app_id}"],
                    recommended_action=ThreatAction.BLOCK,
                )
            )

        # 2. Cryptographic integrity check (tampering detection)
        actual_hash = hashlib.sha256(chunk.content.encode("utf-8")).hexdigest()
        if chunk.expected_hash and chunk.expected_hash != actual_hash:
            signals.append(
                ThreatSignal(
                    threat_type=ThreatType.RETRIEVAL_TAMPERING,
                    severity=ThreatSeverity.HIGH,
                    confidence=0.98,
                    rule_id="RAG_INTEGRITY_TAMPERING_001",
                    description="RAG chunk cryptographic hash mismatch: underlying vector storage may be tampered.",
                    indicators=[f"expected={chunk.expected_hash}", f"actual={actual_hash}"],
                    recommended_action=ThreatAction.QUARANTINE,
                )
            )

        # 3. Poisoning & indirect prompt injection scan
        injection_eval = self.injection_detector.inspect(chunk.content)
        if injection_eval.is_threat:
            for sig in injection_eval.signals:
                signals.append(
                    ThreatSignal(
                        threat_type=ThreatType.INDIRECT_PROMPT_INJECTION,
                        severity=sig.severity,
                        confidence=sig.confidence,
                        rule_id=f"RAG_{sig.rule_id}",
                        description=f"Poisoned RAG knowledge chunk: {sig.description}",
                        indicators=sig.indicators,
                        recommended_action=ThreatAction.QUARANTINE,
                    )
                )

        if not signals:
            return True, ThreatAssessment(
                is_threat=False,
                max_severity=ThreatSeverity.LOW,
                overall_risk_score=0.0,
                signals=[],
                action=ThreatAction.ALLOW,
                reason="Retrieved chunk verified authentic and clean.",
            )

        severity_rank = {
            ThreatSeverity.LOW: 1,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.HIGH: 3,
            ThreatSeverity.CRITICAL: 4,
        }
        max_sig = max(signals, key=lambda s: (severity_rank[s.severity], s.confidence))

        action = max_sig.recommended_action
        assessment = ThreatAssessment(
            is_threat=True,
            max_severity=max_sig.severity,
            overall_risk_score=max_sig.confidence,
            signals=signals,
            action=action,
            reason=max_sig.description,
        )
        return False, assessment


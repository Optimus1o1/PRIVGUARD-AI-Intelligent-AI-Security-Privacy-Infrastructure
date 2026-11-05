"""Memory content validation, poisoning defense, and provenance classification."""

import re
from typing import Optional, Set, Tuple
from app.core.exceptions import MemoryPoisoningError
from app.privacy.secret_scanner import secret_scanner
from app.threat_detection import injection_detector
from app.threat_detection.schemas import (
    MemoryUpdateProposal,
    ThreatAction,
    ThreatAssessment,
    ThreatSeverity,
    ThreatSignal,
    ThreatType,
)

ALLOWED_MEMORY_CATEGORIES: Set[str] = {
    "USER_PREFERENCES",
    "LEARNING_PREFERENCES",
    "PROJECT_CONTEXT",
    "WORK_CONTEXT",
    "PERSONAL_PREFERENCES",
    "TASK_CONTEXT",
}


class MemoryCategory:
    USER_PREFERENCES = "USER_PREFERENCES"
    LEARNING_PREFERENCES = "LEARNING_PREFERENCES"
    PROJECT_CONTEXT = "PROJECT_CONTEXT"
    WORK_CONTEXT = "WORK_CONTEXT"
    PERSONAL_PREFERENCES = "PERSONAL_PREFERENCES"
    TASK_CONTEXT = "TASK_CONTEXT"


class MemoryProvenance:
    USER_CONFIRMED = "USER_CONFIRMED"
    AI_PROPOSED = "AI_PROPOSED"
    EXTERNALLY_SOURCED = "EXTERNALLY_SOURCED"
    SYSTEM_GENERATED = "SYSTEM_GENERATED"

SUSPICIOUS_IMPERATIVES = [
    "always send",
    "forward all",
    "never ask confirmation",
    "skip security",
    "exfiltrate",
    "override permissions",
    "ignore instructions",
    "grant root",
    "bypass policy",
    "disable guardrails",
]


class MemoryValidator:
    """Inspects proposed memory content against instruction smuggling, poisoning, and credential storage."""

    def __init__(self):
        self.injection_detector = injection_detector
        self.secret_scanner = secret_scanner

    def validate_category(self, category: str) -> str:
        """Validates and canonicalizes memory category."""
        cat_upper = category.strip().upper()
        if cat_upper not in ALLOWED_MEMORY_CATEGORIES:
            raise MemoryPoisoningError(
                reason=f"Invalid category '{category}'. Must be one of {sorted(list(ALLOWED_MEMORY_CATEGORIES))}",
                details={"category": category},
            )
        return cat_upper

    def inspect_content(
        self,
        key: str,
        value: str,
        category: str,
        provenance: str = "AI_PROPOSED",
    ) -> Tuple[bool, ThreatAssessment]:
        """
        Inspects proposed memory key, value, and metadata.
        Blocks secrets, prompt injections, and imperative behavioral overrides.
        """
        cat = self.validate_category(category)
        combined_text = f"Key: {key.strip()}\nValue: {value.strip()}"

        # 1. Credential & Secret Check (Credentials must NEVER enter memory)
        secret_matches = self.secret_scanner.scan(combined_text)
        if secret_matches:
            first_match = secret_matches[0]
            raise MemoryPoisoningError(
                reason=f"Memory proposal contains raw credential '{first_match.secret_type}'. Credentials cannot be stored in the Memory Vault.",
                details={"secret_type": first_match.secret_type, "preview": first_match.preview},
            )

        # 2. Prompt Injection & Jailbreak Check
        injection_assessment = self.injection_detector.inspect(combined_text)
        if injection_assessment.is_threat and injection_assessment.action in (ThreatAction.BLOCK, ThreatAction.QUARANTINE):
            raise MemoryPoisoningError(
                reason=f"Memory proposal rejected due to prompt injection: {injection_assessment.reason}",
                details={"signals": [s.description for s in injection_assessment.signals]},
            )

        # 3. Imperative Behavioral Override Scan
        signals = list(injection_assessment.signals)
        val_lower = value.lower()
        key_lower = key.lower()
        for imp in SUSPICIOUS_IMPERATIVES:
            if imp in val_lower or imp in key_lower:
                sig = ThreatSignal(
                    threat_type=ThreatType.MEMORY_POISONING,
                    severity=ThreatSeverity.HIGH,
                    confidence=0.92,
                    rule_id="MEM_POISON_IMPERATIVE_001",
                    description=f"Imperative agent override smuggled into memory: '{imp}'",
                    indicators=[imp],
                    recommended_action=ThreatAction.BLOCK,
                )
                signals.append(sig)
                raise MemoryPoisoningError(
                    reason=f"Imperative agent instruction '{imp}' is forbidden in persistent memory.",
                    details={"imperative": imp},
                )

        assessment = ThreatAssessment(
            is_threat=len(signals) > 0,
            max_severity=ThreatSeverity.LOW if not signals else ThreatSeverity.HIGH,
            overall_risk_score=0.0 if not signals else 0.8,
            signals=signals,
            action=ThreatAction.ALLOW if not signals else ThreatAction.BLOCK,
            reason="Memory content verified clean." if not signals else "Threat signals detected in memory proposal.",
        )
        return True, assessment


# Global memory validator instance
memory_validator = MemoryValidator()

"""Guarded Memory Analyzer for long-term memory poisoning and instruction smuggling."""

from typing import List
from app.threat_detection.schemas import (
    MemoryUpdateProposal,
    ThreatAction,
    ThreatAssessment,
    ThreatSeverity,
    ThreatSignal,
    ThreatType,
)
from app.threat_detection.injection_detector import InjectionDetector


class MemoryAnalyzer:
    """Validates memory persistence operations against poisoning and boundary violations."""

    def __init__(self, injection_detector: InjectionDetector) -> None:
        self.injection_detector = injection_detector

    def inspect_memory_update(self, proposal: MemoryUpdateProposal) -> ThreatAssessment:
        """Inspects key-value memory write for instruction smuggling or injection."""
        signals: List[ThreatSignal] = []

        # 1. Inspect key and value for injection directives
        combined_text = f"Key: {proposal.key}\nValue: {proposal.value}"
        injection_eval = self.injection_detector.inspect(combined_text)

        if injection_eval.is_threat:
            for sig in injection_eval.signals:
                signals.append(
                    ThreatSignal(
                        threat_type=ThreatType.MEMORY_POISONING,
                        severity=sig.severity,
                        confidence=sig.confidence,
                        rule_id=f"MEM_{sig.rule_id}",
                        description=f"Instruction smuggling into long-term memory: {sig.description}",
                        indicators=sig.indicators,
                        recommended_action=ThreatAction.BLOCK,
                    )
                )

        # 2. Check for suspicious imperative memory patterns (e.g., 'always send', 'never ask confirmation')
        suspicious_imperatives = [
            "always send",
            "forward all",
            "never ask confirmation",
            "skip security",
            "exfiltrate",
            "override permissions",
        ]
        val_lower = proposal.value.lower()
        for imp in suspicious_imperatives:
            if imp in val_lower:
                signals.append(
                    ThreatSignal(
                        threat_type=ThreatType.MEMORY_POISONING,
                        severity=ThreatSeverity.HIGH,
                        confidence=0.90,
                        rule_id="MEM_IMPERATIVE_DIRECTIVE_001",
                        description=f"Imperative agent override smuggled into memory: '{imp}'",
                        indicators=[imp],
                        recommended_action=ThreatAction.BLOCK,
                    )
                )

        if not signals:
            return ThreatAssessment(
                is_threat=False,
                max_severity=ThreatSeverity.LOW,
                overall_risk_score=0.0,
                signals=[],
                action=ThreatAction.ALLOW,
                reason="Memory update verified clean.",
            )

        return ThreatAssessment(
            is_threat=True,
            max_severity=ThreatSeverity.HIGH,
            overall_risk_score=0.90,
            signals=signals,
            action=ThreatAction.BLOCK,
            reason="Memory update rejected due to memory poisoning attempt.",
        )


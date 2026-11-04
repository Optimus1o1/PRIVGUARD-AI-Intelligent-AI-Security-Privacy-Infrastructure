"""Multi-layer Prompt Injection, Jailbreak, and Canary Token Detector."""

import base64
import re
import unicodedata
import uuid
from typing import List, Optional, Set
from app.threat_detection.schemas import (
    ThreatAction,
    ThreatAssessment,
    ThreatSeverity,
    ThreatSignal,
    ThreatType,
)
from app.threat_detection.rules.prompt_injection import ALL_INJECTION_RULES, InjectionPattern

_BASE64_CANDIDATE_REGEX = re.compile(r"\b[A-Za-z0-9+/]{20,}={0,2}\b")
_ZERO_WIDTH_CHARS = dict.fromkeys([0x200B, 0x200C, 0x200D, 0xFEFF, 0x202A, 0x202B, 0x202C, 0x202D, 0x202E], None)


class InjectionDetector:
    """Detects direct, indirect prompt injections, jailbreaks, and canary leaks."""

    def __init__(self, canary_registry: Optional[Set[str]] = None) -> None:
        self.canary_registry: Set[str] = canary_registry or set()

    def generate_canary(self) -> str:
        """Generates a high-entropy canary token for insertion into system context."""
        canary = f"PRIVGUARD_CANARY_{uuid.uuid4().hex[:16]}"
        self.canary_registry.add(canary)
        return canary

    def normalize_text(self, text: str) -> str:
        """Normalizes Unicode (NFKC), removes invisible chars and zero-width spaces."""
        if not text:
            return ""
        # NFKC normalizes homoglyphs and composed characters
        normalized = unicodedata.normalize("NFKC", text)
        # Strip zero-width & bidi control characters
        cleaned = normalized.translate(_ZERO_WIDTH_CHARS)
        return cleaned

    def _extract_base64_payloads(self, text: str) -> List[str]:
        """Discovers and decodes base64 candidates embedded in text."""
        decoded_payloads: List[str] = []
        candidates = _BASE64_CANDIDATE_REGEX.findall(text)
        for cand in candidates:
            try:
                # Add padding if required
                padded = cand + "=" * (-len(cand) % 4)
                decoded_bytes = base64.b64decode(padded, validate=True)
                decoded_str = decoded_bytes.decode("utf-8", errors="ignore")
                # If decoded text is mostly printable ASCII and sufficiently long, inspect it
                if len(decoded_str) >= 10 and all(c.isprintable() or c.isspace() for c in decoded_str):
                    decoded_payloads.append(decoded_str)
            except Exception:
                continue
        return decoded_payloads

    def inspect(self, text: str, source_trust: str = "UNTRUSTED") -> ThreatAssessment:
        """Inspects text for prompt injection, jailbreaks, and obfuscation."""
        if not text or not text.strip():
            return ThreatAssessment(
                is_threat=False,
                max_severity=ThreatSeverity.LOW,
                overall_risk_score=0.0,
                signals=[],
                action=ThreatAction.ALLOW,
            )

        signals: List[ThreatSignal] = []

        # 1. Check for raw zero-width characters before normalization
        if any(ord(c) in _ZERO_WIDTH_CHARS for c in text):
            signals.append(
                ThreatSignal(
                    threat_type=ThreatType.OBFUSCATED_PAYLOAD,
                    severity=ThreatSeverity.MEDIUM,
                    confidence=0.85,
                    rule_id="INJ_OBF_001",
                    description="Zero-width or invisible Unicode characters detected in prompt.",
                    indicators=["invisible_unicode_chars"],
                    recommended_action=ThreatAction.FLAG,
                )
            )

        # 2. Normalize text
        normalized = self.normalize_text(text)

        # 3. Canary Token Check
        for canary in self.canary_registry:
            if canary in text or canary in normalized:
                signals.append(
                    ThreatSignal(
                        threat_type=ThreatType.SYSTEM_PROMPT_EXTRACTION,
                        severity=ThreatSeverity.CRITICAL,
                        confidence=1.0,
                        rule_id="INJ_CANARY_LEAK_001",
                        description=f"System prompt canary token detected in stream/text: {canary[:16]}...",
                        indicators=["canary_leak"],
                        recommended_action=ThreatAction.BLOCK,
                    )
                )

        # 4. Pattern matching across deterministic rules
        for rule in ALL_INJECTION_RULES:
            match = rule.pattern.search(normalized)
            if match:
                matched_str = match.group(0)
                # Check for false-positive mitigation (academic / explanatory context)
                confidence = rule.confidence
                severity = rule.severity
                action = rule.recommended_action
                
                # Check if this pattern is inside a quoted pedagogical question
                # e.g., 'What does "ignore previous instructions" mean?'
                if self._is_quoted_pedagogical(normalized, matched_str):
                    confidence = max(0.2, confidence - 0.5)
                    severity = ThreatSeverity.LOW
                    action = ThreatAction.FLAG

                signals.append(
                    ThreatSignal(
                        threat_type=rule.threat_type,
                        severity=severity,
                        confidence=confidence,
                        rule_id=rule.rule_id,
                        description=rule.description,
                        indicators=[matched_str[:80]],
                        recommended_action=action,
                    )
                )

        # 5. Base64 payload inspection
        base64_payloads = self._extract_base64_payloads(text)
        for payload in base64_payloads:
            norm_payload = self.normalize_text(payload)
            for rule in ALL_INJECTION_RULES:
                match = rule.pattern.search(norm_payload)
                if match:
                    signals.append(
                        ThreatSignal(
                            threat_type=ThreatType.OBFUSCATED_PAYLOAD,
                            severity=ThreatSeverity.CRITICAL,
                            confidence=0.98,
                            rule_id=f"B64_{rule.rule_id}",
                            description=f"Base64 obfuscated injection payload detected: {rule.description}",
                            indicators=[match.group(0)[:80]],
                            recommended_action=ThreatAction.BLOCK,
                        )
                    )

        # Compute assessment summary
        if not signals:
            return ThreatAssessment(
                is_threat=False,
                max_severity=ThreatSeverity.LOW,
                overall_risk_score=0.0,
                signals=[],
                action=ThreatAction.ALLOW,
                reason="No prompt injection or adversarial patterns detected.",
            )

        # Determine maximum severity and overall score
        severity_rank = {
            ThreatSeverity.LOW: 1,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.HIGH: 3,
            ThreatSeverity.CRITICAL: 4,
        }
        max_sig = max(signals, key=lambda s: (severity_rank[s.severity], s.confidence))
        risk_score = round(min(1.0, sum(s.confidence for s in signals) / len(signals)), 3)

        # Determine overall action using precedence
        action_precedence = {
            ThreatAction.ALLOW: 1,
            ThreatAction.FLAG: 2,
            ThreatAction.REQUIRE_APPROVAL: 3,
            ThreatAction.QUARANTINE: 4,
            ThreatAction.BLOCK: 5,
        }
        final_action = max(
            [s.recommended_action for s in signals],
            key=lambda a: action_precedence.get(a, 1),
        )

        return ThreatAssessment(
            is_threat=True,
            max_severity=max_sig.severity,
            overall_risk_score=risk_score,
            signals=signals,
            action=final_action,
            reason=f"Threat detected: {max_sig.description}",
        )


    def _is_quoted_pedagogical(self, text: str, matched_str: str) -> bool:
        """Determines if a matched phrase appears to be quoted in an academic or inquiry context."""
        lower_text = text.lower()
        if f'"{matched_str.lower()}"' in lower_text or f"'{matched_str.lower()}'" in lower_text:
            if any(q in lower_text for q in ["how to defend against", "what does", "define", "explain", "meaning of"]):
                return True
        return False

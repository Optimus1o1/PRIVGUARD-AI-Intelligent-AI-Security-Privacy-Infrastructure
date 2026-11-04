"""Deterministic rules and regex signatures for Prompt Injection & Jailbreak Defense."""

import re
from typing import List, NamedTuple
from app.threat_detection.schemas import ThreatSeverity, ThreatType, ThreatAction


class InjectionPattern(NamedTuple):
    rule_id: str
    pattern: re.Pattern
    threat_type: ThreatType
    severity: ThreatSeverity
    confidence: float
    description: str
    recommended_action: ThreatAction


# 1. Direct Instruction Override Signatures
OVERRIDE_RULES = [
    InjectionPattern(
        rule_id="INJ_OVERRIDE_001",
        pattern=re.compile(
            r"\b(ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:(?:previous|prior|above|system|initial)\s+)?(instructions|prompts|directions|rules|guidelines|constraints)\b",
            re.IGNORECASE,
        ),
        threat_type=ThreatType.DIRECT_PROMPT_INJECTION,
        severity=ThreatSeverity.CRITICAL,
        confidence=0.95,
        description="Direct instruction override attempt detected ('ignore previous instructions').",
        recommended_action=ThreatAction.BLOCK,
    ),
    InjectionPattern(
        rule_id="INJ_OVERRIDE_002",
        pattern=re.compile(
            r"\b(new\s+instruction|system\s+override|admin\s+override|priority\s+override)\s*:\s*",
            re.IGNORECASE,
        ),
        threat_type=ThreatType.DIRECT_PROMPT_INJECTION,
        severity=ThreatSeverity.HIGH,
        confidence=0.90,
        description="Explicit directive override prefix detected.",
        recommended_action=ThreatAction.BLOCK,
    ),
    InjectionPattern(
        rule_id="INJ_OVERRIDE_003",
        pattern=re.compile(
            r"\byou\s+are\s+no\s+longer\s+(bound\s+by|restricted\s+by|an?\s+ai|subject\s+to)\b",
            re.IGNORECASE,
        ),
        threat_type=ThreatType.DIRECT_PROMPT_INJECTION,
        severity=ThreatSeverity.HIGH,
        confidence=0.88,
        description="Restriction negation attempt detected.",
        recommended_action=ThreatAction.BLOCK,
    ),
]

# 2. Jailbreak & Unrestricted Roleplay Signatures
JAILBREAK_RULES = [
    InjectionPattern(
        rule_id="INJ_JAILBREAK_001",
        pattern=re.compile(
            r"\b(dan\s+mode|jailbreak|developer\s+mode\s+v\d+|unrestricted\s+mode|godmode)\b",
            re.IGNORECASE,
        ),
        threat_type=ThreatType.JAILBREAK_ATTEMPT,
        severity=ThreatSeverity.CRITICAL,
        confidence=0.95,
        description="Known jailbreak persona signature detected (DAN/Developer Mode).",
        recommended_action=ThreatAction.BLOCK,
    ),
    InjectionPattern(
        rule_id="INJ_JAILBREAK_002",
        pattern=re.compile(
            r"\b(pretend|act\s+as\s+if|roleplay\s+as)\s+(you\s+have\s+no\s+(rules|guidelines|safety|filters|limits)|an?\s+unrestricted\s+ai|an?\s+evil\s+ai)\b",
            re.IGNORECASE,
        ),
        threat_type=ThreatType.JAILBREAK_ATTEMPT,
        severity=ThreatSeverity.HIGH,
        confidence=0.90,
        description="Adversarial roleplay evasion attempt detected.",
        recommended_action=ThreatAction.BLOCK,
    ),
]

# 3. System Prompt Extraction Signatures
EXTRACTION_RULES = [
    InjectionPattern(
        rule_id="INJ_EXTRACT_001",
        pattern=re.compile(
            r"\b(repeat|print|output|display|show|reveal|echo)\s+(all\s+)?(the\s+)?(text\s+above|system\s+prompt|initial\s+instructions|system\s+message|instructions\s+verbatim)\b",
            re.IGNORECASE,
        ),
        threat_type=ThreatType.SYSTEM_PROMPT_EXTRACTION,
        severity=ThreatSeverity.HIGH,
        confidence=0.92,
        description="System prompt extraction attempt detected.",
        recommended_action=ThreatAction.BLOCK,
    ),
    InjectionPattern(
        rule_id="INJ_EXTRACT_002",
        pattern=re.compile(
            r"\bwhat\s+(were|are)\s+your\s+(exact\s+)?(initial|system|original|developer)\s+(instructions|prompt|rules)\b",
            re.IGNORECASE,
        ),
        threat_type=ThreatType.SYSTEM_PROMPT_EXTRACTION,
        severity=ThreatSeverity.HIGH,
        confidence=0.88,
        description="Direct inquiry into internal system instructions.",
        recommended_action=ThreatAction.BLOCK,
    ),
]

# 4. Context & Delimiter Hijacking Signatures
DELIMITER_RULES = [
    InjectionPattern(
        rule_id="INJ_DELIM_001",
        pattern=re.compile(
            r"(<\|im_start\|>|<\|im_end\|>|<\|system\|>|\[INST\]\s*<<SYS>>|###\s*(SYSTEM|INSTRUCTION|HUMAN):)",
            re.IGNORECASE,
        ),
        threat_type=ThreatType.DIRECT_PROMPT_INJECTION,
        severity=ThreatSeverity.CRITICAL,
        confidence=0.98,
        description="Raw LLM chat delimiter injection detected.",
        recommended_action=ThreatAction.BLOCK,
    ),
    InjectionPattern(
        rule_id="INJ_DELIM_002",
        pattern=re.compile(
            r"(-{3,}\s*(BEGIN|END)\s+(OF\s+)?(SYSTEM\s+(CONTEXT|PROMPT)|INSTRUCTIONS|ADMIN\s+MODE)\s*-{3,})",
            re.IGNORECASE,
        ),
        threat_type=ThreatType.DIRECT_PROMPT_INJECTION,
        severity=ThreatSeverity.HIGH,
        confidence=0.92,
        description="Structured fake instruction boundary delimiter detected.",
        recommended_action=ThreatAction.BLOCK,
    ),
    InjectionPattern(
        rule_id="INJ_DELIM_003",
        pattern=re.compile(
            r"(```\s*system|###\s*(End\s+of\s+Prompt|New\s+Task|Admin\s+Instruction)\s*###?)",
            re.IGNORECASE,
        ),
        threat_type=ThreatType.DIRECT_PROMPT_INJECTION,
        severity=ThreatSeverity.HIGH,
        confidence=0.95,
        description="Markdown system block or section boundary hijacking detected.",
        recommended_action=ThreatAction.BLOCK,
    ),
]

# 5. Evasion & Obfuscation Signatures
OBFUSCATION_RULES = [
    InjectionPattern(
        rule_id="INJ_OBF_001",
        pattern=re.compile(
            r"[\u200B-\u200D\uFEFF\u202A-\u202E]",
        ),
        threat_type=ThreatType.OBFUSCATED_PAYLOAD,
        severity=ThreatSeverity.MEDIUM,
        confidence=0.85,
        description="Invisible zero-width or bidirectional Unicode characters detected.",
        recommended_action=ThreatAction.FLAG,
    ),
]

ALL_INJECTION_RULES: List[InjectionPattern] = (
    OVERRIDE_RULES + JAILBREAK_RULES + EXTRACTION_RULES + DELIMITER_RULES + OBFUSCATION_RULES
)


"""PII (Personally Identifiable Information) detection engine."""

import re
from typing import List, NamedTuple, Optional


class PIIMatch(NamedTuple):
    """Details of a detected PII entity."""

    entity_type: str
    text: str
    start: int
    end: int
    score: float


def validate_luhn(card_number_str: str) -> bool:
    """Validates a numeric string using the Luhn checksum algorithm."""
    digits = [int(c) for c in card_number_str if c.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for i, digit in enumerate(reverse_digits):
        if i % 2 == 1:
            doubled = digit * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += digit
    return checksum % 10 == 0


# High-precision PII regular expressions
PII_REGEX_PATTERNS = [
    # Email addresses
    (
        "EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),
        0.95,
    ),
    # Phone numbers (North America, UK, India, and international E.164)
    (
        "PHONE_NUMBER",
        re.compile(
            r"(?:\+\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b|"
            r"\+\d{1,3}[-.\s]?\d{3}[-.\s]?\d{4}\b|"
            r"\+91[-.\s]?[6-9]\d{9}\b|"
            r"\b[6-9]\d{9}\b"
        ),
        0.85,
    ),
    # US Social Security Numbers
    (
        "SSN",
        re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b"),
        0.90,
    ),
    # IPv4 Addresses
    (
        "IP_ADDRESS",
        re.compile(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"),
        0.80,
    ),
    # Credit / Debit Cards (with Luhn pre-match)
    (
        "CREDIT_CARD",
        re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{15,16}\b"),
        0.95,
    ),
    # Bank Account Numbers / Identifiers
    (
        "ACCOUNT_NUMBER",
        re.compile(r"(?i)\baccount(?:\s+number|\s+id|\s+no|\s*#)?\s*[:=]?\s*([0-9]{8,18})\b"),
        0.85,
    ),
]


class PIIDetector:
    """Detects personally identifiable information in unstructured text."""

    def __init__(self, use_presidio: bool = True):
        self.use_presidio = use_presidio
        self._presidio_analyzer = None

        if self.use_presidio:
            try:
                from presidio_analyzer import AnalyzerEngine

                self._presidio_analyzer = AnalyzerEngine()
            except Exception:
                # Graceful fallback to pure regex if presidio / spacy is unavailable
                self._presidio_analyzer = None

    def detect(self, text: str) -> List[PIIMatch]:
        """Scans the text for PII entities and returns detected spans."""
        if not text:
            return []

        matches: List[PIIMatch] = []
        seen_spans = set()

        # 1. Native Regex Detection
        for entity_type, pattern, score in PII_REGEX_PATTERNS:
            for match in pattern.finditer(text):
                matched_val = match.group(0)
                start = match.start(0)
                end = match.end(0)

                # Special validation for Credit Cards: must satisfy Luhn
                if entity_type == "CREDIT_CARD":
                    clean_digits = re.sub(r"\D", "", matched_val)
                    if not validate_luhn(clean_digits):
                        continue

                # Account number pattern has capture group for number
                if entity_type == "ACCOUNT_NUMBER" and match.groups():
                    matched_val = match.group(1)
                    start = match.start(1)
                    end = match.end(1)

                span = (start, end)
                if span in seen_spans:
                    continue

                seen_spans.add(span)
                matches.append(
                    PIIMatch(
                        entity_type=entity_type,
                        text=matched_val,
                        start=start,
                        end=end,
                        score=score,
                    )
                )

        # 2. Presidio Analyzer (if initialized)
        if self._presidio_analyzer:
            try:
                presidio_results = self._presidio_analyzer.analyze(
                    text=text,
                    language="en",
                )
                for res in presidio_results:
                    span = (res.start, res.end)
                    if span not in seen_spans:
                        seen_spans.add(span)
                        matches.append(
                            PIIMatch(
                                entity_type=res.entity_type,
                                text=text[res.start : res.end],
                                start=res.start,
                                end=res.end,
                                score=res.score,
                            )
                        )
            except Exception:
                # Do not break inspection if presidio fails; native regex already collected
                pass

        # Sort matches by appearance in text
        matches.sort(key=lambda m: m.start)
        return matches


# Default shared PII detector
pii_detector = PIIDetector(use_presidio=False)

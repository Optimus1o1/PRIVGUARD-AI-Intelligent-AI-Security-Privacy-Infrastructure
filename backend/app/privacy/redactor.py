"""Data redaction and reversible pseudonymization engine."""

from typing import Dict, List, NamedTuple, Tuple
from pydantic import BaseModel


class RedactedEntity(BaseModel):
    """Metadata regarding a redacted entity."""
    entity_type: str
    placeholder: str
    start: int
    end: int


class RedactionResult(BaseModel):
    """Result of data redaction process."""
    original_text: str
    redacted_text: str
    mapping: Dict[str, str]        # placeholder -> original_value
    reverse_mapping: Dict[str, str] # original_value -> placeholder
    redacted_entities: List[RedactedEntity]
    entity_counts: Dict[str, int]


class DataRedactor:
    """Manages reversible and irreversible data redaction."""

    def redact(
        self,
        text: str,
        spans: List[Tuple[str, int, int, str]],  # (entity_type, start, end, raw_value)
    ) -> RedactionResult:
        """
        Redacts specified spans within the text using indexed tokens (e.g. <EMAIL_1>).
        Spans must not overlap.
        """
        if not text or not spans:
            return RedactionResult(
                original_text=text,
                redacted_text=text,
                mapping={},
                reverse_mapping={},
                redacted_entities=[],
                entity_counts={},
            )

        # Sort spans strictly in order of start position
        sorted_spans = sorted(spans, key=lambda s: s[1])

        # Resolve any accidental overlaps by keeping the first
        non_overlapping_spans = []
        last_end = -1
        for s in sorted_spans:
            if s[1] >= last_end:
                non_overlapping_spans.append(s)
                last_end = s[2]

        mapping: Dict[str, str] = {}
        reverse_mapping: Dict[str, str] = {}
        type_counters: Dict[str, int] = {}
        entity_counts: Dict[str, int] = {}
        redacted_entities: List[RedactedEntity] = []

        # Build redacted text piece by piece
        chunks = []
        current_idx = 0

        for entity_type, start, end, raw_val in non_overlapping_spans:
            # Append preceding clean text
            chunks.append(text[current_idx:start])

            # Check if this exact raw value was already assigned a placeholder
            if raw_val in reverse_mapping:
                token = reverse_mapping[raw_val]
            else:
                counter = type_counters.get(entity_type, 0) + 1
                type_counters[entity_type] = counter
                token = f"<{entity_type}_{counter}>"
                mapping[token] = raw_val
                reverse_mapping[raw_val] = token

            entity_counts[entity_type] = entity_counts.get(entity_type, 0) + 1
            chunks.append(token)
            redacted_entities.append(
                RedactedEntity(
                    entity_type=entity_type,
                    placeholder=token,
                    start=start,
                    end=end,
                )
            )
            current_idx = end

        # Append remaining text
        chunks.append(text[current_idx:])
        redacted_text = "".join(chunks)

        return RedactionResult(
            original_text=text,
            redacted_text=redacted_text,
            mapping=mapping,
            reverse_mapping=reverse_mapping,
            redacted_entities=redacted_entities,
            entity_counts=entity_counts,
        )

    def restore(self, text: str, mapping: Dict[str, str]) -> str:
        """Restores original values from token placeholders (reversible de-redaction)."""
        if not text or not mapping:
            return text

        restored = text
        for placeholder, original in mapping.items():
            restored = restored.replace(placeholder, original)
        return restored


# Default shared redactor instance
redactor = DataRedactor()

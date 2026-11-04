"""Model output response security inspector and placeholder restoration."""

from typing import Dict, NamedTuple, Optional
from app.core.exceptions import ResponseSecurityViolationError
from app.core.security import content_hash
from app.privacy.redactor import redactor
from app.privacy.secret_scanner import secret_scanner


class InspectedResponse(NamedTuple):
    """Result of inspecting and restoring model response text."""
    sanitized_content: str
    restored_content: str
    has_secrets: bool
    content_fingerprint: str
    restoration_count: int


class ResponseSecurityInspector:
    """Inspects raw model output for leaked credentials and restores authorized placeholders."""

    def __init__(self):
        self.secret_scanner = secret_scanner
        self.redactor = redactor

    def inspect_and_restore(
        self,
        raw_model_content: str,
        request_mapping: Optional[Dict[str, str]] = None,
    ) -> InspectedResponse:
        """
        Validates model output against secret scanning rules and restores authorized tokens.
        Raises ResponseSecurityViolationError if the model generated credentials.
        """
        if not raw_model_content:
            return InspectedResponse(
                sanitized_content="",
                restored_content="",
                has_secrets=False,
                content_fingerprint=content_hash(""),
                restoration_count=0,
            )

        fingerprint = content_hash(raw_model_content)

        # 1. First Line of Defense: Secret Scanning on Model Output
        secret_matches = self.secret_scanner.scan(raw_model_content)
        if secret_matches:
            first_match = secret_matches[0]
            raise ResponseSecurityViolationError(
                violation_type=first_match.secret_type,
                preview=first_match.preview,
                reason="Model output contained sensitive credentials or secrets.",
            )

        # 2. Second Step: Reversible PII Restoration
        restored_text = raw_model_content
        restoration_count = 0

        if request_mapping:
            for token, original_val in request_mapping.items():
                if token in restored_text:
                    occurrences = restored_text.count(token)
                    restoration_count += occurrences
                    restored_text = restored_text.replace(token, original_val)

        return InspectedResponse(
            sanitized_content=raw_model_content,
            restored_content=restored_text,
            has_secrets=False,
            content_fingerprint=fingerprint,
            restoration_count=restoration_count,
        )


# Shared response inspector instance
response_inspector = ResponseSecurityInspector()

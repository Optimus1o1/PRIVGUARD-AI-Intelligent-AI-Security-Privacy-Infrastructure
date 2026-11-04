"""Data classification and risk level categorization."""

from enum import Enum
from typing import Dict, List, Optional
from pydantic import BaseModel


class DataCategory(str, Enum):
    """Data classification categories."""
    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    PERSONAL = "PERSONAL"
    CONFIDENTIAL = "CONFIDENTIAL"
    CRITICAL = "CRITICAL"


class RiskLevel(str, Enum):
    """Security risk levels."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# Entity type to Category & Risk mapping
ENTITY_CLASSIFICATION_MAP: Dict[str, tuple[DataCategory, RiskLevel]] = {
    # Critical credentials and secrets
    "API_KEY": (DataCategory.CRITICAL, RiskLevel.CRITICAL),
    "PRIVATE_KEY": (DataCategory.CRITICAL, RiskLevel.CRITICAL),
    "PASSWORD": (DataCategory.CRITICAL, RiskLevel.CRITICAL),
    "DATABASE_URL": (DataCategory.CRITICAL, RiskLevel.CRITICAL),
    "ACCESS_TOKEN": (DataCategory.CRITICAL, RiskLevel.CRITICAL),
    "JWT_TOKEN": (DataCategory.CRITICAL, RiskLevel.CRITICAL),
    "AWS_KEY": (DataCategory.CRITICAL, RiskLevel.CRITICAL),
    "SSH_KEY": (DataCategory.CRITICAL, RiskLevel.CRITICAL),

    # Personal Identifiable Information (PII)
    "EMAIL": (DataCategory.PERSONAL, RiskLevel.MEDIUM),
    "PHONE_NUMBER": (DataCategory.PERSONAL, RiskLevel.MEDIUM),
    "CREDIT_CARD": (DataCategory.PERSONAL, RiskLevel.HIGH),
    "SSN": (DataCategory.PERSONAL, RiskLevel.HIGH),
    "PERSON_NAME": (DataCategory.PERSONAL, RiskLevel.LOW),
    "IP_ADDRESS": (DataCategory.PERSONAL, RiskLevel.LOW),
    "NATIONAL_ID": (DataCategory.PERSONAL, RiskLevel.HIGH),

    # Confidential
    "CONFIDENTIAL_MARKER": (DataCategory.CONFIDENTIAL, RiskLevel.HIGH),
    "INTERNAL_DOCUMENT": (DataCategory.INTERNAL, RiskLevel.LOW),
}


class ClassificationResult(BaseModel):
    """Result of classifying a text or extracted entity set."""
    overall_category: DataCategory
    highest_risk: RiskLevel
    entity_counts: Dict[str, int]
    is_safe_to_forward: bool = True
    blocking_reason: Optional[str] = None


def classify_entities(detected_entities: List[str]) -> ClassificationResult:
    """Computes overall category and maximum risk level from detected entity types."""
    if not detected_entities:
        return ClassificationResult(
            overall_category=DataCategory.PUBLIC,
            highest_risk=RiskLevel.LOW,
            entity_counts={},
            is_safe_to_forward=True,
        )

    entity_counts: Dict[str, int] = {}
    for entity in detected_entities:
        entity_counts[entity] = entity_counts.get(entity, 0) + 1

    # Check for Critical / Secrets first
    has_critical = any(
        ENTITY_CLASSIFICATION_MAP.get(e, (DataCategory.PUBLIC, RiskLevel.LOW))[0] == DataCategory.CRITICAL
        for e in detected_entities
    )
    if has_critical:
        return ClassificationResult(
            overall_category=DataCategory.CRITICAL,
            highest_risk=RiskLevel.CRITICAL,
            entity_counts=entity_counts,
            is_safe_to_forward=False,
            blocking_reason="Critical secret or credential detected in payload.",
        )

    # Check Confidential
    has_confidential = any(
        ENTITY_CLASSIFICATION_MAP.get(e, (DataCategory.PUBLIC, RiskLevel.LOW))[0] == DataCategory.CONFIDENTIAL
        for e in detected_entities
    )
    if has_confidential:
        return ClassificationResult(
            overall_category=DataCategory.CONFIDENTIAL,
            highest_risk=RiskLevel.HIGH,
            entity_counts=entity_counts,
            is_safe_to_forward=True,
        )

    # Check Personal
    has_personal = any(
        ENTITY_CLASSIFICATION_MAP.get(e, (DataCategory.PUBLIC, RiskLevel.LOW))[0] == DataCategory.PERSONAL
        for e in detected_entities
    )
    if has_personal:
        # High risk if credit card or ssn
        high_risk_personal = any(e in ("CREDIT_CARD", "SSN", "NATIONAL_ID") for e in detected_entities)
        return ClassificationResult(
            overall_category=DataCategory.PERSONAL,
            highest_risk=RiskLevel.HIGH if high_risk_personal else RiskLevel.MEDIUM,
            entity_counts=entity_counts,
            is_safe_to_forward=True,
        )

    # Check Internal
    has_internal = any(
        ENTITY_CLASSIFICATION_MAP.get(e, (DataCategory.PUBLIC, RiskLevel.LOW))[0] == DataCategory.INTERNAL
        for e in detected_entities
    )
    if has_internal:
        return ClassificationResult(
            overall_category=DataCategory.INTERNAL,
            highest_risk=RiskLevel.LOW,
            entity_counts=entity_counts,
            is_safe_to_forward=True,
        )

    return ClassificationResult(
        overall_category=DataCategory.PUBLIC,
        highest_risk=RiskLevel.LOW,
        entity_counts=entity_counts,
        is_safe_to_forward=True,
    )


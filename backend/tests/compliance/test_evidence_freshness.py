"""Unit tests for Five-State Assurance and Evidence Freshness Lifecycle."""

from datetime import datetime, timedelta, timezone
import pytest

from app.compliance.evidence_freshness import freshness_evaluator
from app.compliance.schemas import (
    AssuranceLevel,
    ControlImplementationStatus,
    EvidenceFreshness,
    EvidenceVerificationStatus,
    MappingType,
)


def test_freshness_calculation():
    """Verifies freshness calculation transitions based on expiration timestamp."""
    now = datetime.now(timezone.utc)

    # 1. Current evidence (expires in 10 days)
    f_current = freshness_evaluator.evaluate_freshness(
        collected_at=now,
        expires_at=now + timedelta(days=10),
        as_of=now,
    )
    assert f_current == EvidenceFreshness.CURRENT

    # 2. Stale evidence (expires in 1 day, under 2-day threshold)
    f_stale = freshness_evaluator.evaluate_freshness(
        collected_at=now - timedelta(days=6),
        expires_at=now + timedelta(days=1),
        as_of=now,
    )
    assert f_stale == EvidenceFreshness.STALE

    # 3. Expired evidence (expired 2 days ago)
    f_expired = freshness_evaluator.evaluate_freshness(
        collected_at=now - timedelta(days=10),
        expires_at=now - timedelta(days=2),
        as_of=now,
    )
    assert f_expired == EvidenceFreshness.EXPIRED


def test_assurance_level_derivation_semantic_invariant():
    """
    CRITICAL SEMANTIC INVARIANT:
    Stale evidence reduces assurance_status to LOW, but does NOT alter control_implementation_status.
    """
    # Healthy state: IMPLEMENTED + VERIFIED + CURRENT -> HIGH assurance
    a_high = freshness_evaluator.evaluate_assurance_level(
        implementation_status=ControlImplementationStatus.IMPLEMENTED,
        verification_status=EvidenceVerificationStatus.VERIFIED,
        freshness=EvidenceFreshness.CURRENT,
        mapping_type=MappingType.DIRECT,
    )
    assert a_high == AssuranceLevel.HIGH

    # Stale state: IMPLEMENTED + VERIFIED + STALE -> LOW assurance
    # Control remains IMPLEMENTED!
    a_stale = freshness_evaluator.evaluate_assurance_level(
        implementation_status=ControlImplementationStatus.IMPLEMENTED,
        verification_status=EvidenceVerificationStatus.VERIFIED,
        freshness=EvidenceFreshness.STALE,
        mapping_type=MappingType.DIRECT,
    )
    assert a_stale == AssuranceLevel.LOW

    # Expired state -> LOW assurance
    a_exp = freshness_evaluator.evaluate_assurance_level(
        implementation_status=ControlImplementationStatus.IMPLEMENTED,
        verification_status=EvidenceVerificationStatus.VERIFIED,
        freshness=EvidenceFreshness.EXPIRED,
        mapping_type=MappingType.DIRECT,
    )
    assert a_exp == AssuranceLevel.LOW

    # Verification failed -> INSUFFICIENT
    a_failed = freshness_evaluator.evaluate_assurance_level(
        implementation_status=ControlImplementationStatus.IMPLEMENTED,
        verification_status=EvidenceVerificationStatus.FAILED,
        freshness=EvidenceFreshness.CURRENT,
    )
    assert a_failed == AssuranceLevel.INSUFFICIENT


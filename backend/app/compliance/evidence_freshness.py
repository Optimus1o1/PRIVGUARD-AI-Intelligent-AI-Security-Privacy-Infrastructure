"""Five-State Assurance and Evidence Freshness Engine for PRIVGUARD AI (Stage 10.9).

Enforces the core semantic invariant:
- Control Implementation Status (whether the code is built)
- Evidence Verification Status (whether verification passed)
- Evidence Freshness (whether evidence is within operational TTL)
- Assurance Level (audit confidence derived from implementation + freshness)
- Applicability Decision (scoped role determination)

Semantic Invariant:
Stale or expired evidence reduces assurance_status (to LOW or INSUFFICIENT).
It does NOT automatically declare a working control unimplemented.
"""

from datetime import datetime, timezone
from typing import Optional
from app.compliance.schemas import (
    AssuranceLevel,
    ControlImplementationStatus,
    EvidenceFreshness,
    EvidenceVerificationStatus,
    MappingType,
)


class EvidenceFreshnessEvaluator:
    """Evaluates evidence validity windows and computes 5-state assurance transitions."""

    @staticmethod
    def evaluate_freshness(
        collected_at: datetime,
        expires_at: datetime,
        as_of: Optional[datetime] = None,
    ) -> EvidenceFreshness:
        """Determines freshness based on TTL expiration timestamps."""
        now = as_of or datetime.now(timezone.utc)
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        if now > expires_at:
            return EvidenceFreshness.EXPIRED
        elif (expires_at - now).total_seconds() < 86400 * 2:  # Less than 2 days remaining
            return EvidenceFreshness.STALE
        return EvidenceFreshness.CURRENT

    @staticmethod
    def evaluate_assurance_level(
        implementation_status: ControlImplementationStatus,
        verification_status: Optional[EvidenceVerificationStatus],
        freshness: Optional[EvidenceFreshness],
        mapping_type: MappingType = MappingType.DIRECT,
    ) -> AssuranceLevel:
        """
        Computes composite assurance level:
        - HIGH: Control is IMPLEMENTED, evidence is VERIFIED and CURRENT with DIRECT mapping.
        - MEDIUM: Control is IMPLEMENTED, evidence is VERIFIED and CURRENT with PARTIAL/SUPPORTING mapping, OR requires review.
        - LOW: Control is IMPLEMENTED, but evidence is STALE/EXPIRED or UNKNOWN.
        - INSUFFICIENT: Control is NOT_IMPLEMENTED, evidence FAILED, or zero evidence exists.
        """
        if implementation_status in (
            ControlImplementationStatus.NOT_IMPLEMENTED,
            ControlImplementationStatus.NOT_ASSESSED,
        ):
            return AssuranceLevel.INSUFFICIENT

        if verification_status == EvidenceVerificationStatus.FAILED:
            return AssuranceLevel.INSUFFICIENT

        if verification_status is None:
            return AssuranceLevel.INSUFFICIENT

        # Stale or expired evidence reduces assurance to LOW
        if freshness in (EvidenceFreshness.STALE, EvidenceFreshness.EXPIRED):
            return AssuranceLevel.LOW

        if verification_status == EvidenceVerificationStatus.REQUIRES_REVIEW:
            return AssuranceLevel.MEDIUM

        if verification_status == EvidenceVerificationStatus.UNKNOWN:
            return AssuranceLevel.LOW

        if verification_status == EvidenceVerificationStatus.VERIFIED and freshness == EvidenceFreshness.CURRENT:
            if mapping_type == MappingType.DIRECT:
                return AssuranceLevel.HIGH
            return AssuranceLevel.MEDIUM

        return AssuranceLevel.LOW


# Global singleton evaluator
freshness_evaluator = EvidenceFreshnessEvaluator()


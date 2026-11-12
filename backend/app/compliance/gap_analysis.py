"""Compliance Gap Analysis Engine for PRIVGUARD AI (Stage 10.9).

Identifies actionable gaps:
- UNMAPPED_REQUIREMENT: Statutory requirement with zero internal technical mappings.
- MISSING_EVIDENCE: Technical control implemented but without collected evidence records.
- FAILED_EVIDENCE: Operational verification failure on active control.
- STALE_EVIDENCE: Operational evidence past TTL window.
- PARTIAL_MAPPING: Technical control partially satisfies requirement; organizational policy needed.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.compliance.control_catalog import control_catalog
from app.compliance.control_mapping import control_mapping_engine
from app.compliance.framework_registry import framework_registry
from app.compliance.models import ComplianceEvidenceRecord
from app.compliance.schemas import (
    CommencementStatus,
    ComplianceGapAnalysisResponse,
    ComplianceGapItem,
    EvidenceFreshness,
    EvidenceVerificationStatus,
    MappingType,
)


class ComplianceGapAnalyzer:
    """Evaluates tenant compliance posture and isolates actionable gaps."""

    async def analyze_gaps(
        self,
        db: Optional[AsyncSession] = None,
        tenant_id: str = "default_tenant",
        framework_id: Optional[str] = None,
    ) -> ComplianceGapAnalysisResponse:
        """Executes multi-dimensional gap analysis across registered frameworks."""
        items: List[ComplianceGapItem] = []
        now = datetime.now(timezone.utc)

        # 1. Fetch latest evidence per control for this tenant if db provided
        evidence_by_control: Dict[str, ComplianceEvidenceRecord] = {}
        if db:
            stmt = (
                select(ComplianceEvidenceRecord)
                .where(ComplianceEvidenceRecord.tenant_id == tenant_id)
                .order_by(ComplianceEvidenceRecord.collected_at.desc())
            )
            res = await db.execute(stmt)
            all_records = res.scalars().all()
            for r in all_records:
                if r.control_id not in evidence_by_control:
                    evidence_by_control[r.control_id] = r

        # 2. Frameworks to inspect
        target_frameworks = (
            [framework_registry.get_framework(framework_id)]
            if framework_id and framework_registry.get_framework(framework_id)
            else framework_registry.list_frameworks()
        )

        for fw in target_frameworks:
            if not fw:
                continue

            for req in fw.requirements:
                mappings = control_mapping_engine.get_mappings_for_requirement(req.id)

                # Gap 1: Unmapped requirement
                if not mappings:
                    severity = (
                        "CRITICAL"
                        if req.commencement_status == CommencementStatus.COMMENCED and req.mandatory
                        else "MEDIUM"
                    )
                    items.append(
                        ComplianceGapItem(
                            gap_type="UNMAPPED_REQUIREMENT",
                            severity=severity,
                            requirement_id=req.id,
                            control_id=None,
                            title=f"Unmapped Requirement: {fw.name} {req.identifier}",
                            description=f"Requirement '{req.title}' has no internal PRIVGUARD controls mapped.",
                            remediation_action=(
                                f"Review statutory obligations for {req.identifier} and define a technical or procedural control mapping."
                            ),
                        )
                    )
                    continue

                for m in mappings:
                    ctrl = control_catalog.get_control(m.control_id)
                    ev = evidence_by_control.get(m.control_id)

                    # Gap 2: Missing Evidence
                    if not ev:
                        items.append(
                            ComplianceGapItem(
                                gap_type="MISSING_EVIDENCE",
                                severity="HIGH" if ctrl and ctrl.criticality == "CRITICAL" else "MEDIUM",
                                requirement_id=req.id,
                                control_id=m.control_id,
                                title=f"Missing Evidence: {m.control_id} for {req.identifier}",
                                description=f"Control {m.control_id} ({ctrl.title if ctrl else ''}) has not collected evidence for tenant '{tenant_id}'.",
                                remediation_action=f"Trigger evidence collection for {m.control_id} via /v1/compliance/evidence/collect.",
                            )
                        )
                        continue

                    # Gap 3: Failed Evidence
                    if ev.verification_status == EvidenceVerificationStatus.FAILED.value:
                        items.append(
                            ComplianceGapItem(
                                gap_type="FAILED_EVIDENCE",
                                severity="CRITICAL",
                                requirement_id=req.id,
                                control_id=m.control_id,
                                title=f"Verification Failed: {m.control_id} for {req.identifier}",
                                description=f"Recent operational test for control {m.control_id} failed verification.",
                                remediation_action=f"Inspect failing subsystem logs for {ev.collector_name} and remediate root cause.",
                            )
                        )

                    # Gap 4: Stale / Expired Evidence
                    exp_at = (
                        ev.expires_at.replace(tzinfo=timezone.utc) if ev.expires_at.tzinfo is None else ev.expires_at
                    )
                    if now > exp_at:
                        items.append(
                            ComplianceGapItem(
                                gap_type="STALE_EVIDENCE",
                                severity="MEDIUM",
                                requirement_id=req.id,
                                control_id=m.control_id,
                                title=f"Expired Evidence: {m.control_id} for {req.identifier}",
                                description=f"Evidence for control {m.control_id} expired on {exp_at.isoformat()}.",
                                remediation_action=f"Re-run evidence collector {ev.collector_name} to refresh assurance artifact.",
                            )
                        )

                    # Gap 5: Partial Mapping requiring organizational / procedural policy
                    if m.mapping_type == MappingType.PARTIAL:
                        items.append(
                            ComplianceGapItem(
                                gap_type="PARTIAL_MAPPING",
                                severity="LOW",
                                requirement_id=req.id,
                                control_id=m.control_id,
                                title=f"Partial Coverage: {req.identifier} via {m.control_id}",
                                description=f"Technical control {m.control_id} satisfies technical aspects only: {m.rationale}",
                                remediation_action=f"Upload organizational policy documentation to satisfy procedural requirements of {req.identifier}.",
                            )
                        )

        # Count severities
        crit = sum(1 for i in items if i.severity == "CRITICAL")
        high = sum(1 for i in items if i.severity == "HIGH")
        med = sum(1 for i in items if i.severity == "MEDIUM")
        low = sum(1 for i in items if i.severity == "LOW")

        return ComplianceGapAnalysisResponse(
            tenant_id=tenant_id,
            evaluated_at=now,
            total_gaps=len(items),
            critical_gaps=crit,
            high_gaps=high,
            medium_gaps=med,
            low_gaps=low,
            items=items,
        )


# Global singleton analyzer
gap_analyzer = ComplianceGapAnalyzer()

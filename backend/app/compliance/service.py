"""Compliance Service Orchestrator for PRIVGUARD AI (Stage 10.9).

Unified application facade coordinating:
- Framework Registry & Phased Statutory Milestones
- Internal Control Catalog (PG-CONTROL-001..035)
- Crosswalk Control Mappings & Coverage Scoring
- Modular Hardened Evidence Collectors
- Five-State Assurance Evaluation & Freshness Lifecycle
- Multi-Tenant Applicability Decisions
- Gap Analysis & Actionable Remediation
- Cryptographic Export Packaging (ZIP, JSON, CSV) & Ed25519 Signing
"""

import json
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_, delete

from app.core.config import settings
from app.compliance.applicability import applicability_manager
from app.compliance.control_catalog import control_catalog
from app.compliance.control_mapping import control_mapping_engine
from app.compliance.evidence_collector import evidence_collector_engine
from app.compliance.evidence_export import evidence_export_packager
from app.compliance.evidence_freshness import freshness_evaluator
from app.compliance.evidence_integrity import evidence_integrity_service
from app.compliance.framework_registry import framework_registry
from app.compliance.gap_analysis import gap_analyzer
from app.compliance.models import (
    ComplianceApplicabilityRecord,
    ComplianceAssessment,
    ComplianceEvidenceRecord,
    ComplianceExportSnapshot,
)
from app.compliance.schemas import (
    ApplicabilityDecision,
    ApplicabilityRecordResponse,
    ApplicabilityUpdateRequest,
    AssuranceLevel,
    CommencementStatus,
    ComplianceAssessmentResponse,
    ComplianceControlDetailResponse,
    ComplianceControlMappingResponse,
    ComplianceControlResponse,
    ComplianceEvidenceResponse,
    ComplianceFrameworkDetailResponse,
    ComplianceFrameworkResponse,
    ComplianceGapAnalysisResponse,
    ComplianceRequirementResponse,
    ControlImplementationStatus,
    EvidenceCollectionResult,
    EvidenceExportRequest,
    EvidenceExportResponse,
    EvidenceFreshness,
    EvidencePublicKeyResponse,
    EvidenceVerificationStatus,
    ExportFormat,
    MappingType,
    OrganizationRole,
)


class ComplianceService:
    """Enterprise Compliance Evidence Service."""

    # --------------------------------------------------------------------------
    # Frameworks & Requirements
    # --------------------------------------------------------------------------

    def list_frameworks(self) -> List[ComplianceFrameworkResponse]:
        """Lists registered frameworks with requirement counts and coverage."""
        res: List[ComplianceFrameworkResponse] = []
        for fw in framework_registry.list_frameworks():
            reqs = fw.requirements
            commenced = sum(1 for r in reqs if r.commencement_status == CommencementStatus.COMMENCED)
            cov = control_mapping_engine.compute_framework_coverage([r.id for r in reqs])

            res.append(
                ComplianceFrameworkResponse(
                    id=fw.id,
                    name=fw.name,
                    version=fw.version,
                    jurisdiction=fw.jurisdiction,
                    authority=fw.authority,
                    description=fw.description,
                    official_reference=fw.official_reference,
                    status=fw.status,
                    commenced_at=fw.commenced_at,
                    total_requirements=len(reqs),
                    commenced_requirements=commenced,
                    mapped_requirements=cov["mapped_requirements"],
                )
            )
        return res

    def get_framework_detail(self, framework_id: str) -> Optional[ComplianceFrameworkDetailResponse]:
        """Retrieves framework specification with itemized clauses."""
        fw = framework_registry.get_framework(framework_id)
        if not fw:
            return None

        reqs = fw.requirements
        commenced = sum(1 for r in reqs if r.commencement_status == CommencementStatus.COMMENCED)
        cov = control_mapping_engine.compute_framework_coverage([r.id for r in reqs])

        return ComplianceFrameworkDetailResponse(
            id=fw.id,
            name=fw.name,
            version=fw.version,
            jurisdiction=fw.jurisdiction,
            authority=fw.authority,
            description=fw.description,
            official_reference=fw.official_reference,
            status=fw.status,
            commenced_at=fw.commenced_at,
            total_requirements=len(reqs),
            commenced_requirements=commenced,
            mapped_requirements=cov["mapped_requirements"],
            requirements=[
                ComplianceRequirementResponse(
                    id=r.id,
                    framework_id=r.framework_id,
                    identifier=r.identifier,
                    title=r.title,
                    description=r.description,
                    domain=r.domain,
                    commencement_status=r.commencement_status,
                    commencement_date=r.commencement_date,
                    phase_category=r.phase_category,
                    mandatory=r.mandatory,
                )
                for r in reqs
            ],
        )

    # --------------------------------------------------------------------------
    # Controls & Mappings
    # --------------------------------------------------------------------------

    async def list_controls(
        self,
        db: Optional[AsyncSession] = None,
        tenant_id: str = "default_tenant",
        domain: Optional[str] = None,
    ) -> List[ComplianceControlResponse]:
        """Lists standardized controls."""
        controls = control_catalog.list_controls(domain=domain)
        return [
            ComplianceControlResponse(
                id=c.id,
                title=c.title,
                domain=c.domain,
                description=c.description,
                owner_role=c.owner_role,
                verification_method=c.verification_method,
                review_frequency_days=c.review_frequency_days,
                criticality=c.criticality,
                version=c.version,
                implementation_status=ControlImplementationStatus(c.implementation_status),
                active=c.active,
            )
            for c in controls
        ]

    async def get_control_detail(
        self,
        control_id: str,
        db: Optional[AsyncSession] = None,
        tenant_id: str = "default_tenant",
    ) -> Optional[ComplianceControlDetailResponse]:
        """Retrieves control with associated mappings, latest evidence, and 5-state assurance."""
        c = control_catalog.get_control(control_id)
        if not c:
            return None

        mappings = control_mapping_engine.get_mappings_for_control(c.id)
        mapping_responses = [
            ComplianceControlMappingResponse(
                id=f"map_{m.control_id}_{m.requirement_id}",
                control_id=m.control_id,
                requirement_id=m.requirement_id,
                mapping_type=m.mapping_type,
                rationale=m.rationale,
                coverage_score=m.coverage_score,
            )
            for m in mappings
        ]

        latest_ev_dict = None
        current_assurance = AssuranceLevel.INSUFFICIENT

        if db:
            stmt = (
                select(ComplianceEvidenceRecord)
                .where(
                    ComplianceEvidenceRecord.tenant_id == tenant_id,
                    ComplianceEvidenceRecord.control_id == c.id,
                )
                .order_by(ComplianceEvidenceRecord.collected_at.desc())
            )
            res = await db.execute(stmt)
            ev = res.scalar_one_or_none()

            if ev:
                payload = (
                    json.loads(ev.artifact_payload) if isinstance(ev.artifact_payload, str) else ev.artifact_payload
                )
                freshness = freshness_evaluator.evaluate_freshness(ev.collected_at, ev.expires_at)
                v_status = EvidenceVerificationStatus(ev.verification_status)
                current_assurance = freshness_evaluator.evaluate_assurance_level(
                    implementation_status=ControlImplementationStatus(c.implementation_status),
                    verification_status=v_status,
                    freshness=freshness,
                )

                latest_ev_dict = {
                    "id": ev.id,
                    "collector_name": ev.collector_name,
                    "artifact_hash_sha256": ev.artifact_hash_sha256,
                    "verification_status": ev.verification_status,
                    "freshness_status": freshness.value,
                    "assurance_status": current_assurance.value,
                    "collected_at": ev.collected_at.isoformat() if ev.collected_at else None,
                    "expires_at": ev.expires_at.isoformat() if ev.expires_at else None,
                    "details": payload.get("details", {}),
                }

        return ComplianceControlDetailResponse(
            id=c.id,
            title=c.title,
            domain=c.domain,
            description=c.description,
            owner_role=c.owner_role,
            verification_method=c.verification_method,
            review_frequency_days=c.review_frequency_days,
            criticality=c.criticality,
            version=c.version,
            implementation_status=ControlImplementationStatus(c.implementation_status),
            active=c.active,
            mappings=mapping_responses,
            latest_evidence=latest_ev_dict,
            current_assurance=current_assurance,
        )

    # --------------------------------------------------------------------------
    # Automated Evidence Collection
    # --------------------------------------------------------------------------

    async def collect_evidence(
        self,
        db: AsyncSession,
        tenant_id: str = "default_tenant",
        collector_names: Optional[List[str]] = None,
        force_refresh: bool = False,
    ) -> EvidenceCollectionResult:
        """Executes evidence collectors and commits cryptographically signed artifacts."""
        artifacts = await evidence_collector_engine.run_collectors(
            db=db, tenant_id=tenant_id, collector_names=collector_names
        )

        records: List[ComplianceEvidenceResponse] = []
        verified_count = 0
        failed_count = 0

        # Active evidence signing key ID
        signing_kid = evidence_integrity_service.get_public_verification_key()["kid"]

        for art in artifacts:
            # Sign artifact payload
            canonical_bytes = evidence_integrity_service.hash_structured_payload(art.payload).encode("utf-8")
            from app.key_management.signing import signing_key_manager

            sig_hex, kid_used = signing_key_manager.sign_evidence(canonical_bytes)

            freshness = freshness_evaluator.evaluate_freshness(art.collected_at, art.expires_at)

            rec = ComplianceEvidenceRecord(
                tenant_id=tenant_id,
                control_id=art.control_id,
                collector_name=art.collector_name,
                artifact_type=art.artifact_type,
                artifact_hash_sha256=art.artifact_hash_sha256,
                artifact_payload=json.dumps(art.payload),
                verification_status=art.verification_status.value,
                freshness_status=freshness.value,
                assurance_status=art.assurance_status.value,
                collected_at=art.collected_at,
                expires_at=art.expires_at,
                signing_kid=kid_used,
                signature_hex=sig_hex,
            )
            db.add(rec)
            await db.flush()

            if art.verification_status == EvidenceVerificationStatus.VERIFIED:
                verified_count += 1
            else:
                failed_count += 1

            records.append(
                ComplianceEvidenceResponse(
                    id=rec.id,
                    tenant_id=rec.tenant_id,
                    control_id=rec.control_id,
                    collector_name=rec.collector_name,
                    artifact_type=rec.artifact_type,
                    artifact_hash_sha256=rec.artifact_hash_sha256,
                    artifact_payload=art.payload,
                    verification_status=art.verification_status,
                    freshness_status=freshness,
                    assurance_status=art.assurance_status,
                    collected_at=rec.collected_at,
                    expires_at=rec.expires_at,
                    signing_kid=kid_used,
                    signature_hex=sig_hex,
                )
            )

        await db.commit()

        return EvidenceCollectionResult(
            collected_count=len(records),
            verified_count=verified_count,
            failed_count=failed_count,
            evidence_records=records,
        )

    async def list_evidence(
        self,
        db: AsyncSession,
        tenant_id: str = "default_tenant",
        control_id: Optional[str] = None,
        collector_name: Optional[str] = None,
    ) -> List[ComplianceEvidenceResponse]:
        """Lists evidence records with verified freshness."""
        stmt = (
            select(ComplianceEvidenceRecord)
            .where(ComplianceEvidenceRecord.tenant_id == tenant_id)
            .order_by(ComplianceEvidenceRecord.collected_at.desc())
        )

        if control_id:
            stmt = stmt.where(ComplianceEvidenceRecord.control_id == control_id.strip().upper())
        if collector_name:
            stmt = stmt.where(ComplianceEvidenceRecord.collector_name == collector_name.strip().lower())

        res = await db.execute(stmt)
        rows = res.scalars().all()

        results: List[ComplianceEvidenceResponse] = []
        for r in rows:
            payload = json.loads(r.artifact_payload) if isinstance(r.artifact_payload, str) else r.artifact_payload
            freshness = freshness_evaluator.evaluate_freshness(r.collected_at, r.expires_at)

            results.append(
                ComplianceEvidenceResponse(
                    id=r.id,
                    tenant_id=r.tenant_id,
                    control_id=r.control_id,
                    collector_name=r.collector_name,
                    artifact_type=r.artifact_type,
                    artifact_hash_sha256=r.artifact_hash_sha256,
                    artifact_payload=payload,
                    verification_status=EvidenceVerificationStatus(r.verification_status),
                    freshness_status=freshness,
                    assurance_status=AssuranceLevel(r.assurance_status),
                    collected_at=r.collected_at,
                    expires_at=r.expires_at,
                    signing_kid=r.signing_kid,
                    signature_hex=r.signature_hex,
                )
            )
        return results

    # --------------------------------------------------------------------------
    # Applicability & Gap Analysis
    # --------------------------------------------------------------------------

    async def get_applicability(
        self,
        db: AsyncSession,
        tenant_id: str = "default_tenant",
        framework_id: Optional[str] = None,
    ) -> List[ApplicabilityRecordResponse]:
        """Retrieves tenant applicability decisions."""
        records = await applicability_manager.get_tenant_applicability(db, tenant_id, framework_id)
        return [
            ApplicabilityRecordResponse(
                id=r.id,
                tenant_id=r.tenant_id,
                framework_id=r.framework_id,
                requirement_id=r.requirement_id,
                decision=ApplicabilityDecision(r.decision),
                role=OrganizationRole(r.role),
                justification=r.justification,
                reviewed_by=r.reviewed_by,
                reviewed_at=r.reviewed_at,
            )
            for r in records
        ]

    async def update_applicability(
        self,
        db: AsyncSession,
        tenant_id: str,
        req: ApplicabilityUpdateRequest,
        reviewed_by: str = "compliance_officer",
    ) -> ApplicabilityRecordResponse:
        """Sets or updates tenant applicability scoping."""
        record = await applicability_manager.set_applicability_decision(db, tenant_id, req, reviewed_by)
        return ApplicabilityRecordResponse(
            id=record.id,
            tenant_id=record.tenant_id,
            framework_id=record.framework_id,
            requirement_id=record.requirement_id,
            decision=ApplicabilityDecision(record.decision),
            role=OrganizationRole(record.role),
            justification=record.justification,
            reviewed_by=record.reviewed_by,
            reviewed_at=record.reviewed_at,
        )

    async def run_gap_analysis(
        self,
        db: AsyncSession,
        tenant_id: str = "default_tenant",
        framework_id: Optional[str] = None,
    ) -> ComplianceGapAnalysisResponse:
        """Executes full compliance gap analysis for a tenant."""
        return await gap_analyzer.analyze_gaps(db=db, tenant_id=tenant_id, framework_id=framework_id)

    # --------------------------------------------------------------------------
    # Cryptographic Export Packaging
    # --------------------------------------------------------------------------

    async def generate_export(
        self,
        db: AsyncSession,
        tenant_id: str,
        export_req: EvidenceExportRequest,
        created_by: str = "compliance_officer",
    ) -> EvidenceExportResponse:
        """Packages, signs, and snapshots a compliance export."""
        # Query tenant evidence
        stmt = select(ComplianceEvidenceRecord).where(ComplianceEvidenceRecord.tenant_id == tenant_id)
        res = await db.execute(stmt)
        evidence_records = list(res.scalars().all())

        # Query applicability records
        app_records = await applicability_manager.get_tenant_applicability(db, tenant_id, export_req.framework_id)

        # Generate ZIP archive
        zip_bytes, manifest_sha256, sig_hex, kid = evidence_export_packager.export_as_zip_archive(
            tenant_id=tenant_id,
            framework_id=export_req.framework_id,
            evidence_records=evidence_records,
            applicability_records=app_records,
        )

        # Save snapshot file to local storage or export directory
        export_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", "exports", "compliance"))
        os.makedirs(export_dir, exist_ok=True)

        filename = f"privguard_evidence_{tenant_id}_{export_req.framework_id or 'all'}_{uuid.uuid4().hex[:8]}.zip"
        file_path = os.path.join(export_dir, filename)
        with open(file_path, "wb") as f:
            f.write(zip_bytes)

        snapshot = ComplianceExportSnapshot(
            tenant_id=tenant_id,
            framework_id=export_req.framework_id,
            export_format=export_req.export_format.value,
            manifest_hash_sha256=manifest_sha256,
            signing_kid=kid,
            signature_hex=sig_hex,
            artifact_count=len(evidence_records),
            package_size_bytes=len(zip_bytes),
            storage_path=file_path,
            created_by=created_by,
        )
        db.add(snapshot)
        await db.commit()
        await db.refresh(snapshot)

        return EvidenceExportResponse(
            export_id=snapshot.id,
            tenant_id=snapshot.tenant_id,
            framework_id=snapshot.framework_id,
            export_format=ExportFormat(snapshot.export_format),
            manifest_hash_sha256=snapshot.manifest_hash_sha256,
            signing_kid=snapshot.signing_kid,
            signature_hex=snapshot.signature_hex,
            artifact_count=snapshot.artifact_count,
            package_size_bytes=snapshot.package_size_bytes,
            download_url=f"/v1/compliance/exports/{snapshot.id}/download",
            created_at=snapshot.created_at,
        )

    def get_public_signing_key(self, kid: Optional[str] = None) -> EvidencePublicKeyResponse:
        """Returns public key metadata and PEM for unauthenticated third-party verification."""
        meta = evidence_integrity_service.get_public_verification_key(kid)
        return EvidencePublicKeyResponse(**meta)


# Global singleton compliance service
compliance_service = ComplianceService()

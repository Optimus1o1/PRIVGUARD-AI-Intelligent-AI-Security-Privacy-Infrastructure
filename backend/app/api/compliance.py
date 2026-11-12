"""Compliance Evidence Engine API Endpoints for PRIVGUARD AI (Stage 10.9).

Provides:
- GET /v1/compliance/frameworks (Strictly read-only)
- GET /v1/compliance/frameworks/{framework_id} (Strictly read-only)
- GET /v1/compliance/controls (Strictly read-only)
- GET /v1/compliance/controls/{control_id} (Strictly read-only)
- GET /v1/compliance/mappings (Strictly read-only)
- POST /v1/compliance/evidence/collect
- GET /v1/compliance/evidence (Strictly read-only)
- GET /v1/compliance/evidence/{evidence_id}/verify (Strictly read-only)
- GET /v1/compliance/gaps (Strictly read-only)
- GET /v1/compliance/applicability (Strictly read-only)
- PATCH /v1/compliance/applicability (Reviewer RBAC)
- POST /v1/compliance/exports
- GET /v1/compliance/exports/{export_id}/download
- GET /v1/compliance/signing-keys/public (Unauthenticated third-party auditor verification)
"""

import os
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.authentication import get_current_app
from app.database.connection import get_db_session
from app.database.models import Application
from app.compliance.control_mapping import control_mapping_engine
from app.compliance.evidence_integrity import evidence_integrity_service
from app.compliance.models import ComplianceEvidenceRecord, ComplianceExportSnapshot
from app.compliance.schemas import (
    ApplicabilityRecordResponse,
    ApplicabilityUpdateRequest,
    ComplianceControlDetailResponse,
    ComplianceControlMappingResponse,
    ComplianceControlResponse,
    ComplianceEvidenceResponse,
    ComplianceFrameworkDetailResponse,
    ComplianceFrameworkResponse,
    ComplianceGapAnalysisResponse,
    EvidenceCollectionRequest,
    EvidenceCollectionResult,
    EvidenceExportRequest,
    EvidenceExportResponse,
    EvidencePublicKeyResponse,
)
from app.compliance.service import compliance_service

router = APIRouter(prefix="/v1/compliance", tags=["Compliance Evidence Engine"])


# ------------------------------------------------------------------------------
# 1. Frameworks & Requirements (Strictly Read-Only)
# ------------------------------------------------------------------------------


@router.get("/frameworks", response_model=List[ComplianceFrameworkResponse])
async def list_frameworks(
    current_app: Application = Depends(get_current_app),
) -> List[ComplianceFrameworkResponse]:
    """Lists registered compliance frameworks with statutory commencement statuses and coverage."""
    return compliance_service.list_frameworks()


@router.get("/frameworks/{framework_id}", response_model=ComplianceFrameworkDetailResponse)
async def get_framework(
    framework_id: str,
    current_app: Application = Depends(get_current_app),
) -> ComplianceFrameworkDetailResponse:
    """Retrieves full framework specification with all statutory clauses and commencement phases."""
    fw = compliance_service.get_framework_detail(framework_id)
    if not fw:
        raise HTTPException(status_code=404, detail=f"Compliance framework '{framework_id}' not found.")
    return fw


# ------------------------------------------------------------------------------
# 2. Controls & Mappings (Strictly Read-Only)
# ------------------------------------------------------------------------------


@router.get("/controls", response_model=List[ComplianceControlResponse])
async def list_controls(
    domain: Optional[str] = Query(None, description="Filter controls by functional domain"),
    db: AsyncSession = Depends(get_db_session),
    current_app: Application = Depends(get_current_app),
) -> List[ComplianceControlResponse]:
    """Lists standardized internal PRIVGUARD controls (PG-CONTROL-001..035)."""
    return await compliance_service.list_controls(db=db, tenant_id=current_app.tenant_id, domain=domain)


@router.get("/controls/{control_id}", response_model=ComplianceControlDetailResponse)
async def get_control(
    control_id: str,
    db: AsyncSession = Depends(get_db_session),
    current_app: Application = Depends(get_current_app),
) -> ComplianceControlDetailResponse:
    """Retrieves control details, framework crosswalk mappings, and current 5-state assurance."""
    ctrl = await compliance_service.get_control_detail(control_id=control_id, db=db, tenant_id=current_app.tenant_id)
    if not ctrl:
        raise HTTPException(status_code=404, detail=f"Control '{control_id}' not found.")
    return ctrl


@router.get("/mappings", response_model=List[ComplianceControlMappingResponse])
async def list_mappings(
    control_id: Optional[str] = Query(None, description="Filter by internal control ID"),
    requirement_id: Optional[str] = Query(None, description="Filter by framework requirement ID"),
    current_app: Application = Depends(get_current_app),
) -> List[ComplianceControlMappingResponse]:
    """Lists bi-directional crosswalk mappings between technical controls and statutory clauses."""
    all_mappings = control_mapping_engine.list_all_mappings()
    if control_id:
        all_mappings = [m for m in all_mappings if m.control_id.upper() == control_id.strip().upper()]
    if requirement_id:
        all_mappings = [m for m in all_mappings if m.requirement_id.upper() == requirement_id.strip().upper()]

    return [
        ComplianceControlMappingResponse(
            id=f"map_{m.control_id}_{m.requirement_id}",
            control_id=m.control_id,
            requirement_id=m.requirement_id,
            mapping_type=m.mapping_type,
            rationale=m.rationale,
            coverage_score=m.coverage_score,
        )
        for m in all_mappings
    ]


# ------------------------------------------------------------------------------
# 3. Evidence Vault & Automated Collection
# ------------------------------------------------------------------------------


@router.post("/evidence/collect", response_model=EvidenceCollectionResult)
async def collect_evidence(
    req: EvidenceCollectionRequest = EvidenceCollectionRequest(),
    db: AsyncSession = Depends(get_db_session),
    current_app: Application = Depends(get_current_app),
) -> EvidenceCollectionResult:
    """Triggers automated execution of modular evidence collectors for active tenant."""
    return await compliance_service.collect_evidence(
        db=db,
        tenant_id=current_app.tenant_id,
        collector_names=req.collectors,
        force_refresh=req.force_refresh,
    )


@router.get("/evidence", response_model=List[ComplianceEvidenceResponse])
async def list_evidence(
    control_id: Optional[str] = Query(None, description="Filter by control ID"),
    collector: Optional[str] = Query(None, description="Filter by collector name"),
    db: AsyncSession = Depends(get_db_session),
    current_app: Application = Depends(get_current_app),
) -> List[ComplianceEvidenceResponse]:
    """Lists cryptographically fingerprinted evidence vault records for the caller tenant."""
    return await compliance_service.list_evidence(
        db=db,
        tenant_id=current_app.tenant_id,
        control_id=control_id,
        collector_name=collector,
    )


@router.get("/evidence/{evidence_id}/verify")
async def verify_evidence_artifact(
    evidence_id: str,
    db: AsyncSession = Depends(get_db_session),
    current_app: Application = Depends(get_current_app),
) -> Dict[str, Any]:
    """Verifies the RFC 8785 canonical SHA-256 fingerprint of an evidence artifact."""
    stmt = select(ComplianceEvidenceRecord).where(
        ComplianceEvidenceRecord.id == evidence_id,
        ComplianceEvidenceRecord.tenant_id == current_app.tenant_id,
    )
    res = await db.execute(stmt)
    record = res.scalar_one_or_none()
    if not record:
        raise HTTPException(status_code=404, detail=f"Evidence artifact '{evidence_id}' not found.")

    import json

    payload = (
        json.loads(record.artifact_payload) if isinstance(record.artifact_payload, str) else record.artifact_payload
    )
    computed_hash = evidence_integrity_service.hash_structured_payload(payload)
    is_valid = computed_hash == record.artifact_hash_sha256

    return {
        "evidence_id": record.id,
        "control_id": record.control_id,
        "recorded_hash_sha256": record.artifact_hash_sha256,
        "computed_hash_sha256": computed_hash,
        "integrity_verified": is_valid,
        "verification_status": record.verification_status,
        "freshness_status": record.freshness_status,
        "assurance_status": record.assurance_status,
    }


# ------------------------------------------------------------------------------
# 4. Gap Analysis (Strictly Read-Only)
# ------------------------------------------------------------------------------


@router.get("/gaps", response_model=ComplianceGapAnalysisResponse)
async def get_compliance_gaps(
    framework_id: Optional[str] = Query(None, description="Optional target framework filter"),
    db: AsyncSession = Depends(get_db_session),
    current_app: Application = Depends(get_current_app),
) -> ComplianceGapAnalysisResponse:
    """Executes multi-dimensional compliance gap analysis across statutory frameworks."""
    return await compliance_service.run_gap_analysis(db=db, tenant_id=current_app.tenant_id, framework_id=framework_id)


# ------------------------------------------------------------------------------
# 5. Applicability Layer
# ------------------------------------------------------------------------------


@router.get("/applicability", response_model=List[ApplicabilityRecordResponse])
async def get_applicability(
    framework_id: Optional[str] = Query(None, description="Filter by framework"),
    db: AsyncSession = Depends(get_db_session),
    current_app: Application = Depends(get_current_app),
) -> List[ApplicabilityRecordResponse]:
    """Retrieves tenant applicability decisions and role determinations."""
    return await compliance_service.get_applicability(db=db, tenant_id=current_app.tenant_id, framework_id=framework_id)


@router.patch("/applicability", response_model=ApplicabilityRecordResponse)
async def update_applicability(
    req: ApplicabilityUpdateRequest,
    db: AsyncSession = Depends(get_db_session),
    current_app: Application = Depends(get_current_app),
) -> ApplicabilityRecordResponse:
    """Updates applicability scoping or role determination for a framework/requirement."""
    return await compliance_service.update_applicability(
        db=db, tenant_id=current_app.tenant_id, req=req, reviewed_by=current_app.name
    )


# ------------------------------------------------------------------------------
# 6. Cryptographic Export Packaging
# ------------------------------------------------------------------------------


@router.post("/exports", response_model=EvidenceExportResponse)
async def create_compliance_export(
    export_req: EvidenceExportRequest = EvidenceExportRequest(),
    db: AsyncSession = Depends(get_db_session),
    current_app: Application = Depends(get_current_app),
) -> EvidenceExportResponse:
    """Generates a cryptographically signed, sanitized compliance evidence package."""
    return await compliance_service.generate_export(
        db=db,
        tenant_id=current_app.tenant_id,
        export_req=export_req,
        created_by=current_app.name,
    )


@router.get("/exports/{export_id}/download")
async def download_compliance_export(
    export_id: str,
    db: AsyncSession = Depends(get_db_session),
    current_app: Application = Depends(get_current_app),
):
    """Downloads signed audit package ZIP archive."""
    stmt = select(ComplianceExportSnapshot).where(
        ComplianceExportSnapshot.id == export_id,
        ComplianceExportSnapshot.tenant_id == current_app.tenant_id,
    )
    res = await db.execute(stmt)
    snapshot = res.scalar_one_or_none()

    if not snapshot or not snapshot.storage_path or not os.path.isfile(snapshot.storage_path):
        raise HTTPException(status_code=404, detail=f"Export package '{export_id}' not found.")

    filename = os.path.basename(snapshot.storage_path)
    return FileResponse(
        path=snapshot.storage_path,
        media_type="application/zip",
        filename=filename,
    )


# ------------------------------------------------------------------------------
# 7. Unauthenticated Third-Party Auditor Public Key Export
# ------------------------------------------------------------------------------


@router.get("/signing-keys/public", response_model=EvidencePublicKeyResponse)
async def get_public_signing_key() -> EvidencePublicKeyResponse:
    """
    Exports Ed25519 SubjectPublicKeyInfo PEM and key metadata.
    Unauthenticated to allow independent third-party audit verification without PRIVGUARD access.
    """
    return compliance_service.get_public_signing_key()

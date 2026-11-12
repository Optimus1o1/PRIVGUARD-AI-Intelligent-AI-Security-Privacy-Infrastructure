"""Pydantic V2 schemas for PRIVGUARD AI Compliance Evidence Engine (Stage 10.9)."""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


# ------------------------------------------------------------------------------
# 5-State Assurance Separation Enums
# ------------------------------------------------------------------------------


class ControlImplementationStatus(str, Enum):
    """Whether the underlying technical mechanism is built and enabled in code."""

    IMPLEMENTED = "IMPLEMENTED"
    PARTIALLY_IMPLEMENTED = "PARTIALLY_IMPLEMENTED"
    NOT_IMPLEMENTED = "NOT_IMPLEMENTED"
    NOT_ASSESSED = "NOT_ASSESSED"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class EvidenceVerificationStatus(str, Enum):
    """Whether recent cryptographic and operational validation tests passed."""

    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    UNKNOWN = "UNKNOWN"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"


class EvidenceFreshness(str, Enum):
    """Whether evidence is within its operational Time-To-Live (TTL)."""

    CURRENT = "CURRENT"
    STALE = "STALE"
    EXPIRED = "EXPIRED"


class AssuranceLevel(str, Enum):
    """Overall operational audit assurance derived from implementation + verified freshness."""

    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INSUFFICIENT = "INSUFFICIENT"


class ApplicabilityDecision(str, Enum):
    """Scoped organizational applicability determination."""

    APPLICABLE = "APPLICABLE"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    REQUIRES_REVIEW = "REQUIRES_REVIEW"


class MappingType(str, Enum):
    """Degree of satisfaction between internal control and regulatory requirement."""

    DIRECT = "DIRECT"
    PARTIAL = "PARTIAL"
    SUPPORTING = "SUPPORTING"
    NOT_MAPPED = "NOT_MAPPED"


class CommencementStatus(str, Enum):
    """Statutory enforceability status for a requirement or rule provision."""

    COMMENCED = "COMMENCED"
    PENDING_COMMENCEMENT = "PENDING_COMMENCEMENT"
    EXEMPTED = "EXEMPTED"


class ExportFormat(str, Enum):
    """Export package format."""

    ZIP = "ZIP"
    JSON = "JSON"
    CSV = "CSV"


class OrganizationRole(str, Enum):
    """Regulated role played by the deploying entity."""

    DATA_FIDUCIARY = "DATA_FIDUCIARY"
    DATA_PROCESSOR = "DATA_PROCESSOR"
    AI_DEPLOYER = "AI_DEPLOYER"
    AI_PROVIDER = "AI_PROVIDER"
    CONTROLLER = "CONTROLLER"


# ------------------------------------------------------------------------------
# Framework & Requirement Schemas
# ------------------------------------------------------------------------------


class ComplianceRequirementResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    framework_id: str
    identifier: str
    title: str
    description: str
    domain: str
    commencement_status: CommencementStatus
    commencement_date: Optional[datetime] = None
    phase_category: Optional[str] = None
    mandatory: bool = True


class ComplianceFrameworkResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    version: str
    jurisdiction: str
    authority: str
    description: str
    official_reference: str
    status: str
    commenced_at: Optional[datetime] = None
    total_requirements: int = 0
    commenced_requirements: int = 0
    mapped_requirements: int = 0


class ComplianceFrameworkDetailResponse(ComplianceFrameworkResponse):
    requirements: List[ComplianceRequirementResponse] = Field(default_factory=list)


# ------------------------------------------------------------------------------
# Control & Mapping Schemas
# ------------------------------------------------------------------------------


class ComplianceControlMappingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    control_id: str
    requirement_id: str
    mapping_type: MappingType
    rationale: str
    coverage_score: float
    verified_by: Optional[str] = None


class ComplianceControlResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    title: str
    domain: str
    description: str
    owner_role: str
    verification_method: str
    review_frequency_days: int
    criticality: str
    version: str
    implementation_status: ControlImplementationStatus
    active: bool


class ComplianceControlDetailResponse(ComplianceControlResponse):
    mappings: List[ComplianceControlMappingResponse] = Field(default_factory=list)
    latest_evidence: Optional[Dict[str, Any]] = None
    current_assurance: AssuranceLevel = AssuranceLevel.INSUFFICIENT


# ------------------------------------------------------------------------------
# Evidence & Verification Schemas
# ------------------------------------------------------------------------------


class ComplianceEvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    control_id: str
    collector_name: str
    artifact_type: str
    artifact_hash_sha256: str
    artifact_payload: Dict[str, Any]
    verification_status: EvidenceVerificationStatus
    freshness_status: EvidenceFreshness
    assurance_status: AssuranceLevel
    collected_at: datetime
    expires_at: datetime
    signing_kid: Optional[str] = None
    signature_hex: Optional[str] = None


class EvidenceCollectionRequest(BaseModel):
    collectors: Optional[List[str]] = None  # None = run all collectors
    force_refresh: bool = False


class EvidenceCollectionResult(BaseModel):
    collected_count: int
    verified_count: int
    failed_count: int
    evidence_records: List[ComplianceEvidenceResponse] = Field(default_factory=list)


# ------------------------------------------------------------------------------
# 5-State Assessment Schemas
# ------------------------------------------------------------------------------


class ComplianceAssessmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    control_id: str
    control_implementation_status: ControlImplementationStatus
    evidence_verification_status: EvidenceVerificationStatus
    evidence_freshness: EvidenceFreshness
    assurance_status: AssuranceLevel
    applicability_decision: ApplicabilityDecision
    assessed_by: str
    assessed_at: datetime
    notes: Optional[str] = None


# ------------------------------------------------------------------------------
# Applicability Schemas
# ------------------------------------------------------------------------------


class ApplicabilityRecordResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    tenant_id: str
    framework_id: str
    requirement_id: Optional[str] = None
    decision: ApplicabilityDecision
    role: OrganizationRole
    justification: str
    reviewed_by: str
    reviewed_at: datetime


class ApplicabilityUpdateRequest(BaseModel):
    framework_id: str
    requirement_id: Optional[str] = None
    decision: ApplicabilityDecision
    role: OrganizationRole
    justification: str


# ------------------------------------------------------------------------------
# Gap Analysis Schemas
# ------------------------------------------------------------------------------


class ComplianceGapItem(BaseModel):
    gap_type: str  # UNMAPPED_REQUIREMENT, MISSING_EVIDENCE, FAILED_EVIDENCE, STALE_EVIDENCE, PARTIAL_MAPPING
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    requirement_id: Optional[str] = None
    control_id: Optional[str] = None
    title: str
    description: str
    remediation_action: str


class ComplianceGapAnalysisResponse(BaseModel):
    tenant_id: str
    evaluated_at: datetime
    total_gaps: int
    critical_gaps: int
    high_gaps: int
    medium_gaps: int
    low_gaps: int
    items: List[ComplianceGapItem] = Field(default_factory=list)


# ------------------------------------------------------------------------------
# Public Key & Signing Schemas
# ------------------------------------------------------------------------------


class EvidencePublicKeyResponse(BaseModel):
    kid: str
    algorithm: str
    purpose: str
    public_key_hex: str
    public_key_pem: str
    fingerprint_sha256: str
    status: str


# ------------------------------------------------------------------------------
# Export Schemas & Signed Manifest
# ------------------------------------------------------------------------------


class EvidenceExportRequest(BaseModel):
    framework_id: Optional[str] = None
    export_format: ExportFormat = ExportFormat.ZIP
    include_raw_artifacts: bool = True


class SignedManifest(BaseModel):
    manifest_version: str = "1.0"
    tenant_id: str
    framework_id: Optional[str] = None
    product_name: str = "PRIVGUARD AI"
    product_version: str
    generated_at: str
    signing_kid: str
    signature: Optional[str] = None
    artifact_hashes: Dict[str, str] = Field(default_factory=dict)
    summary: Dict[str, Any] = Field(default_factory=dict)
    disclaimer: str = (
        "LEGAL DISCLAIMER: This compliance evidence package provides cryptographically verified "
        "technical enforcement artifacts for the identified software controls. It does not constitute "
        "statutory legal certification or an independent third-party audit opinion. Legal compliance "
        "requires formal assessment by accredited counsel or licensed auditing bodies."
    )


class EvidenceExportResponse(BaseModel):
    export_id: str
    tenant_id: str
    framework_id: Optional[str] = None
    export_format: ExportFormat
    manifest_hash_sha256: str
    signing_kid: str
    signature_hex: str
    artifact_count: int
    package_size_bytes: int
    download_url: str
    created_at: datetime


# ------------------------------------------------------------------------------
# Strict Allowlisted Evidence Metadata Schemas (Defense-in-Depth)
# ------------------------------------------------------------------------------


class AllowlistedEvidencePayload(BaseModel):
    """Base schema enforcing zero secret / PII leakage."""

    model_config = ConfigDict(extra="forbid")

    collector: str
    target_subsystem: str
    technical_assertion: str
    verification_passed: bool
    details: Dict[str, Any]
    evaluated_at: str

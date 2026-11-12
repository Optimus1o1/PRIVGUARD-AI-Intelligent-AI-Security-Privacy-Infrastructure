"""Compliance evidence engine models for PRIVGUARD SDK."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from privguard_sdk.types import ExportFormat


class ComplianceFrameworkResponse(BaseModel):
    """Statutory or security compliance framework definition."""

    id: str
    name: str
    version: str
    jurisdiction: str
    authority: str
    status: str
    total_requirements: int
    mapped_requirements: int
    coverage_percentage: float


class ComplianceControlResponse(BaseModel):
    """Standardized PRIVGUARD internal control specification."""

    id: str
    domain: str
    title: str
    description: str
    criticality: str
    owner_role: str
    active: bool = True


class ComplianceEvidenceRecordResponse(BaseModel):
    """Automated, cryptographically hashed compliance evidence record."""

    id: str
    control_id: str
    evidence_type: str
    collected_at: datetime
    valid_until: datetime
    assurance_level: str
    freshness: str
    sha256_fingerprint: str
    payload_summary: dict[str, Any] = Field(default_factory=dict)


class ComplianceGapAnalysisResponse(BaseModel):
    """Automated gap analysis report."""

    framework_id: str
    overall_coverage_percentage: float
    total_requirements: int
    gaps: list[dict[str, Any]] = Field(default_factory=list)


class EvidencePublicKeyResponse(BaseModel):
    """Public verification key metadata."""

    kid: str
    purpose: str
    algorithm: str
    public_key_hex: str
    public_key_pem: str
    is_active: bool
    created_at: datetime


class EvidenceExportRequest(BaseModel):
    """Request payload to generate a signed compliance export snapshot."""

    format: ExportFormat = Field(default=ExportFormat.ZIP)
    framework_ids: list[str] | None = None
    include_artifacts: bool = Field(True, description="Whether to include full hashed artifacts in ZIP")


class EvidenceExportResponse(BaseModel):
    """Export snapshot status and download metadata."""

    export_id: str
    format: str
    status: str
    download_url: str
    manifest: dict[str, Any] = Field(default_factory=dict)
    expires_at: datetime

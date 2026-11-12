"""SQLAlchemy ORM models for PRIVGUARD AI Compliance Evidence Engine (Stage 10.9)."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text, ForeignKey, Index
from app.database.connection import Base
from app.database.models import ensure_utc, utcnow


class ComplianceFramework(Base):
    """Registered regulatory compliance or governance framework."""

    __tablename__ = "compliance_frameworks"

    id = Column(
        String(64), primary_key=True
    )  # e.g., "dpdp-2023", "dpdp-rules-2025", "eu-ai-act", "nist-ai-100-1", "nist-privacy-1-0", "iso-27001-2022", "soc2-tsc"
    name = Column(String(128), nullable=False)
    version = Column(String(32), nullable=False)
    jurisdiction = Column(String(64), nullable=False)  # India, EU, US, Global
    authority = Column(String(128), nullable=False)  # MeitY, European Commission, NIST, ISO/IEC, AICPA
    description = Column(Text, nullable=False)
    official_reference = Column(String(255), nullable=False)
    status = Column(String(32), default="ACTIVE", nullable=False)  # ACTIVE, DRAFT, RETIRED
    commenced_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class ComplianceRequirement(Base):
    """Specific statutory clause, rule provision, or framework requirement."""

    __tablename__ = "compliance_requirements"

    id = Column(
        String(96), primary_key=True
    )  # e.g., "DPDP-SEC-4", "DPDP-R4-SAFEGUARDS", "EU-AI-ART-50", "NIST-AI-GV-1", "SOC2-CC6.1"
    framework_id = Column(String(64), ForeignKey("compliance_frameworks.id"), nullable=False, index=True)
    identifier = Column(
        String(64), nullable=False, index=True
    )  # e.g., "Section 4", "Rule 4", "Art. 50(2)", "A.8.24", "CC6.1"
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    domain = Column(String(64), nullable=False, index=True)  # Security, Privacy, Governance, Transparency, etc.
    commencement_status = Column(
        String(32), default="COMMENCED", nullable=False
    )  # COMMENCED, PENDING_COMMENCEMENT, EXEMPTED
    commencement_date = Column(DateTime(timezone=True), nullable=True)
    phase_category = Column(
        String(64), nullable=True
    )  # e.g. "immediate_1_year", "one_year_rule4", "eighteen_months_rule3_etc", "feb_2025_prohibited", "aug_2025_gpai", "aug_2026_general", "dec_2026_standards", "dec_2027_annex3", "aug_2028_annex1"
    mandatory = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class ComplianceControl(Base):
    """Standardized internal PRIVGUARD technical control (PG-CONTROL-001..035)."""

    __tablename__ = "compliance_controls"

    id = Column(String(32), primary_key=True)  # PG-CONTROL-001 to PG-CONTROL-035
    title = Column(String(160), nullable=False)
    domain = Column(String(64), nullable=False, index=True)  # One of the 20 functional domains
    description = Column(Text, nullable=False)
    owner_role = Column(String(64), nullable=False, default="security_engineer")
    verification_method = Column(String(32), default="AUTOMATED", nullable=False)  # AUTOMATED, HYBRID, MANUAL
    review_frequency_days = Column(Integer, default=30, nullable=False)
    criticality = Column(String(16), default="HIGH", nullable=False)  # CRITICAL, HIGH, MEDIUM, LOW
    version = Column(String(16), default="1.0", nullable=False)
    implementation_status = Column(
        String(32), default="IMPLEMENTED", nullable=False
    )  # IMPLEMENTED, PARTIALLY_IMPLEMENTED, NOT_IMPLEMENTED, NOT_ASSESSED, NOT_APPLICABLE
    active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow, nullable=False)


class ComplianceControlMapping(Base):
    """Many-to-many relationship mapping internal controls to framework requirements."""

    __tablename__ = "compliance_control_mappings"

    id = Column(String(64), primary_key=True, default=lambda: f"map_{uuid.uuid4().hex[:16]}")
    control_id = Column(String(32), ForeignKey("compliance_controls.id"), nullable=False, index=True)
    requirement_id = Column(String(96), ForeignKey("compliance_requirements.id"), nullable=False, index=True)
    mapping_type = Column(String(32), default="DIRECT", nullable=False)  # DIRECT, PARTIAL, SUPPORTING, NOT_MAPPED
    rationale = Column(Text, nullable=False)
    coverage_score = Column(Float, default=1.0, nullable=False)  # 1.0 (DIRECT), 0.6 (PARTIAL), 0.3 (SUPPORTING)
    verified_by = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class ComplianceEvidenceRecord(Base):
    """Cryptographically fingerprinted, allowlisted technical evidence artifact."""

    __tablename__ = "compliance_evidence_records"

    id = Column(String(64), primary_key=True, default=lambda: f"ev_{uuid.uuid4().hex[:16]}")
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

    control_id = Column(String(32), ForeignKey("compliance_controls.id"), nullable=False, index=True)
    collector_name = Column(String(64), nullable=False, index=True)  # canary, policy, rls, kms, supply_chain, chaos
    artifact_type = Column(String(32), default="JSON", nullable=False)  # JSON, LOG, REPORT, CONFIG
    artifact_hash_sha256 = Column(String(64), nullable=False, index=True)  # RFC 8785 canonical hash
    artifact_payload = Column(Text, nullable=False)  # Allowlisted JSON metadata (zero secrets/PII)

    # 5-State Assurance Model
    verification_status = Column(
        String(32), default="VERIFIED", nullable=False
    )  # VERIFIED, FAILED, UNKNOWN, REQUIRES_REVIEW
    freshness_status = Column(String(32), default="CURRENT", nullable=False)  # CURRENT, STALE, EXPIRED
    assurance_status = Column(String(32), default="HIGH", nullable=False)  # HIGH, MEDIUM, LOW, INSUFFICIENT

    collected_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    signing_kid = Column(String(64), nullable=True)
    signature_hex = Column(String(128), nullable=True)


class ComplianceAssessment(Base):
    """Point-in-time control assessment separating implementation from operational assurance."""

    __tablename__ = "compliance_assessments"

    id = Column(String(64), primary_key=True, default=lambda: f"asm_{uuid.uuid4().hex[:16]}")
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

    control_id = Column(String(32), ForeignKey("compliance_controls.id"), nullable=False, index=True)

    # Five-State Assurance Separation
    control_implementation_status = Column(
        String(32), default="IMPLEMENTED", nullable=False
    )  # IMPLEMENTED, PARTIALLY_IMPLEMENTED, etc.
    evidence_verification_status = Column(
        String(32), default="VERIFIED", nullable=False
    )  # VERIFIED, FAILED, UNKNOWN, REQUIRES_REVIEW
    evidence_freshness = Column(String(32), default="CURRENT", nullable=False)  # CURRENT, STALE, EXPIRED
    assurance_status = Column(String(32), default="HIGH", nullable=False)  # HIGH, MEDIUM, LOW, INSUFFICIENT
    applicability_decision = Column(
        String(32), default="APPLICABLE", nullable=False
    )  # APPLICABLE, NOT_APPLICABLE, REQUIRES_REVIEW

    assessed_by = Column(String(64), default="system", nullable=False)
    assessed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    notes = Column(Text, nullable=True)


class ComplianceApplicabilityRecord(Base):
    """Tenant-scoped applicability scoping and legal role assignment."""

    __tablename__ = "compliance_applicability_records"

    id = Column(String(64), primary_key=True, default=lambda: f"app_{uuid.uuid4().hex[:16]}")
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

    framework_id = Column(String(64), ForeignKey("compliance_frameworks.id"), nullable=False, index=True)
    requirement_id = Column(String(96), nullable=True, index=True)  # None = entire framework level
    decision = Column(String(32), default="APPLICABLE", nullable=False)  # APPLICABLE, NOT_APPLICABLE, REQUIRES_REVIEW
    role = Column(
        String(64), default="DATA_FIDUCIARY", nullable=False
    )  # DATA_FIDUCIARY, DATA_PROCESSOR, AI_DEPLOYER, AI_PROVIDER, CONTROLLER
    justification = Column(Text, nullable=False)
    reviewed_by = Column(String(64), default="compliance_officer", nullable=False)
    reviewed_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class ComplianceExportSnapshot(Base):
    """Cryptographic audit export package snapshot metadata."""

    __tablename__ = "compliance_export_snapshots"

    id = Column(String(64), primary_key=True, default=lambda: f"exp_{uuid.uuid4().hex[:16]}")
    tenant_id = Column(String(64), nullable=False, default="default_tenant", index=True)
    workspace_id = Column(String(64), nullable=True, index=True)

    framework_id = Column(String(64), nullable=True)
    export_format = Column(String(16), default="ZIP", nullable=False)  # ZIP, JSON, CSV
    manifest_hash_sha256 = Column(String(64), nullable=False)
    signing_kid = Column(String(64), nullable=False)
    signature_hex = Column(String(128), nullable=False)
    artifact_count = Column(Integer, default=0, nullable=False)
    package_size_bytes = Column(Integer, default=0, nullable=False)
    storage_path = Column(String(255), nullable=True)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    created_by = Column(String(64), default="system", nullable=False)

"""Control Mapping Engine for PRIVGUARD AI (Stage 10.9).

Maps standardized internal controls (PG-CONTROL-001..035) to statutory requirements across:
- India DPDP Act, 2023 & DPDP Rules, 2025
- EU AI Act (Regulation (EU) 2024/1689)
- NIST AI Risk Management Framework 1.0 (NIST AI 100-1)
- NIST Privacy Framework 1.0
- ISO/IEC 27001:2022
- SOC 2 Trust Services Criteria (5 Categories)
"""

from typing import Dict, List, Optional
from pydantic import BaseModel
from app.compliance.schemas import MappingType


class MappingDefinition(BaseModel):
    control_id: str
    requirement_id: str
    mapping_type: MappingType
    rationale: str
    coverage_score: float  # 1.0 (DIRECT), 0.6 (PARTIAL), 0.3 (SUPPORTING)


STANDARD_MAPPINGS: List[MappingDefinition] = [
    # --------------------------------------------------------------------------
    # DPDP Act, 2023 Mappings
    # --------------------------------------------------------------------------
    MappingDefinition(
        control_id="PG-CONTROL-001",
        requirement_id="DPDP-ACT-SEC-8-5",
        mapping_type=MappingType.DIRECT,
        rationale="API key cryptographic hashing prevents credential exposure in database storage, directly fulfilling reasonable security safeguard duties.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-003",
        requirement_id="DPDP-ACT-SEC-8-5",
        mapping_type=MappingType.DIRECT,
        rationale="8-Role enterprise RBAC restricts administrative and data access to authorized roles only.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-005",
        requirement_id="DPDP-ACT-SEC-8-5",
        mapping_type=MappingType.DIRECT,
        rationale="PostgreSQL FORCE RLS guarantees cross-tenant digital personal data isolation at the storage tier.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-007",
        requirement_id="DPDP-ACT-SEC-8-5",
        mapping_type=MappingType.DIRECT,
        rationale="Deterministic PII detection and format-preserving token substitution prevents unminimized personal data exposure to upstream third parties.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-009",
        requirement_id="DPDP-ACT-SEC-8-5",
        mapping_type=MappingType.DIRECT,
        rationale="AES-256-GCM envelope encryption protects digital personal data at rest with per-record DEKs.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-010",
        requirement_id="DPDP-ACT-SEC-8-7",
        mapping_type=MappingType.DIRECT,
        rationale="Cryptographic erasure destroys the DEK of long-term memory records, fulfilling statutory erasure duties upon consent withdrawal.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-010",
        requirement_id="DPDP-ACT-SEC-12",
        mapping_type=MappingType.DIRECT,
        rationale="Enforces data principal right to erasure via instantaneous cryptographic key destruction.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-011",
        requirement_id="DPDP-ACT-SEC-6",
        mapping_type=MappingType.DIRECT,
        rationale="Human consent gate prevents agent memory persistence without explicit, affirmative data principal consent.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-021",
        requirement_id="DPDP-ACT-SEC-16",
        mapping_type=MappingType.PARTIAL,
        rationale="Monotonic taint tracking enforces outbound network sink constraints, preventing unauthorized data exfiltration across borders.",
        coverage_score=0.6,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-023",
        requirement_id="DPDP-ACT-SEC-8-6",
        mapping_type=MappingType.SUPPORTING,
        rationale="Tamper-evident hash-chained audit log provides verifiable forensics for breach investigation and board reporting.",
        coverage_score=0.3,
    ),
    # --------------------------------------------------------------------------
    # DPDP Rules, 2025 Mappings
    # --------------------------------------------------------------------------
    MappingDefinition(
        control_id="PG-CONTROL-023",
        requirement_id="DPDP-R4-SAFEGUARDS-LOGGING",
        mapping_type=MappingType.DIRECT,
        rationale="Cryptographic append-only chained audit ledger satisfies technical logging and tamper-evident event recording requirements.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-009",
        requirement_id="DPDP-R4-SAFEGUARDS-LOGGING",
        mapping_type=MappingType.DIRECT,
        rationale="AES-256-GCM encryption at rest directly satisfies Rule 4 technical security safeguard mandates.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-011",
        requirement_id="DPDP-R5-CONSENT-MANAGERS",
        mapping_type=MappingType.PARTIAL,
        rationale="Human consent gate and proposal staging provides integration hook for external Consent Managers, fulfilling technical consent staging.",
        coverage_score=0.6,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-022",
        requirement_id="DPDP-R22-CROSS-BORDER",
        mapping_type=MappingType.PARTIAL,
        rationale="Outbound network sink filtering restricts network egress to allowlisted regional endpoints.",
        coverage_score=0.6,
    ),
    # --------------------------------------------------------------------------
    # EU AI Act Mappings
    # --------------------------------------------------------------------------
    MappingDefinition(
        control_id="PG-CONTROL-015",
        requirement_id="EU-AI-ART-14",
        mapping_type=MappingType.DIRECT,
        rationale="HMAC action hash anti-tampering ensures human reviewers have immutable control over high-risk actions, fulfilling Article 14 human oversight.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-016",
        requirement_id="EU-AI-ART-14",
        mapping_type=MappingType.DIRECT,
        rationale="High-risk tool authorization gate requires human confirmation prior to dispatch, guaranteeing effective human intervention.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-023",
        requirement_id="EU-AI-ART-12",
        mapping_type=MappingType.DIRECT,
        rationale="Tamper-evident chained audit ledger automatically logs agent invocations, capability grants, and policy evaluations throughout system lifecycle.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-019",
        requirement_id="EU-AI-ART-5",
        mapping_type=MappingType.DIRECT,
        rationale="Deterministic prompt injection detection prevents subversion of system boundaries and rejection of prohibited manipulation patterns.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-020",
        requirement_id="EU-AI-ART-50",
        mapping_type=MappingType.SUPPORTING,
        rationale="Content boundary tagging and sanitization ensures generated and ingested content retains provenance metadata for transparency.",
        coverage_score=0.3,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-029",
        requirement_id="EU-AI-ART-51-53",
        mapping_type=MappingType.PARTIAL,
        rationale="CycloneDX 1.6 machine-readable SBOMs capture dependency and model artifact provenance required for GPAI documentation.",
        coverage_score=0.6,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-034",
        requirement_id="EU-AI-ANNEX-III",
        mapping_type=MappingType.PARTIAL,
        rationale="Execution step quotas and runaway task revocation mitigate high-risk AI loop exhaustion in Annex III critical workflows.",
        coverage_score=0.6,
    ),
    # --------------------------------------------------------------------------
    # NIST AI RMF 1.0 (NIST AI 100-1) Mappings
    # --------------------------------------------------------------------------
    MappingDefinition(
        control_id="PG-CONTROL-027",
        requirement_id="NIST-AI-GV-1",
        mapping_type=MappingType.DIRECT,
        rationale="Ed25519-signed policy bundles codify organizational AI governance rules into tamper-evident machine-enforceable controls.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-002",
        requirement_id="NIST-AI-MP-2",
        mapping_type=MappingType.DIRECT,
        rationale="Agent identity registration and ownership scoping delineates system boundaries and environmental interaction contexts.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-032",
        requirement_id="NIST-AI-MS-2",
        mapping_type=MappingType.DIRECT,
        rationale="Continuous synthetic canaries quantitatively measure and evaluate system safety, injection defense, and capability boundaries.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-013",
        requirement_id="NIST-AI-MG-1",
        mapping_type=MappingType.DIRECT,
        rationale="Revocable scoped capability tokens prioritize risk mitigation by enforcing fine-grained least-privilege tool execution.",
        coverage_score=1.0,
    ),
    # --------------------------------------------------------------------------
    # NIST Privacy Framework 1.0 Mappings
    # --------------------------------------------------------------------------
    MappingDefinition(
        control_id="PG-CONTROL-007",
        requirement_id="NIST-PR-CT-DM",
        mapping_type=MappingType.DIRECT,
        rationale="Deterministic PII token substitution implements automated data minimization and disassociation before LLM processing.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-009",
        requirement_id="NIST-PR-PR-DS",
        mapping_type=MappingType.DIRECT,
        rationale="AES-256-GCM envelope encryption and KMS key lifecycle manage data-at-rest cryptographic protections.",
        coverage_score=1.0,
    ),
    # --------------------------------------------------------------------------
    # ISO/IEC 27001:2022 Mappings
    # --------------------------------------------------------------------------
    MappingDefinition(
        control_id="PG-CONTROL-003",
        requirement_id="ISO-A-5-15",
        mapping_type=MappingType.DIRECT,
        rationale="8-Role enterprise RBAC implements comprehensive logical access control based on business requirements.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-021",
        requirement_id="ISO-A-8-12",
        mapping_type=MappingType.DIRECT,
        rationale="Monotonic taint tracking and outbound sink control apply data leakage prevention against exfiltration.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-023",
        requirement_id="ISO-A-8-15",
        mapping_type=MappingType.DIRECT,
        rationale="Tamper-evident append-only chained audit ledger produces, stores, and protects security activity logs.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-025",
        requirement_id="ISO-A-8-24",
        mapping_type=MappingType.DIRECT,
        rationale="Provider-independent KMS abstraction and envelope encryption define and implement effective cryptography management.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-030",
        requirement_id="ISO-A-8-28",
        mapping_type=MappingType.DIRECT,
        rationale="SLSA Level 3 provenance and Cosign signature verification enforce secure coding and build supply chain integrity.",
        coverage_score=1.0,
    ),
    # --------------------------------------------------------------------------
    # SOC 2 Trust Services Criteria Mappings (5 Categories)
    # --------------------------------------------------------------------------
    MappingDefinition(
        control_id="PG-CONTROL-003",
        requirement_id="SOC2-CC-6-1",
        mapping_type=MappingType.DIRECT,
        rationale="Enterprise RBAC and session scoping satisfy logical access software security controls.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-017",
        requirement_id="SOC2-CC-6-6",
        mapping_type=MappingType.DIRECT,
        rationale="MCP SSRF destination protection and private network blocking enforce logical boundaries against unauthorized ingestion.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-032",
        requirement_id="SOC2-CC-7-2",
        mapping_type=MappingType.DIRECT,
        rationale="Continuous synthetic canaries monitor system components for behavioral anomalies and policy subversions.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-033",
        requirement_id="SOC2-A-1-2",
        mapping_type=MappingType.DIRECT,
        rationale="ASGI request size limits (10 MB) and bounded streaming chunk buffers protect system availability against resource exhaustion.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-014",
        requirement_id="SOC2-PI-1-1",
        mapping_type=MappingType.DIRECT,
        rationale="Atomic CAS anti-replay primitives ensure processing integrity and transaction completeness for capability tokens.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-009",
        requirement_id="SOC2-C-1-1",
        mapping_type=MappingType.DIRECT,
        rationale="AES-256-GCM envelope encryption identifies confidential memory records and prevents unauthorized disclosure.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-011",
        requirement_id="SOC2-P-3-1",
        mapping_type=MappingType.DIRECT,
        rationale="Human consent gate ensures personal information is stored only with affirmative consent.",
        coverage_score=1.0,
    ),
    MappingDefinition(
        control_id="PG-CONTROL-007",
        requirement_id="SOC2-P-6-1",
        mapping_type=MappingType.DIRECT,
        rationale="Format-preserving PII token substitution safeguards personal information against unauthorized exposure to upstream services.",
        coverage_score=1.0,
    ),
]


class ControlMappingEngine:
    """Query and evaluation engine for bi-directional control mappings."""

    def __init__(self) -> None:
        self._mappings_by_control: Dict[str, List[MappingDefinition]] = {}
        self._mappings_by_requirement: Dict[str, List[MappingDefinition]] = {}
        for m in STANDARD_MAPPINGS:
            self._mappings_by_control.setdefault(m.control_id, []).append(m)
            self._mappings_by_requirement.setdefault(m.requirement_id, []).append(m)

    def get_mappings_for_control(self, control_id: str) -> List[MappingDefinition]:
        """Returns all framework requirement mappings for an internal control."""
        return self._mappings_by_control.get(control_id.strip().upper(), [])

    def get_mappings_for_requirement(self, requirement_id: str) -> List[MappingDefinition]:
        """Returns all internal controls satisfying a specific requirement."""
        return self._mappings_by_requirement.get(requirement_id.strip().upper(), [])

    def list_all_mappings(self) -> List[MappingDefinition]:
        """Returns all registered standard mappings."""
        return STANDARD_MAPPINGS

    def compute_framework_coverage(self, requirement_ids: List[str]) -> Dict[str, float]:
        """
        Computes coverage metrics for a set of framework requirements.
        Returns: {total_requirements, mapped_requirements, coverage_percentage}
        """
        if not requirement_ids:
            return {"total_requirements": 0, "mapped_requirements": 0, "coverage_percentage": 0.0}

        mapped_count = 0
        score_sum = 0.0
        for req_id in requirement_ids:
            mappings = self.get_mappings_for_requirement(req_id)
            if mappings:
                mapped_count += 1
                best_score = max(m.coverage_score for m in mappings)
                score_sum += best_score

        total = len(requirement_ids)
        pct = round((score_sum / total) * 100.0, 1) if total > 0 else 0.0
        return {
            "total_requirements": total,
            "mapped_requirements": mapped_count,
            "coverage_percentage": pct,
        }


# Global singleton mapping engine
control_mapping_engine = ControlMappingEngine()

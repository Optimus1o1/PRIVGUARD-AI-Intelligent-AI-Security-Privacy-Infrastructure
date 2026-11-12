"""Standardized PRIVGUARD Control Catalog (20 Functional Domains, 35 Controls).

Provides authoritative, immutable definitions for PG-CONTROL-001 through PG-CONTROL-035.
"""

from typing import Dict, List, Optional
from pydantic import BaseModel


class ControlDefinition(BaseModel):
    id: str
    title: str
    domain: str
    description: str
    owner_role: str
    verification_method: str
    review_frequency_days: int
    criticality: str
    version: str = "1.0"
    implementation_status: str = "IMPLEMENTED"
    active: bool = True


PRIVGUARD_CONTROLS: List[ControlDefinition] = [
    # Domain 1: Identity & Authentication
    ControlDefinition(
        id="PG-CONTROL-001",
        title="Application API Key Cryptographic Hashing",
        domain="Identity & Authentication",
        description="All application API credentials are authenticated using salted SHA-256 digests. Raw API keys are never stored in plaintext within the persistent database.",
        owner_role="security_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=30,
        criticality="CRITICAL",
    ),
    ControlDefinition(
        id="PG-CONTROL-002",
        title="Agent Identity Registration & Ownership Scoping",
        domain="Identity & Authentication",
        description="Every executing autonomous agent must possess a unique cryptographic identity bound to an authenticated parent Application entity.",
        owner_role="security_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=30,
        criticality="HIGH",
    ),
    # Domain 2: Authorization & RBAC
    ControlDefinition(
        id="PG-CONTROL-003",
        title="8-Role Enterprise Role-Based Access Control",
        domain="Authorization & RBAC",
        description="Enforces strict least privilege across 8 standardized enterprise roles with granular permission scopes verified at request boundaries.",
        owner_role="security_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=30,
        criticality="CRITICAL",
    ),
    ControlDefinition(
        id="PG-CONTROL-004",
        title="Separation of Duties & Policy Administration Boundary",
        domain="Authorization & RBAC",
        description="Administrative policy modifications require specialized compliance reviewer roles, preventing single-actor privilege escalation.",
        owner_role="compliance_officer",
        verification_method="AUTOMATED",
        review_frequency_days=30,
        criticality="HIGH",
    ),
    # Domain 3: Multi-Tenancy & Data Isolation
    ControlDefinition(
        id="PG-CONTROL-005",
        title="PostgreSQL Row-Level Security (FORCE RLS)",
        domain="Multi-Tenancy & Data Isolation",
        description="PostgreSQL tables enforce strict tenant isolation via Row-Level Security policies with non-bypassable non-superuser database connections.",
        owner_role="database_admin",
        verification_method="AUTOMATED",
        review_frequency_days=7,
        criticality="CRITICAL",
    ),
    ControlDefinition(
        id="PG-CONTROL-006",
        title="Connection Pool Session Tenant Context Scoping",
        domain="Multi-Tenancy & Data Isolation",
        description="Every incoming request binds an isolated tenant context variable that configures session-level database connection parameters before query dispatch.",
        owner_role="database_admin",
        verification_method="AUTOMATED",
        review_frequency_days=14,
        criticality="CRITICAL",
    ),
    # Domain 4: Privacy & PII Minimization
    ControlDefinition(
        id="PG-CONTROL-007",
        title="Deterministic PII Detection & Token Substitution",
        domain="Privacy & PII Minimization",
        description="Sensitive identifiers (names, emails, phones, SSNs, Aadhaar, credit cards) are intercepted and masked with format-preserving surrogate tokens prior to upstream LLM forwarding.",
        owner_role="privacy_officer",
        verification_method="AUTOMATED",
        review_frequency_days=14,
        criticality="CRITICAL",
    ),
    ControlDefinition(
        id="PG-CONTROL-008",
        title="Reversible De-Redaction on Downstream Responses",
        domain="Privacy & PII Minimization",
        description="Surrogate tokens returned from model completions are safely de-redacted using tenant-isolated ephemeral key stores before final delivery to authorized callers.",
        owner_role="privacy_officer",
        verification_method="AUTOMATED",
        review_frequency_days=14,
        criticality="HIGH",
    ),
    # Domain 5: Personal AI Memory Vault
    ControlDefinition(
        id="PG-CONTROL-009",
        title="Personal AI Memory Vault AES-256-GCM Envelope Encryption",
        domain="Personal AI Memory Vault",
        description="Long-term agent memories are encrypted at rest using AES-256-GCM envelope encryption with per-record Data Encryption Keys (DEKs) wrapped by master Key Encryption Keys (KEKs).",
        owner_role="security_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=14,
        criticality="CRITICAL",
    ),
    ControlDefinition(
        id="PG-CONTROL-010",
        title="Cryptographic Erasure & DEK Destruction (Right to be Forgotten)",
        domain="Personal AI Memory Vault",
        description="Right-to-be-forgotten deletion requests execute cryptographic erasure by immediately destroying the memory record's wrapped DEK, rendering ciphertext unrecoverable.",
        owner_role="privacy_officer",
        verification_method="AUTOMATED",
        review_frequency_days=30,
        criticality="CRITICAL",
    ),
    # Domain 6: Consent & Proposal Staging
    ControlDefinition(
        id="PG-CONTROL-011",
        title="Human Consent Gate for Long-Term Memory Storage",
        domain="Consent & Proposal Staging",
        description="Autonomous agents cannot write permanent memories without an explicit, verifiable human consent grant staged through an asynchronous proposal workflow.",
        owner_role="privacy_officer",
        verification_method="AUTOMATED",
        review_frequency_days=30,
        criticality="HIGH",
    ),
    ControlDefinition(
        id="PG-CONTROL-012",
        title="Memory Poisoning & Directive Override Scanning",
        domain="Consent & Proposal Staging",
        description="All proposed memory updates undergo pre-commit semantic analysis to detect and reject indirect prompt injection and behavioral instruction subversions.",
        owner_role="security_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=14,
        criticality="CRITICAL",
    ),
    # Domain 7: Agent Execution Governance
    ControlDefinition(
        id="PG-CONTROL-013",
        title="Revocable Scoped Capability Tokens",
        domain="Agent Execution Governance",
        description="Agent tool execution is gated by short-lived cryptographic capability tokens restricting specific tool, method, and target resource invocations.",
        owner_role="security_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=14,
        criticality="CRITICAL",
    ),
    ControlDefinition(
        id="PG-CONTROL-014",
        title="Atomic CAS Anti-Replay Capability Protection",
        domain="Agent Execution Governance",
        description="Capability token consumption uses atomic Compare-And-Swap (CAS) database primitives to prevent race conditions and token replay attacks.",
        owner_role="security_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=14,
        criticality="CRITICAL",
    ),
    # Domain 8: Human-in-the-Loop Approvals
    ControlDefinition(
        id="PG-CONTROL-015",
        title="HMAC Action Hash Anti-Tampering for Human Approvals",
        domain="Human-in-the-Loop Approvals",
        description="Human approval requests cryptographically bind tool parameters using versioned HMAC-SHA256 digests. Any parameter mutation between approval and execution triggers rejection.",
        owner_role="security_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=14,
        criticality="CRITICAL",
    ),
    ControlDefinition(
        id="PG-CONTROL-016",
        title="High-Risk Action Authorization Gate",
        domain="Human-in-the-Loop Approvals",
        description="Critical and high-risk agent operations (fund transfers, data modification, credential export) fail closed pending authenticated human approval.",
        owner_role="compliance_officer",
        verification_method="AUTOMATED",
        review_frequency_days=30,
        criticality="CRITICAL",
    ),
    # Domain 9: MCP Security Gateway
    ControlDefinition(
        id="PG-CONTROL-017",
        title="Model Context Protocol (MCP) SSRF Destination Protection",
        domain="MCP Security Gateway",
        description="MCP server connections undergo DNS rebinding checks and private network blocking to prevent Server-Side Request Forgery against cloud metadata or internal endpoints.",
        owner_role="security_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=14,
        criticality="CRITICAL",
    ),
    ControlDefinition(
        id="PG-CONTROL-018",
        title="MCP Tool Description Poisoning & Schema Drift Quarantine",
        domain="MCP Security Gateway",
        description="Dynamic tool schemas are fingerprinted on registration. Unannounced schema alterations or directive injections in tool documentation trigger automatic quarantine.",
        owner_role="security_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=14,
        criticality="HIGH",
    ),
    # Domain 10: Prompt Injection Defense
    ControlDefinition(
        id="PG-CONTROL-019",
        title="Deterministic Direct Prompt Injection Detection",
        domain="Prompt Injection Defense",
        description="Inbound user and agent prompts are inspected using deterministic heuristic rule engines to detect delimiter hijacking, role reversal, and escape attempts.",
        owner_role="security_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=14,
        criticality="CRITICAL",
    ),
    ControlDefinition(
        id="PG-CONTROL-020",
        title="Untrusted Data Content Sanitization & Boundary Isolation",
        domain="Prompt Injection Defense",
        description="Data ingested from external APIs, web searches, or files is wrapped in strict boundary delimiters and neutralized before prompt construction.",
        owner_role="security_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=14,
        criticality="HIGH",
    ),
    # Domain 11: Data Exfiltration Defense
    ControlDefinition(
        id="PG-CONTROL-021",
        title="Monotonic Taint Tracking for Data Exfiltration (MITRE T1700)",
        domain="Data Exfiltration Defense",
        description="Data retrieved from sensitive internal sources carries a non-downgradable taint flag preventing subsequent transfer to unapproved external network sinks.",
        owner_role="security_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=14,
        criticality="CRITICAL",
    ),
    ControlDefinition(
        id="PG-CONTROL-022",
        title="Outbound Network Sink Enforcement",
        domain="Data Exfiltration Defense",
        description="Agents are prohibited from initiating direct arbitrary network connections; egress is restricted to explicit allowlisted domain endpoints.",
        owner_role="security_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=14,
        criticality="CRITICAL",
    ),
    # Domain 12: Audit Trail Integrity
    ControlDefinition(
        id="PG-CONTROL-023",
        title="Tamper-Evident SHA-256 Chained Audit Ledger",
        domain="Audit Trail Integrity",
        description="All security-relevant actions are committed to an append-only audit log where every entry includes the SHA-256 hash of the preceding entry, forming a verifiable hash chain.",
        owner_role="compliance_officer",
        verification_method="AUTOMATED",
        review_frequency_days=7,
        criticality="CRITICAL",
    ),
    ControlDefinition(
        id="PG-CONTROL-024",
        title="Zero-Content Audit Storage Invariant",
        domain="Audit Trail Integrity",
        description="Audit entries store strictly allowlisted metadata, cryptographic hashes, and outcome codes. Raw prompts, model completions, and PII are never persisted in the audit ledger.",
        owner_role="privacy_officer",
        verification_method="AUTOMATED",
        review_frequency_days=14,
        criticality="CRITICAL",
    ),
    # Domain 13: Cryptographic Key Management
    ControlDefinition(
        id="PG-CONTROL-025",
        title="Provider-Independent KMS Abstraction",
        domain="Cryptographic Key Management",
        description="Master encryption keys are managed through a unified KMS provider interface supporting Local, AWS KMS, GCP KMS, Azure Key Vault, and HashiCorp Vault.",
        owner_role="security_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=30,
        criticality="CRITICAL",
    ),
    ControlDefinition(
        id="PG-CONTROL-026",
        title="Non-Destructive Key Rotation & Versioning",
        domain="Cryptographic Key Management",
        description="Key rotation generates a new active KeyVersion without destroying historical keys, allowing older ciphertexts to be safely decrypted and lazily re-wrapped.",
        owner_role="security_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=30,
        criticality="HIGH",
    ),
    # Domain 14: Policy Governance & Signing
    ControlDefinition(
        id="PG-CONTROL-027",
        title="Ed25519-Signed Governance Policy Bundles",
        domain="Policy Governance & Signing",
        description="Enterprise governance policies are cryptographically signed using Ed25519 private keys. Unsigned or corrupted policies are rejected at runtime.",
        owner_role="compliance_officer",
        verification_method="AUTOMATED",
        review_frequency_days=14,
        criticality="CRITICAL",
    ),
    ControlDefinition(
        id="PG-CONTROL-028",
        title="Anti-Downgrade Policy Version Enforcement",
        domain="Policy Governance & Signing",
        description="Policy version numbers must strictly increment; the policy engine rejects attempted deployments of older policy versions to prevent downgrade attacks.",
        owner_role="compliance_officer",
        verification_method="AUTOMATED",
        review_frequency_days=30,
        criticality="HIGH",
    ),
    # Domain 15: Software Supply Chain
    ControlDefinition(
        id="PG-CONTROL-029",
        title="CycloneDX 1.6 Machine-Readable SBOMs",
        domain="Software Supply Chain",
        description="Every container image and software release artifact includes an automated CycloneDX 1.6 Software Bill of Materials detailing full dependency provenance.",
        owner_role="security_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=30,
        criticality="HIGH",
    ),
    ControlDefinition(
        id="PG-CONTROL-030",
        title="SLSA Level 3 Provenance & Cosign Signature Verification",
        domain="Software Supply Chain",
        description="Release artifacts are verified against SLSA v1.0 Level 3 build provenance and signed using Sigstore Cosign keys before production deployment.",
        owner_role="security_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=30,
        criticality="CRITICAL",
    ),
    # Domain 16: Vulnerability Management
    ControlDefinition(
        id="PG-CONTROL-031",
        title="Automated Dependency & Container Vulnerability Gates",
        domain="Vulnerability Management",
        description="CI/CD pipelines enforce automated vulnerability scanning via Trivy, pip-audit, and npm audit, blocking releases with unpatched Critical or High findings.",
        owner_role="security_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=14,
        criticality="CRITICAL",
    ),
    # Domain 17: Zero-Content Observability
    ControlDefinition(
        id="PG-CONTROL-032",
        title="Continuous Synthetic Security Canaries",
        domain="Zero-Content Observability",
        description="A suite of 8 synthetic canary tests continuously probe critical security boundaries (injection, redaction, capability, tamper) verifying fail-closed enforcement.",
        owner_role="devops_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=7,
        criticality="CRITICAL",
    ),
    # Domain 18: Edge Resource Bounding
    ControlDefinition(
        id="PG-CONTROL-033",
        title="ASGI Request Size & Streaming Chunk Bounding",
        domain="Edge Resource Bounding",
        description="HTTP reverse proxies and ASGI middleware strictly enforce a 10 MB maximum request payload and bound streaming chunk buffers to mitigate resource exhaustion.",
        owner_role="devops_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=30,
        criticality="HIGH",
    ),
    # Domain 19: Execution Budget & Runaway Defense
    ControlDefinition(
        id="PG-CONTROL-034",
        title="Policy-Configurable Agent Step Quotas & Auto-Revocation",
        domain="Execution Budget & Runaway Defense",
        description="Agent tasks enforce bounded execution step limits configurable by administrative policy. Exceeding the step quota immediately terminates the task and revokes tokens.",
        owner_role="security_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=14,
        criticality="CRITICAL",
    ),
    # Domain 20: Disaster Recovery & Outbox Durability
    ControlDefinition(
        id="PG-CONTROL-035",
        title="Transactional Outbox & Dead-Letter Isolation",
        domain="Disaster Recovery & Outbox Durability",
        description="Cross-service events are persisted in a database transactional outbox table before broker dispatch. Failed events are isolated into dead-letter storage without data loss.",
        owner_role="devops_engineer",
        verification_method="AUTOMATED",
        review_frequency_days=30,
        criticality="HIGH",
    ),
]


class ControlCatalog:
    """Query and management facade for the 35 PRIVGUARD controls."""

    def __init__(self) -> None:
        self._controls_by_id: Dict[str, ControlDefinition] = {ctrl.id: ctrl for ctrl in PRIVGUARD_CONTROLS}

    def list_controls(
        self,
        domain: Optional[str] = None,
        criticality: Optional[str] = None,
    ) -> List[ControlDefinition]:
        """Returns all controls matching optional domain and criticality filters."""
        res = list(self._controls_by_id.values())
        if domain:
            res = [c for c in res if c.domain.lower() == domain.lower()]
        if criticality:
            res = [c for c in res if c.criticality.upper() == criticality.upper()]
        return res

    def get_control(self, control_id: str) -> Optional[ControlDefinition]:
        """Looks up a control by its stable ID (e.g. 'PG-CONTROL-001')."""
        return self._controls_by_id.get(control_id.strip().upper())

    def list_domains(self) -> List[str]:
        """Returns distinct functional domains in catalog order."""
        domains: List[str] = []
        for c in PRIVGUARD_CONTROLS:
            if c.domain not in domains:
                domains.append(c.domain)
        return domains


# Global singleton catalog
control_catalog = ControlCatalog()

"""Statutory and Governance Framework Registry for PRIVGUARD AI (Stage 10.9).

Accurately models phased commencement timelines, statutory authority, and requirement definitions
for DPDP Act/Rules, EU AI Act, NIST AI 100-1, NIST Privacy 1.0, ISO 27001:2022, and SOC 2 TSC.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from pydantic import BaseModel
from app.compliance.schemas import CommencementStatus


class RequirementDefinition(BaseModel):
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


class FrameworkDefinition(BaseModel):
    id: str
    name: str
    version: str
    jurisdiction: str
    authority: str
    description: str
    official_reference: str
    status: str = "ACTIVE"
    commenced_at: Optional[datetime] = None
    requirements: List[RequirementDefinition]


# ------------------------------------------------------------------------------
# 1. India DPDP Act, 2023 (Modeled at Section Level)
# ------------------------------------------------------------------------------
DPDP_ACT_2023 = FrameworkDefinition(
    id="dpdp-2023",
    name="Digital Personal Data Protection Act, 2023",
    version="Act No. 22 of 2023",
    jurisdiction="India",
    authority="Ministry of Electronics and Information Technology (MeitY)",
    description="Primary Indian data protection legislation governing digital personal data processing, rights of data principals, and obligations of data fiduciaries.",
    official_reference="The Gazette of India, CG-DL-E-12082023-248045",
    commenced_at=datetime(2023, 8, 11, tzinfo=timezone.utc),
    requirements=[
        RequirementDefinition(
            id="DPDP-ACT-SEC-4",
            framework_id="dpdp-2023",
            identifier="Section 4",
            title="Grounds for Processing Personal Data",
            description="Personal data shall only be processed for lawful purposes with affirmative consent or certain legitimate uses.",
            domain="Consent & Purpose",
            commencement_status=CommencementStatus.COMMENCED,
            commencement_date=datetime(2023, 8, 11, tzinfo=timezone.utc),
            phase_category="statutory_enactment",
        ),
        RequirementDefinition(
            id="DPDP-ACT-SEC-6",
            framework_id="dpdp-2023",
            identifier="Section 6",
            title="Consent Requirements & Notice",
            description="Consent must be free, specific, informed, unconditional, and unambiguous with clear affirmative action.",
            domain="Consent & Purpose",
            commencement_status=CommencementStatus.COMMENCED,
            commencement_date=datetime(2023, 8, 11, tzinfo=timezone.utc),
            phase_category="statutory_enactment",
        ),
        RequirementDefinition(
            id="DPDP-ACT-SEC-8-5",
            framework_id="dpdp-2023",
            identifier="Section 8(5)",
            title="Reasonable Security Safeguards",
            description="A Data Fiduciary must protect personal data in its possession or under its control by taking reasonable security safeguards to prevent personal data breach.",
            domain="Security Safeguards",
            commencement_status=CommencementStatus.COMMENCED,
            commencement_date=datetime(2023, 8, 11, tzinfo=timezone.utc),
            phase_category="statutory_enactment",
        ),
        RequirementDefinition(
            id="DPDP-ACT-SEC-8-6",
            framework_id="dpdp-2023",
            identifier="Section 8(6)",
            title="Personal Data Breach Notification",
            description="In the event of a personal data breach, the Data Fiduciary shall notify the Data Protection Board and affected Data Principals.",
            domain="Breach Management",
            commencement_status=CommencementStatus.COMMENCED,
            commencement_date=datetime(2023, 8, 11, tzinfo=timezone.utc),
            phase_category="statutory_enactment",
        ),
        RequirementDefinition(
            id="DPDP-ACT-SEC-8-7",
            framework_id="dpdp-2023",
            identifier="Section 8(7)",
            title="Erasure upon Purpose Fulfillment",
            description="A Data Fiduciary must erase personal data upon withdrawal of consent or as soon as reasonable to assume the specified purpose is no longer served.",
            domain="Data Erasure & Retention",
            commencement_status=CommencementStatus.COMMENCED,
            commencement_date=datetime(2023, 8, 11, tzinfo=timezone.utc),
            phase_category="statutory_enactment",
        ),
        RequirementDefinition(
            id="DPDP-ACT-SEC-10",
            framework_id="dpdp-2023",
            identifier="Section 10",
            title="Significant Data Fiduciary Additional Obligations",
            description="Designated Significant Data Fiduciaries must appoint a resident DPO, independent data auditor, and conduct Data Protection Impact Assessments (DPIA).",
            domain="Governance & Accountability",
            commencement_status=CommencementStatus.COMMENCED,
            commencement_date=datetime(2023, 8, 11, tzinfo=timezone.utc),
            phase_category="statutory_enactment",
        ),
        RequirementDefinition(
            id="DPDP-ACT-SEC-12",
            framework_id="dpdp-2023",
            identifier="Section 12",
            title="Right to Correction and Erasure of Personal Data",
            description="Data Principals have the statutory right to correction, completion, updating, and erasure of their personal data.",
            domain="Principal Rights",
            commencement_status=CommencementStatus.COMMENCED,
            commencement_date=datetime(2023, 8, 11, tzinfo=timezone.utc),
            phase_category="statutory_enactment",
        ),
        RequirementDefinition(
            id="DPDP-ACT-SEC-16",
            framework_id="dpdp-2023",
            identifier="Section 16",
            title="Cross-Border Transfer of Personal Data",
            description="Transfer of personal data outside India is permitted except to countries or territories restricted by Central Government notification.",
            domain="Data Localization & Transfer",
            commencement_status=CommencementStatus.COMMENCED,
            commencement_date=datetime(2023, 8, 11, tzinfo=timezone.utc),
            phase_category="statutory_enactment",
        ),
    ],
)

# ------------------------------------------------------------------------------
# 2. India DPDP Rules, 2025 (Three Distinct Commencement Milestones)
# ------------------------------------------------------------------------------
DPDP_RULES_2025 = FrameworkDefinition(
    id="dpdp-rules-2025",
    name="Digital Personal Data Protection Rules, 2025",
    version="Draft/Final Rules Notification 2025",
    jurisdiction="India",
    authority="Ministry of Electronics and Information Technology (MeitY)",
    description="Subordinate procedural regulations establishing implementation standards across 3 phased commencement tiers.",
    official_reference="MeitY Notification under Section 40 of the DPDP Act, 2023",
    commenced_at=datetime(2025, 11, 13, tzinfo=timezone.utc),
    requirements=[
        # Phase 1: 13 November 2025 (Rules 1, 2, 17-21)
        RequirementDefinition(
            id="DPDP-R1-PRELIMINARY",
            framework_id="dpdp-rules-2025",
            identifier="Rule 1",
            title="Short Title and Commencement",
            description="Preliminary definitions and phased commencement provisions.",
            domain="Statutory Framework",
            commencement_status=CommencementStatus.COMMENCED,
            commencement_date=datetime(2025, 11, 13, tzinfo=timezone.utc),
            phase_category="immediate_phase_nov_2025",
        ),
        RequirementDefinition(
            id="DPDP-R17-BOARD-PROCEDURE",
            framework_id="dpdp-rules-2025",
            identifier="Rule 17",
            title="Data Protection Board Digital Inquiry Procedure",
            description="Digital-by-design complaint filing, electronic summons, and techno-legal inquiries before the Data Protection Board.",
            domain="Dispute & Inquiry",
            commencement_status=CommencementStatus.COMMENCED,
            commencement_date=datetime(2025, 11, 13, tzinfo=timezone.utc),
            phase_category="immediate_phase_nov_2025",
        ),
        # Phase 2: 13 November 2026 (Rule 4 Security Safeguards & Breach Reporting)
        RequirementDefinition(
            id="DPDP-R4-SAFEGUARDS-LOGGING",
            framework_id="dpdp-rules-2025",
            identifier="Rule 4",
            title="Technical Safeguards, Logging & Breach Reporting",
            description="Technical encryption, access control, audit logging, and mandatory 6-hour intimation standards for data breaches.",
            domain="Security Safeguards",
            commencement_status=CommencementStatus.PENDING_COMMENCEMENT,
            commencement_date=datetime(2026, 11, 13, tzinfo=timezone.utc),
            phase_category="one_year_rule4_nov_2026",
        ),
        # Phase 3: 13 May 2027 (Rules 3, 5-16, 22-23 - Notice, Consent, Rights, Transfers)
        RequirementDefinition(
            id="DPDP-R3-NOTICE-STANDARDS",
            framework_id="dpdp-rules-2025",
            identifier="Rule 3",
            title="Detailed Notice & Multilingual Itemization Standards",
            description="Itemized notice specifications disclosing goods/services, exact data categories, processing purpose, DPO contact, and multilingual delivery.",
            domain="Notice & Transparency",
            commencement_status=CommencementStatus.PENDING_COMMENCEMENT,
            commencement_date=datetime(2027, 5, 13, tzinfo=timezone.utc),
            phase_category="eighteen_months_may_2027",
        ),
        RequirementDefinition(
            id="DPDP-R5-CONSENT-MANAGERS",
            framework_id="dpdp-rules-2025",
            identifier="Rule 5",
            title="Consent Architecture & Consent Manager Integration",
            description="Standardized interoperable digital interfaces for registered Consent Managers and accessible withdrawal protocols.",
            domain="Consent & Choice",
            commencement_status=CommencementStatus.PENDING_COMMENCEMENT,
            commencement_date=datetime(2027, 5, 13, tzinfo=timezone.utc),
            phase_category="eighteen_months_may_2027",
        ),
        RequirementDefinition(
            id="DPDP-R7-CHILD-CONSENT",
            framework_id="dpdp-rules-2025",
            identifier="Rule 7",
            title="Verifiable Parental Consent & Child Protection",
            description="Mechanisms for verifying age and parental consent; prohibition of behavioral tracking or targeted advertising directed at children.",
            domain="Children Data",
            commencement_status=CommencementStatus.PENDING_COMMENCEMENT,
            commencement_date=datetime(2027, 5, 13, tzinfo=timezone.utc),
            phase_category="eighteen_months_may_2027",
        ),
        RequirementDefinition(
            id="DPDP-R10-GRIEVANCE",
            framework_id="dpdp-rules-2025",
            identifier="Rule 10",
            title="Time-Bound Grievance Redressal Mechanism",
            description="Data Fiduciaries must acknowledge and resolve data principal grievances within the mandated maximum 72-hour or 7-day windows.",
            domain="Grievance Redressal",
            commencement_status=CommencementStatus.PENDING_COMMENCEMENT,
            commencement_date=datetime(2027, 5, 13, tzinfo=timezone.utc),
            phase_category="eighteen_months_may_2027",
        ),
        RequirementDefinition(
            id="DPDP-R22-CROSS-BORDER",
            framework_id="dpdp-rules-2025",
            identifier="Rule 22",
            title="Cross-Border Data Transfer Restrictive Lists",
            description="Compliance with notified negative lists for cross-border data transfer and compliance audit disclosures.",
            domain="Data Localization & Transfer",
            commencement_status=CommencementStatus.PENDING_COMMENCEMENT,
            commencement_date=datetime(2027, 5, 13, tzinfo=timezone.utc),
            phase_category="eighteen_months_may_2027",
        ),
    ],
)

# ------------------------------------------------------------------------------
# 3. European Union — EU AI Act (Regulation (EU) 2024/1689) (6 Phased Milestones)
# ------------------------------------------------------------------------------
EU_AI_ACT = FrameworkDefinition(
    id="eu-ai-act",
    name="Artificial Intelligence Act (Regulation (EU) 2024/1689)",
    version="Regulation (EU) 2024/1689",
    jurisdiction="European Union",
    authority="European Commission & European AI Office",
    description="Harmonised rules on artificial intelligence establishing risk-based classifications, GPAI rules, and fundamental rights safeguards across 6 enforcement phases.",
    official_reference="OJ L 2024/1689, 12.7.2024",
    commenced_at=datetime(2024, 8, 1, tzinfo=timezone.utc),
    requirements=[
        # Phase 1: 2 February 2025 (Prohibitions & AI Literacy)
        RequirementDefinition(
            id="EU-AI-ART-4",
            framework_id="eu-ai-act",
            identifier="Art. 4",
            title="AI Literacy Requirements",
            description="Providers and deployers shall take measures to ensure their personnel have a sufficient level of AI literacy.",
            domain="Organizational Governance",
            commencement_status=CommencementStatus.COMMENCED,
            commencement_date=datetime(2025, 2, 2, tzinfo=timezone.utc),
            phase_category="feb_2025_prohibited",
        ),
        RequirementDefinition(
            id="EU-AI-ART-5",
            framework_id="eu-ai-act",
            identifier="Art. 5",
            title="Prohibited Artificial Intelligence Practices",
            description="Prohibition of subliminal manipulation, biometric categorization of sensitive traits, social scoring, and untargeted facial scraping.",
            domain="Prohibited AI",
            commencement_status=CommencementStatus.COMMENCED,
            commencement_date=datetime(2025, 2, 2, tzinfo=timezone.utc),
            phase_category="feb_2025_prohibited",
        ),
        # Phase 2: 2 August 2025 (GPAI Obligations & Notifying Authorities)
        RequirementDefinition(
            id="EU-AI-ART-51-53",
            framework_id="eu-ai-act",
            identifier="Art. 51-53",
            title="General-Purpose AI (GPAI) Model Obligations",
            description="Transparency, technical documentation, copyright compliance, and systemic risk mitigation for GPAI models.",
            domain="Foundation Models & GPAI",
            commencement_status=CommencementStatus.COMMENCED,
            commencement_date=datetime(2025, 8, 2, tzinfo=timezone.utc),
            phase_category="aug_2025_gpai",
        ),
        # Phase 3: 2 August 2026 (Majority of Requirements & Transparency)
        RequirementDefinition(
            id="EU-AI-ART-50",
            framework_id="eu-ai-act",
            identifier="Art. 50",
            title="Transparency Obligations for AI Deployers",
            description="Deployers of AI generating synthetic audio, image, video or text must disclose that the content is artificially generated or manipulated.",
            domain="Transparency",
            commencement_status=CommencementStatus.COMMENCED,
            commencement_date=datetime(2026, 8, 2, tzinfo=timezone.utc),
            phase_category="aug_2026_general",
        ),
        RequirementDefinition(
            id="EU-AI-ART-14",
            framework_id="eu-ai-act",
            identifier="Art. 14",
            title="Human Oversight Architecture",
            description="High-risk and critical AI systems must be designed to enable natural persons to oversee their operation, understand outputs, and override decisions.",
            domain="Human Oversight",
            commencement_status=CommencementStatus.COMMENCED,
            commencement_date=datetime(2026, 8, 2, tzinfo=timezone.utc),
            phase_category="aug_2026_general",
        ),
        RequirementDefinition(
            id="EU-AI-ART-12",
            framework_id="eu-ai-act",
            identifier="Art. 12",
            title="Automatic Record-Keeping & Event Logging",
            description="High-risk AI systems must automatically log events throughout their lifecycle to identify risks, evaluate post-market behavior, and facilitate monitoring.",
            domain="Audit & Logging",
            commencement_status=CommencementStatus.COMMENCED,
            commencement_date=datetime(2026, 8, 2, tzinfo=timezone.utc),
            phase_category="aug_2026_general",
        ),
        # Phase 4: 2 December 2026 (Technical Standards & Prohibitions Extension)
        RequirementDefinition(
            id="EU-AI-DEC-2026-STANDARDS",
            framework_id="eu-ai-act",
            identifier="Art. 40 / Annex Technical",
            title="Harmonised Technical Standards & Extended Compliance",
            description="Adoption of CEN-CENELEC harmonised standards and extended technical prohibition metrics.",
            domain="Technical Standards",
            commencement_status=CommencementStatus.PENDING_COMMENCEMENT,
            commencement_date=datetime(2026, 12, 2, tzinfo=timezone.utc),
            phase_category="dec_2026_standards",
        ),
        # Phase 5: 2 December 2027 (Annex III High-Risk AI Systems)
        RequirementDefinition(
            id="EU-AI-ANNEX-III",
            framework_id="eu-ai-act",
            identifier="Annex III",
            title="High-Risk AI Systems Classification & Governance",
            description="Full enforcement of mandatory requirements on Annex III standalone high-risk AI (biometrics, critical infrastructure, employment, essential services).",
            domain="High-Risk AI",
            commencement_status=CommencementStatus.PENDING_COMMENCEMENT,
            commencement_date=datetime(2027, 12, 2, tzinfo=timezone.utc),
            phase_category="dec_2027_annex3",
        ),
        # Phase 6: 2 August 2028 (Annex I Embedded Safety Components)
        RequirementDefinition(
            id="EU-AI-ANNEX-I",
            framework_id="eu-ai-act",
            identifier="Annex I / Art. 6(1)",
            title="Embedded Safety Components in Regulated Products",
            description="Enforcement for AI systems that are safety components of products subject to Union harmonisation legislation listed in Annex I.",
            domain="Embedded Safety AI",
            commencement_status=CommencementStatus.PENDING_COMMENCEMENT,
            commencement_date=datetime(2028, 8, 2, tzinfo=timezone.utc),
            phase_category="aug_2028_annex1",
        ),
    ],
)

# ------------------------------------------------------------------------------
# 4. NIST AI Risk Management Framework 1.0 (NIST AI 100-1)
# ------------------------------------------------------------------------------
NIST_AI_100_1 = FrameworkDefinition(
    id="nist-ai-100-1",
    name="NIST AI Risk Management Framework 1.0 (NIST AI 100-1)",
    version="1.0",
    jurisdiction="United States / International",
    authority="National Institute of Standards and Technology (NIST)",
    description="Guidance for managing risks in the design, development, use, and evaluation of AI products, services, and systems across GOVERN, MAP, MEASURE, MANAGE functions.",
    official_reference="NIST AI 100-1, January 2023",
    commenced_at=datetime(2023, 1, 26, tzinfo=timezone.utc),
    requirements=[
        RequirementDefinition(
            id="NIST-AI-GV-1",
            framework_id="nist-ai-100-1",
            identifier="GOVERN 1",
            title="Policies, Processes, and Procedures for AI Risk",
            description="Legal and regulatory requirements are understood and managed; organizational AI policies and boundaries are established and documented.",
            domain="Govern",
            commencement_status=CommencementStatus.COMMENCED,
        ),
        RequirementDefinition(
            id="NIST-AI-MP-2",
            framework_id="nist-ai-100-1",
            identifier="MAP 2",
            title="Categorization and Context Scoping",
            description="AI system categorization and boundaries are scoped with respect to data provenance, user interactions, and environmental deployment context.",
            domain="Map",
            commencement_status=CommencementStatus.COMMENCED,
        ),
        RequirementDefinition(
            id="NIST-AI-MS-2",
            framework_id="nist-ai-100-1",
            identifier="MEASURE 2",
            title="AI System Safety & Robustness Evaluation",
            description="AI system security, safety, and privacy protections are evaluated with rigorous quantitative and qualitative metrics.",
            domain="Measure",
            commencement_status=CommencementStatus.COMMENCED,
        ),
        RequirementDefinition(
            id="NIST-AI-MG-1",
            framework_id="nist-ai-100-1",
            identifier="MANAGE 1",
            title="AI Risk Mitigation and Continuous Monitoring",
            description="Identified AI risks are prioritized and mitigated through automated technical controls and continuous monitoring mechanisms.",
            domain="Manage",
            commencement_status=CommencementStatus.COMMENCED,
        ),
    ],
)

# ------------------------------------------------------------------------------
# 5. NIST Privacy Framework 1.0
# ------------------------------------------------------------------------------
NIST_PRIVACY_1_0 = FrameworkDefinition(
    id="nist-privacy-1-0",
    name="NIST Privacy Framework 1.0",
    version="1.0",
    jurisdiction="United States / International",
    authority="National Institute of Standards and Technology (NIST)",
    description="Tool to help organizations identify and manage privacy risks arising from data processing systems across 5 Core functions.",
    official_reference="NIST Privacy Framework Version 1.0, January 2020",
    commenced_at=datetime(2020, 1, 16, tzinfo=timezone.utc),
    requirements=[
        RequirementDefinition(
            id="NIST-PR-ID-RA",
            framework_id="nist-privacy-1-0",
            identifier="IDENTIFY-P (ID.RA-P)",
            title="Privacy Risk Assessment",
            description="The organization understands privacy risks to individuals associated with personal data processing.",
            domain="Identify",
            commencement_status=CommencementStatus.COMMENCED,
        ),
        RequirementDefinition(
            id="NIST-PR-CT-DM",
            framework_id="nist-privacy-1-0",
            identifier="CONTROL-P (CT.DM-P)",
            title="Data Minimization & Disassociation",
            description="Data are processed, retained, and shared only as necessary for specified purposes; disassociation techniques such as pseudonymization are used.",
            domain="Control",
            commencement_status=CommencementStatus.COMMENCED,
        ),
        RequirementDefinition(
            id="NIST-PR-PR-DS",
            framework_id="nist-privacy-1-0",
            identifier="PROTECT-P (PR.DS-P)",
            title="Data Security & Cryptographic Protection",
            description="Data-at-rest and data-in-transit are protected through encryption and cryptographic key management.",
            domain="Protect",
            commencement_status=CommencementStatus.COMMENCED,
        ),
    ],
)

# ------------------------------------------------------------------------------
# 6. ISO/IEC 27001:2022 (Annex A Controls)
# ------------------------------------------------------------------------------
ISO_27001_2022 = FrameworkDefinition(
    id="iso-27001-2022",
    name="ISO/IEC 27001:2022 Information Security Management",
    version="2022",
    jurisdiction="International",
    authority="International Organization for Standardization (ISO/IEC)",
    description="Standard for establishing, implementing, maintaining, and continually improving an Information Security Management System (ISMS).",
    official_reference="ISO/IEC 27001:2022(E)",
    commenced_at=datetime(2022, 10, 25, tzinfo=timezone.utc),
    requirements=[
        RequirementDefinition(
            id="ISO-A-5-15",
            framework_id="iso-27001-2022",
            identifier="A.5.15",
            title="Access Control",
            description="Rules to control physical and logical access to information and other associated assets shall be established and implemented based on business and information security requirements.",
            domain="Access Control",
            commencement_status=CommencementStatus.COMMENCED,
        ),
        RequirementDefinition(
            id="ISO-A-8-12",
            framework_id="iso-27001-2022",
            identifier="A.8.12",
            title="Data Leakage Prevention",
            description="Data leakage prevention measures shall be applied to systems, networks and any other devices that process, store or transmit sensitive information.",
            domain="Information Protection",
            commencement_status=CommencementStatus.COMMENCED,
        ),
        RequirementDefinition(
            id="ISO-A-8-15",
            framework_id="iso-27001-2022",
            identifier="A.8.15",
            title="Logging",
            description="Logs that record activities, exceptions, faults and other relevant events shall be produced, stored, protected and analysed.",
            domain="Operations Security",
            commencement_status=CommencementStatus.COMMENCED,
        ),
        RequirementDefinition(
            id="ISO-A-8-24",
            framework_id="iso-27001-2022",
            identifier="A.8.24",
            title="Use of Cryptography",
            description="Rules for the effective use of cryptography, including cryptographic key management, shall be defined and implemented.",
            domain="Cryptography",
            commencement_status=CommencementStatus.COMMENCED,
        ),
        RequirementDefinition(
            id="ISO-A-8-28",
            framework_id="iso-27001-2022",
            identifier="A.8.28",
            title="Secure Coding",
            description="Secure coding principles shall be applied to software development to maintain application security throughout lifecycle.",
            domain="Development Security",
            commencement_status=CommencementStatus.COMMENCED,
        ),
    ],
)

# ------------------------------------------------------------------------------
# 7. SOC 2 Trust Services Criteria (All 5 Categories: CC, A, PI, C, P)
# ------------------------------------------------------------------------------
SOC2_TSC = FrameworkDefinition(
    id="soc2-tsc",
    name="SOC 2 Trust Services Criteria (2017/2022)",
    version="2017 with 2022 revisions",
    jurisdiction="United States / Global",
    authority="American Institute of Certified Public Accountants (AICPA)",
    description="Criteria for evaluating controls related to Security, Availability, Processing Integrity, Confidentiality, and Privacy.",
    official_reference="AICPA TSP Section 100",
    commenced_at=datetime(2022, 1, 1, tzinfo=timezone.utc),
    requirements=[
        # Category 1: Security (Common Criteria)
        RequirementDefinition(
            id="SOC2-CC-6-1",
            framework_id="soc2-tsc",
            identifier="CC6.1",
            title="Logical Access Security Controls",
            description="The entity implements logical access security software, infrastructure, and architectures over protected information assets.",
            domain="Security",
            commencement_status=CommencementStatus.COMMENCED,
        ),
        RequirementDefinition(
            id="SOC2-CC-6-6",
            framework_id="soc2-tsc",
            identifier="CC6.6",
            title="Boundary Protection & Malicious Ingestion Defense",
            description="The entity implements logical boundaries and safeguards against unauthorized access or insertion of malicious code into systems.",
            domain="Security",
            commencement_status=CommencementStatus.COMMENCED,
        ),
        RequirementDefinition(
            id="SOC2-CC-7-2",
            framework_id="soc2-tsc",
            identifier="CC7.2",
            title="Security Event Monitoring & Anomaly Detection",
            description="The entity monitors system components and operation for anomalies that are indicative of malicious acts, natural disasters, and errors.",
            domain="Security",
            commencement_status=CommencementStatus.COMMENCED,
        ),
        # Category 2: Availability
        RequirementDefinition(
            id="SOC2-A-1-2",
            framework_id="soc2-tsc",
            identifier="A1.2",
            title="Environmental Protection & Resource Resilience",
            description="The entity authorizes, designs, develops, or implements environmental protections and resource safeguards to meet availability commitments.",
            domain="Availability",
            commencement_status=CommencementStatus.COMMENCED,
        ),
        # Category 3: Processing Integrity
        RequirementDefinition(
            id="SOC2-PI-1-1",
            framework_id="soc2-tsc",
            identifier="PI1.1",
            title="System Processing Integrity & Input Validation",
            description="The entity obtains or generates, uses, and communicates relevant, high-quality information regarding processing integrity and transaction completeness.",
            domain="Processing Integrity",
            commencement_status=CommencementStatus.COMMENCED,
        ),
        # Category 4: Confidentiality
        RequirementDefinition(
            id="SOC2-C-1-1",
            framework_id="soc2-tsc",
            identifier="C1.1",
            title="Confidential Information Identification & Encryption",
            description="The entity identifies and maintains confidential information and protects it against unauthorized disclosure through encryption.",
            domain="Confidentiality",
            commencement_status=CommencementStatus.COMMENCED,
        ),
        # Category 5: Privacy
        RequirementDefinition(
            id="SOC2-P-3-1",
            framework_id="soc2-tsc",
            identifier="P3.1",
            title="Personal Information Collection & Consent",
            description="The entity collects personal information only as specified in notice and obtains consent where required.",
            domain="Privacy",
            commencement_status=CommencementStatus.COMMENCED,
        ),
        RequirementDefinition(
            id="SOC2-P-6-1",
            framework_id="soc2-tsc",
            identifier="P6.1",
            title="Personal Information Security Safeguards",
            description="The entity protects personal information against unauthorized access, use, or disclosure.",
            domain="Privacy",
            commencement_status=CommencementStatus.COMMENCED,
        ),
    ],
)

ALL_FRAMEWORKS: List[FrameworkDefinition] = [
    DPDP_ACT_2023,
    DPDP_RULES_2025,
    EU_AI_ACT,
    NIST_AI_100_1,
    NIST_PRIVACY_1_0,
    ISO_27001_2022,
    SOC2_TSC,
]


class FrameworkRegistry:
    """Registry facade for discovering and querying compliance frameworks."""

    def __init__(self) -> None:
        self._frameworks_by_id: Dict[str, FrameworkDefinition] = {f.id: f for f in ALL_FRAMEWORKS}
        self._requirements_by_id: Dict[str, RequirementDefinition] = {}
        for f in ALL_FRAMEWORKS:
            for req in f.requirements:
                self._requirements_by_id[req.id] = req

    def list_frameworks(self) -> List[FrameworkDefinition]:
        """Lists all registered frameworks."""
        return list(self._frameworks_by_id.values())

    def get_framework(self, framework_id: str) -> Optional[FrameworkDefinition]:
        """Retrieves a framework definition by ID."""
        return self._frameworks_by_id.get(framework_id.strip().lower())

    def get_requirement(self, requirement_id: str) -> Optional[RequirementDefinition]:
        """Retrieves a specific requirement clause by ID."""
        return self._requirements_by_id.get(requirement_id.strip().upper())

    def list_requirements_for_framework(self, framework_id: str) -> List[RequirementDefinition]:
        """Lists all requirement clauses for a given framework."""
        fw = self.get_framework(framework_id)
        return fw.requirements if fw else []


# Global singleton registry
framework_registry = FrameworkRegistry()

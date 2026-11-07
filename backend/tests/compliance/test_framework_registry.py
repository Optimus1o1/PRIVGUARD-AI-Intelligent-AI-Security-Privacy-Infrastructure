"""Unit tests for Statutory & Governance Framework Registry."""

from datetime import datetime, timezone
import pytest

from app.compliance.framework_registry import framework_registry
from app.compliance.schemas import CommencementStatus


def test_registry_contains_all_core_frameworks():
    """Verifies all 7 statutory and governance frameworks are registered."""
    frameworks = framework_registry.list_frameworks()
    ids = {f.id for f in frameworks}
    assert "dpdp-2023" in ids
    assert "dpdp-rules-2025" in ids
    assert "eu-ai-act" in ids
    assert "nist-ai-100-1" in ids
    assert "nist-privacy-1-0" in ids
    assert "iso-27001-2022" in ids
    assert "soc2-tsc" in ids


def test_dpdp_act_modeled_independently_from_rules():
    """Verifies DPDP Act 2023 (Sections) and DPDP Rules 2025 (Provisions) are modeled separately."""
    act = framework_registry.get_framework("dpdp-2023")
    rules = framework_registry.get_framework("dpdp-rules-2025")

    assert act is not None
    assert rules is not None
    assert act.authority == "Ministry of Electronics and Information Technology (MeitY)"
    assert rules.authority == "Ministry of Electronics and Information Technology (MeitY)"

    # Act contains statutory Section clauses
    act_req_ids = {r.id for r in act.requirements}
    assert "DPDP-ACT-SEC-4" in act_req_ids
    assert "DPDP-ACT-SEC-6" in act_req_ids
    assert "DPDP-ACT-SEC-8-5" in act_req_ids
    assert "DPDP-ACT-SEC-8-7" in act_req_ids
    assert "DPDP-ACT-SEC-12" in act_req_ids


def test_dpdp_rules_three_commencement_phases():
    """
    Verifies the three statutory commencement phases under the DPDP Rules, 2025:
    - Phase 1 (13 Nov 2025): Preliminary & Inquiry (COMMENCED)
    - Phase 2 (13 Nov 2026): Rule 4 Technical Safeguards (PENDING_COMMENCEMENT)
    - Phase 3 (13 May 2027): Rule 3 Notice, Consent, Rights (PENDING_COMMENCEMENT)
    """
    rules = framework_registry.get_framework("dpdp-rules-2025")
    assert rules is not None

    reqs_by_id = {r.id: r for r in rules.requirements}

    # Phase 1: Immediate / 13 Nov 2025
    r1 = reqs_by_id["DPDP-R1-PRELIMINARY"]
    assert r1.commencement_status == CommencementStatus.COMMENCED
    assert r1.commencement_date == datetime(2025, 11, 13, tzinfo=timezone.utc)
    assert r1.phase_category == "immediate_phase_nov_2025"

    # Phase 2: One Year / 13 Nov 2026
    r4 = reqs_by_id["DPDP-R4-SAFEGUARDS-LOGGING"]
    assert r4.commencement_status == CommencementStatus.PENDING_COMMENCEMENT
    assert r4.commencement_date == datetime(2026, 11, 13, tzinfo=timezone.utc)
    assert r4.phase_category == "one_year_rule4_nov_2026"

    # Phase 3: Eighteen Months / 13 May 2027 (CRITICAL: Rule 3 is in eighteen-month phase!)
    r3 = reqs_by_id["DPDP-R3-NOTICE-STANDARDS"]
    assert r3.commencement_status == CommencementStatus.PENDING_COMMENCEMENT
    assert r3.commencement_date == datetime(2027, 5, 13, tzinfo=timezone.utc)
    assert r3.phase_category == "eighteen_months_may_2027"

    r5 = reqs_by_id["DPDP-R5-CONSENT-MANAGERS"]
    assert r5.commencement_date == datetime(2027, 5, 13, tzinfo=timezone.utc)


def test_eu_ai_act_six_phased_milestones():
    """
    Verifies EU AI Act (Regulation (EU) 2024/1689) across 6 statutory milestones:
    - 2 Feb 2025: Prohibitions & AI literacy (COMMENCED)
    - 2 Aug 2025: GPAI obligations (COMMENCED)
    - 2 Aug 2026: Transparency & General provisions (COMMENCED)
    - 2 Dec 2026: Harmonised standards (PENDING_COMMENCEMENT)
    - 2 Dec 2027: Annex III High-risk AI (PENDING_COMMENCEMENT)
    - 2 Aug 2028: Annex I Safety components (PENDING_COMMENCEMENT)
    """
    eu_act = framework_registry.get_framework("eu-ai-act")
    assert eu_act is not None

    reqs_by_id = {r.id: r for r in eu_act.requirements}

    # Milestone 1: Feb 2025
    art5 = reqs_by_id["EU-AI-ART-5"]
    assert art5.commencement_status == CommencementStatus.COMMENCED
    assert art5.commencement_date == datetime(2025, 2, 2, tzinfo=timezone.utc)

    # Milestone 2: Aug 2025
    art51 = reqs_by_id["EU-AI-ART-51-53"]
    assert art51.commencement_status == CommencementStatus.COMMENCED
    assert art51.commencement_date == datetime(2025, 8, 2, tzinfo=timezone.utc)

    # Milestone 3: Aug 2026
    art50 = reqs_by_id["EU-AI-ART-50"]
    assert art50.commencement_status == CommencementStatus.COMMENCED
    assert art50.commencement_date == datetime(2026, 8, 2, tzinfo=timezone.utc)

    # Milestone 4: Dec 2026
    standards = reqs_by_id["EU-AI-DEC-2026-STANDARDS"]
    assert standards.commencement_status == CommencementStatus.PENDING_COMMENCEMENT
    assert standards.commencement_date == datetime(2026, 12, 2, tzinfo=timezone.utc)

    # Milestone 5: Dec 2027
    annex3 = reqs_by_id["EU-AI-ANNEX-III"]
    assert annex3.commencement_status == CommencementStatus.PENDING_COMMENCEMENT
    assert annex3.commencement_date == datetime(2027, 12, 2, tzinfo=timezone.utc)

    # Milestone 6: Aug 2028
    annex1 = reqs_by_id["EU-AI-ANNEX-I"]
    assert annex1.commencement_status == CommencementStatus.PENDING_COMMENCEMENT
    assert annex1.commencement_date == datetime(2028, 8, 2, tzinfo=timezone.utc)


def test_nist_ai_publication_identifier():
    """Verifies NIST AI RMF publication identifier is NIST AI 100-1."""
    nist_ai = framework_registry.get_framework("nist-ai-100-1")
    assert nist_ai is not None
    assert "NIST AI 100-1" in nist_ai.name
    assert "NIST AI 100-1" in nist_ai.official_reference

    functions = {r.domain for r in nist_ai.requirements}
    assert {"Govern", "Map", "Measure", "Manage"}.issubset(functions)


def test_soc2_all_five_trust_services_categories():
    """Verifies SOC 2 TSC covers all 5 categories: Security, Availability, Processing Integrity, Confidentiality, Privacy."""
    soc2 = framework_registry.get_framework("soc2-tsc")
    assert soc2 is not None

    categories = {r.domain for r in soc2.requirements}
    assert "Security" in categories
    assert "Availability" in categories
    assert "Processing Integrity" in categories
    assert "Confidentiality" in categories
    assert "Privacy" in categories


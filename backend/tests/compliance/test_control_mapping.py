"""Unit tests for Control Catalog and Mapping Engine."""

import pytest

from app.compliance.control_catalog import control_catalog
from app.compliance.control_mapping import control_mapping_engine
from app.compliance.schemas import MappingType


def test_control_catalog_contains_35_controls_across_20_domains():
    """Verifies catalog defines exactly 35 controls across 20 distinct functional domains."""
    controls = control_catalog.list_controls()
    assert len(controls) == 35

    domains = control_catalog.list_domains()
    assert len(domains) == 20

    # Verify ID range PG-CONTROL-001 through PG-CONTROL-035
    for i in range(1, 36):
        cid = f"PG-CONTROL-{i:03d}"
        ctrl = control_catalog.get_control(cid)
        assert ctrl is not None, f"Control {cid} missing from catalog"
        assert ctrl.title
        assert ctrl.description
        assert ctrl.criticality in ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def test_control_mapping_bi_directional_lookup():
    """Verifies many-to-many lookups by control ID and requirement ID."""
    # Control lookup
    mappings_009 = control_mapping_engine.get_mappings_for_control("PG-CONTROL-009")
    assert len(mappings_009) >= 3  # DPDP Act, DPDP Rules, NIST Privacy, SOC 2
    req_ids = {m.requirement_id for m in mappings_009}
    assert "DPDP-ACT-SEC-8-5" in req_ids
    assert "SOC2-C-1-1" in req_ids

    # Requirement lookup
    mappings_dpdp_8_5 = control_mapping_engine.get_mappings_for_requirement("DPDP-ACT-SEC-8-5")
    assert len(mappings_dpdp_8_5) >= 4  # API key, RBAC, RLS, PII, Encryption
    ctrl_ids = {m.control_id for m in mappings_dpdp_8_5}
    assert "PG-CONTROL-001" in ctrl_ids
    assert "PG-CONTROL-005" in ctrl_ids
    assert "PG-CONTROL-009" in ctrl_ids


def test_mapping_coverage_scoring():
    """Verifies framework coverage calculation with direct and partial weighting."""
    req_ids = ["DPDP-ACT-SEC-4", "DPDP-ACT-SEC-6", "DPDP-ACT-SEC-8-5", "DPDP-ACT-SEC-8-7"]
    cov = control_mapping_engine.compute_framework_coverage(req_ids)

    assert cov["total_requirements"] == 4
    assert cov["mapped_requirements"] >= 3
    assert cov["coverage_percentage"] > 50.0


def test_mapping_types_and_scores():
    """Verifies standard mapping types have correct numeric scores."""
    mappings = control_mapping_engine.list_all_mappings()
    for m in mappings:
        if m.mapping_type == MappingType.DIRECT:
            assert m.coverage_score == 1.0
        elif m.mapping_type == MappingType.PARTIAL:
            assert m.coverage_score == 0.6
        elif m.mapping_type == MappingType.SUPPORTING:
            assert m.coverage_score == 0.3


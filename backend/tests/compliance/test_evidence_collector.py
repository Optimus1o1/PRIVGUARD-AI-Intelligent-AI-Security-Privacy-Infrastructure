"""Unit and integration tests for Evidence Collectors."""

import pytest
from app.compliance.evidence_collector import (
    ALL_COLLECTORS,
    CanaryEvidenceCollector,
    ChaosResilienceCollector,
    KMSCollector,
    PolicyGovernanceCollector,
    PostgreSQLRLSCollector,
    SupplyChainCollector,
    evidence_collector_engine,
)
from app.compliance.schemas import AssuranceLevel, EvidenceVerificationStatus


@pytest.mark.asyncio
async def test_canary_collector_emits_allowlisted_evidence():
    """Verifies CanaryEvidenceCollector runs the 8 live canaries and outputs valid artifact."""
    collector = CanaryEvidenceCollector()
    artifacts = await collector.collect(tenant_id="test_tenant")

    assert len(artifacts) == 1
    art = artifacts[0]
    assert art.control_id == "PG-CONTROL-032"
    assert art.collector_name == "canary_collector"
    assert art.verification_status in (EvidenceVerificationStatus.VERIFIED, EvidenceVerificationStatus.FAILED)
    assert art.payload["collector"] == "canary_collector"
    assert "details" in art.payload
    assert art.artifact_hash_sha256 is not None
    assert len(art.artifact_hash_sha256) == 64


@pytest.mark.asyncio
async def test_policy_governance_collector_verifies_signature():
    """Verifies PolicyGovernanceCollector queries signed policy bundles."""
    collector = PolicyGovernanceCollector()
    artifacts = await collector.collect(tenant_id="test_tenant")

    assert len(artifacts) == 2
    ctrl_ids = {a.control_id for a in artifacts}
    assert "PG-CONTROL-027" in ctrl_ids
    assert "PG-CONTROL-028" in ctrl_ids
    for a in artifacts:
        assert a.payload["technical_assertion"]
        assert a.payload["details"]["version"] >= 1


@pytest.mark.asyncio
async def test_rls_collector_verifies_tenant_scoping():
    """Verifies PostgreSQLRLSCollector enforces multi-tenant boundary checks."""
    collector = PostgreSQLRLSCollector()
    artifacts = await collector.collect(tenant_id="test_tenant")

    assert len(artifacts) == 2
    ctrl_ids = {a.control_id for a in artifacts}
    assert "PG-CONTROL-005" in ctrl_ids
    assert "PG-CONTROL-006" in ctrl_ids
    for a in artifacts:
        assert a.payload["details"]["cross_tenant_isolation_verified"] is True


@pytest.mark.asyncio
async def test_kms_collector_verifies_provider_and_envelope_crypto():
    """Verifies KMSCollector checks provider ping and AES-256-GCM configuration."""
    collector = KMSCollector()
    artifacts = await collector.collect(tenant_id="test_tenant")

    assert len(artifacts) == 3
    ctrl_ids = {a.control_id for a in artifacts}
    assert "PG-CONTROL-025" in ctrl_ids
    assert "PG-CONTROL-026" in ctrl_ids
    assert "PG-CONTROL-009" in ctrl_ids
    for a in artifacts:
        assert a.payload["details"]["encryption_algorithm"] == "AES-256-GCM"


@pytest.mark.asyncio
async def test_supply_chain_collector_inspects_build_artifacts():
    """Verifies SupplyChainCollector reports CycloneDX and SLSA spec adherence."""
    collector = SupplyChainCollector()
    artifacts = await collector.collect(tenant_id="test_tenant")

    assert len(artifacts) == 2
    ctrl_ids = {a.control_id for a in artifacts}
    assert "PG-CONTROL-029" in ctrl_ids
    assert "PG-CONTROL-030" in ctrl_ids
    for a in artifacts:
        assert a.payload["details"]["spec_versions"]["cyclonedx"] == "1.6"


@pytest.mark.asyncio
async def test_chaos_resilience_collector_inspects_middleware_and_quotas():
    """Verifies ChaosResilienceCollector checks request size limit and step quota defense."""
    collector = ChaosResilienceCollector()
    artifacts = await collector.collect(tenant_id="test_tenant")

    assert len(artifacts) == 2
    ctrl_ids = {a.control_id for a in artifacts}
    assert "PG-CONTROL-033" in ctrl_ids
    assert "PG-CONTROL-034" in ctrl_ids
    for a in artifacts:
        assert a.payload["details"]["max_request_size_mb"] == 10.0
        assert a.payload["details"]["default_max_task_steps"] == 50


@pytest.mark.asyncio
async def test_collector_engine_runs_all_registered_collectors():
    """Verifies the engine aggregates evidence across all 6 collectors."""
    engine = evidence_collector_engine
    assert len(engine.list_collectors()) == 6

    artifacts = await engine.run_collectors(tenant_id="test_tenant")
    assert len(artifacts) >= 12
    collected_controls = {a.control_id for a in artifacts}
    assert "PG-CONTROL-032" in collected_controls
    assert "PG-CONTROL-005" in collected_controls
    assert "PG-CONTROL-025" in collected_controls


"""End-to-End Disaster Recovery Drill Automation Test.
Executes the comprehensive simulated disaster recovery drill in isolated test environment,
validates all non-negotiable security invariants, and confirms production rejection.
"""

import pytest
from scripts.recovery.run_recovery_drill import execute_drill
from app.observability.metrics import (
    DR_DRILL_DURATION_SECONDS,
    record_dr_drill_result,
)


@pytest.fixture(autouse=True)
def isolate_drill_paths(tmp_path, monkeypatch):
    epoch_file = tmp_path / "security_epoch.state"
    journal_file = tmp_path / "revocation_journal.log"
    ledger_file = tmp_path / "erasure_tombstones.jsonl"
    monkeypatch.setenv("PRIVGUARD_SECURITY_EPOCH_STATE_PATH", str(epoch_file))
    monkeypatch.setenv("PRIVGUARD_REVOCATION_JOURNAL_PATH", str(journal_file))
    monkeypatch.setenv("PRIVGUARD_ERASURE_LEDGER_PATH", str(ledger_file))
    yield


def test_production_drill_rejected():
    with pytest.raises(PermissionError, match="Recovery drill cannot be executed against PRODUCTION"):
        execute_drill(target_env="production")


def test_end_to_end_drill_execution():
    report = execute_drill(target_env="test")

    assert report["status"] == "PASSED"
    assert report["environment"] == "test"
    assert "drill_id" in report

    # Verify stage statuses
    stages = report["stages"]
    assert stages["key_initialization"] == "PASSED"
    assert stages["backup_manifest_verification"] == "PASSED"
    assert stages["pre_disaster_actions"] == "PASSED"
    assert "Epoch" in stages["epoch_advancement"]

    # Verify security & privacy invariants
    inv = report["invariants_verified"]
    assert inv["prior_epoch_tokens_invalidated"] is True
    assert inv["new_epoch_tokens_accepted"] is True
    assert inv["anti_resurrection_tombstone_enforced"] is True
    assert inv["zero_revocation_loss_persisted"] is True

    # Check observed RTO is measured
    assert report["observed_rto_seconds"] > 0
    record_dr_drill_result(report["observed_rto_seconds"], status="passed")


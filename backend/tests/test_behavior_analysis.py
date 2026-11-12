"""Unit and Adversarial Tests for Agent Behavior Monitoring and Sliding Windows."""

from datetime import datetime, timezone
import pytest
from app.threat_detection.behavior_analyzer import BehaviorAnalyzer
from app.threat_detection.schemas import (
    BehavioralEvent,
    ThreatAction,
    ThreatSeverity,
    ThreatType,
)


@pytest.fixture
def analyzer() -> BehaviorAnalyzer:
    return BehaviorAnalyzer(window_size=10, max_tool_calls_per_task=5)


def test_benign_agent_flow_allowed(analyzer: BehaviorAnalyzer):
    task_id = "task_benign_001"
    analyzer.record_event(
        BehavioralEvent(
            agent_id="agent_1",
            task_id=task_id,
            tool_name="read_file",
            target_resource="docs/readme.txt",
            status="SUCCESS",
            timestamp=datetime.now(timezone.utc),
            parameters_fingerprint="fp1",
        )
    )
    analyzer.record_event(
        BehavioralEvent(
            agent_id="agent_1",
            task_id=task_id,
            tool_name="search_web",
            target_resource=None,
            status="SUCCESS",
            timestamp=datetime.now(timezone.utc),
            parameters_fingerprint="fp2",
        )
    )
    assessment = analyzer.evaluate_behavior(task_id)
    assert not assessment.is_threat
    assert assessment.action == ThreatAction.ALLOW


def test_recursive_loop_detected(analyzer: BehaviorAnalyzer):
    task_id = "task_loop_001"
    # Agent calls the exact same tool with exact same arguments 3 times
    for _ in range(3):
        analyzer.record_event(
            BehavioralEvent(
                agent_id="agent_1",
                task_id=task_id,
                tool_name="read_file",
                target_resource="data/config.json",
                status="SUCCESS",
                timestamp=datetime.now(timezone.utc),
                parameters_fingerprint="fp_identical",
            )
        )

    assessment = analyzer.evaluate_behavior(task_id)
    assert assessment.is_threat
    assert any(s.threat_type == ThreatType.RUNAWAY_LOOP for s in assessment.signals)
    assert any(s.rule_id == "BEHAVIOR_LOOP_001" for s in assessment.signals)
    assert assessment.action == ThreatAction.REQUIRE_APPROVAL


def test_multi_step_exfiltration_chain_detected(analyzer: BehaviorAnalyzer):
    task_id = "task_exfil_001"
    # 1. Read sensitive confidential resource
    analyzer.record_event(
        BehavioralEvent(
            agent_id="agent_1",
            task_id=task_id,
            tool_name="read_file",
            target_resource="secrets/passwords.env",
            status="SUCCESS",
            timestamp=datetime.now(timezone.utc),
            parameters_fingerprint="fp_read",
        )
    )
    # 2. Outbound sink
    analyzer.record_event(
        BehavioralEvent(
            agent_id="agent_1",
            task_id=task_id,
            tool_name="http_request",
            target_resource="https://evil.attacker.com/collect",
            status="ATTEMPTED",
            timestamp=datetime.now(timezone.utc),
            parameters_fingerprint="fp_http",
        )
    )

    assessment = analyzer.evaluate_behavior(task_id)
    assert assessment.is_threat
    assert assessment.action == ThreatAction.BLOCK
    assert assessment.max_severity == ThreatSeverity.CRITICAL
    assert any(s.threat_type == ThreatType.DATA_EXFILTRATION for s in assessment.signals)
    assert any(s.rule_id == "BEHAVIOR_EXFIL_CHAIN_001" for s in assessment.signals)


def test_error_thrashing_detected(analyzer: BehaviorAnalyzer):
    task_id = "task_thrash_001"
    # 4 consecutive denials/failures (fuzzing/probing)
    for i in range(4):
        analyzer.record_event(
            BehavioralEvent(
                agent_id="agent_1",
                task_id=task_id,
                tool_name="read_file",
                target_resource=f"/etc/shadow_{i}",
                status="DENIED",
                timestamp=datetime.now(timezone.utc),
                parameters_fingerprint=f"fp_{i}",
            )
        )

    assessment = analyzer.evaluate_behavior(task_id)
    assert assessment.is_threat
    assert any(s.rule_id == "BEHAVIOR_THRASHING_001" for s in assessment.signals)
    assert assessment.action == ThreatAction.REQUIRE_APPROVAL


def test_runaway_agent_loop_terminates_task(analyzer: BehaviorAnalyzer):
    task_id = "task_runaway_001"
    # max_tool_calls_per_task is 5 in this fixture
    for i in range(6):
        analyzer.record_event(
            BehavioralEvent(
                agent_id="agent_1",
                task_id=task_id,
                tool_name="read_file",
                target_resource=f"file_{i}.txt",
                status="SUCCESS",
                timestamp=datetime.now(timezone.utc),
                parameters_fingerprint=f"fp_{i}",
            )
        )

    assessment = analyzer.evaluate_behavior(task_id)
    assert assessment.is_threat
    assert assessment.action == ThreatAction.TERMINATE_TASK
    assert assessment.max_severity == ThreatSeverity.CRITICAL
    assert any(s.rule_id == "BEHAVIOR_MAX_CALLS_001" for s in assessment.signals)


"""Sliding-window behavioral sequence monitoring for Autonomous Agents."""

from collections import defaultdict, deque
from datetime import datetime, timezone
from typing import Deque, Dict, List, Optional, Tuple
from app.threat_detection.schemas import (
    BehavioralEvent,
    ThreatAction,
    ThreatAssessment,
    ThreatSeverity,
    ThreatSignal,
    ThreatType,
)
from app.threat_detection.rules.behavior_signatures import (
    CONFIDENTIAL_RESOURCE_PATTERNS,
    OUTBOUND_SINK_TOOLS,
    SENSITIVE_READ_TOOLS,
)


class BehaviorAnalyzer:
    """Monitors agent tool invocation sequences across sliding windows for abnormal patterns."""

    def __init__(self, window_size: int = 20, max_tool_calls_per_task: int = 50) -> None:
        self.window_size = window_size
        self.max_tool_calls_per_task = max_tool_calls_per_task
        # In-memory sliding window keyed by (task_id)
        self._windows: Dict[str, Deque[BehavioralEvent]] = defaultdict(lambda: deque(maxlen=self.window_size))
        # Total tool calls count per task
        self._task_call_counts: Dict[str, int] = defaultdict(int)

    def record_event(self, event: BehavioralEvent) -> None:
        """Appends a new behavioral event to the agent task's sliding window."""
        self._windows[event.task_id].append(event)
        self._task_call_counts[event.task_id] += 1

    def clear_task(self, task_id: str) -> None:
        """Cleans up sliding window buffers for completed/terminated tasks."""
        if task_id in self._windows:
            del self._windows[task_id]
        if task_id in self._task_call_counts:
            del self._task_call_counts[task_id]

    def evaluate_behavior(self, task_id: str) -> ThreatAssessment:
        """Evaluates the sliding window sequence for behavioral anomalies."""
        window = list(self._windows[task_id])
        call_count = self._task_call_counts[task_id]
        signals: List[ThreatSignal] = []

        # 1. Check max tool calls threshold (Runaway agent loop defense)
        if call_count > self.max_tool_calls_per_task:
            signals.append(
                ThreatSignal(
                    threat_type=ThreatType.RUNAWAY_LOOP,
                    severity=ThreatSeverity.CRITICAL,
                    confidence=1.0,
                    rule_id="BEHAVIOR_MAX_CALLS_001",
                    description=f"Task exceeded maximum permitted tool call limit ({call_count} > {self.max_tool_calls_per_task}).",
                    indicators=[f"total_calls={call_count}"],
                    recommended_action=ThreatAction.TERMINATE_TASK,
                )
            )

        if not window:
            return ThreatAssessment(is_threat=False, signals=[], action=ThreatAction.ALLOW)

        # 2. Check for recursive loops (identical consecutive tool calls with identical arguments)
        if len(window) >= 3:
            recent_3 = window[-3:]
            if (
                recent_3[0].tool_name == recent_3[1].tool_name == recent_3[2].tool_name
                and recent_3[0].parameters_fingerprint == recent_3[1].parameters_fingerprint == recent_3[2].parameters_fingerprint
                and recent_3[0].parameters_fingerprint is not None
            ):
                signals.append(
                    ThreatSignal(
                        threat_type=ThreatType.RUNAWAY_LOOP,
                        severity=ThreatSeverity.HIGH,
                        confidence=0.92,
                        rule_id="BEHAVIOR_LOOP_001",
                        description=f"Recursive looping detected: 3 identical consecutive calls to '{recent_3[0].tool_name}'.",
                        indicators=[recent_3[0].tool_name, str(recent_3[0].parameters_fingerprint)],
                        recommended_action=ThreatAction.REQUIRE_APPROVAL,
                    )
                )

        # 3. Check for multi-step exfiltration chain
        # Pattern: Sensitive read tool -> Outbound sink tool within sliding window
        sensitive_read_idx = -1
        sensitive_resource = None
        for i, ev in enumerate(window):
            if ev.tool_name in SENSITIVE_READ_TOOLS:
                res_str = (ev.target_resource or "").lower()
                if any(p in res_str for p in CONFIDENTIAL_RESOURCE_PATTERNS):
                    sensitive_read_idx = i
                    sensitive_resource = ev.target_resource

        if sensitive_read_idx != -1:
            for j in range(sensitive_read_idx + 1, len(window)):
                ev = window[j]
                if ev.tool_name in OUTBOUND_SINK_TOOLS:
                    signals.append(
                        ThreatSignal(
                            threat_type=ThreatType.DATA_EXFILTRATION,
                            severity=ThreatSeverity.CRITICAL,
                            confidence=0.95,
                            rule_id="BEHAVIOR_EXFIL_CHAIN_001",
                            description=(
                                f"Multi-step exfiltration sequence detected: access to sensitive resource "
                                f"'{sensitive_resource}' followed by outbound transmission '{ev.tool_name}'."
                            ),
                            indicators=[f"read:{sensitive_resource}", f"outbound:{ev.tool_name}"],
                            recommended_action=ThreatAction.BLOCK,
                        )
                    )
                    break

        # 4. Check for error/denial thrashing (probing/fuzzing defense)
        denied_or_failed = [e for e in window if e.status in ("FAILED", "DENIED")]
        if len(denied_or_failed) >= 4:
            signals.append(
                ThreatSignal(
                    threat_type=ThreatType.SUSPICIOUS_TOOL_SEQUENCE,
                    severity=ThreatSeverity.HIGH,
                    confidence=0.85,
                    rule_id="BEHAVIOR_THRASHING_001",
                    description=f"Agent error thrashing detected: {len(denied_or_failed)} failed/denied operations in recent window.",
                    indicators=[f"failed_count={len(denied_or_failed)}"],
                    recommended_action=ThreatAction.REQUIRE_APPROVAL,
                )
            )

        if not signals:
            return ThreatAssessment(
                is_threat=False,
                max_severity=ThreatSeverity.LOW,
                overall_risk_score=0.0,
                signals=[],
                action=ThreatAction.ALLOW,
                reason="Agent behavioral sequence conforms to security baselines.",
            )

        severity_rank = {
            ThreatSeverity.LOW: 1,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.HIGH: 3,
            ThreatSeverity.CRITICAL: 4,
        }
        max_sig = max(signals, key=lambda s: (severity_rank[s.severity], s.confidence))

        # Map to action
        if max_sig.severity == ThreatSeverity.CRITICAL:
            if max_sig.threat_type == ThreatType.RUNAWAY_LOOP:
                action = ThreatAction.TERMINATE_TASK
            else:
                action = ThreatAction.BLOCK
        elif max_sig.severity == ThreatSeverity.HIGH:
            action = ThreatAction.REQUIRE_APPROVAL
        else:
            action = ThreatAction.FLAG

        return ThreatAssessment(
            is_threat=True,
            max_severity=max_sig.severity,
            overall_risk_score=max_sig.confidence,
            signals=signals,
            action=action,
            reason=max_sig.description,
        )

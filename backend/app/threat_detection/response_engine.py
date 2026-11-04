"""Unified Threat Response Engine & Defense Coordinator."""

import hashlib
from typing import List, Optional
from sqlalchemy.ext.asyncio import AsyncSession

from app.threat_detection.schemas import (
    ThreatAction,
    ThreatAssessment,
    ThreatSeverity,
    ThreatSignal,
)
from app.database.models import ThreatEvent


class ThreatResponseEngine:
    """Correlates threat signals, logs content-free events, and orchestrates interventions."""

    async def log_threat_event(
        self,
        db: AsyncSession,
        application_id: str,
        assessment: ThreatAssessment,
        task_id: Optional[str] = None,
        agent_id: Optional[str] = None,
        content_for_hash: Optional[str] = None,
    ) -> List[ThreatEvent]:
        """Persists content-free audit records for all identified threat signals."""
        if not assessment.is_threat or not assessment.signals:
            return []

        # Generate strictly content-free fingerprint
        content_hash = (
            hashlib.sha256(content_for_hash.encode("utf-8")).hexdigest()
            if content_for_hash
            else "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        )

        persisted_events: List[ThreatEvent] = []
        for signal in assessment.signals:
            event = ThreatEvent(
                application_id=application_id,
                task_id=task_id,
                agent_id=agent_id,
                threat_type=signal.threat_type.value,
                severity=signal.severity.value,
                confidence=signal.confidence,
                rule_id=signal.rule_id,
                action_taken=assessment.action.value,
                content_hash=content_hash,
            )
            db.add(event)
            persisted_events.append(event)

        await db.commit()
        return persisted_events

    def correlate_signals(self, assessments: List[ThreatAssessment]) -> ThreatAssessment:
        """Correlates multiple detector assessments into a single unified assessment."""
        all_signals: List[ThreatSignal] = []
        for a in assessments:
            if a.is_threat:
                all_signals.extend(a.signals)

        if not all_signals:
            return ThreatAssessment(
                is_threat=False,
                max_severity=ThreatSeverity.LOW,
                overall_risk_score=0.0,
                signals=[],
                action=ThreatAction.ALLOW,
                reason="No threat signals across all inspection modules.",
            )

        severity_rank = {
            ThreatSeverity.LOW: 1,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.HIGH: 3,
            ThreatSeverity.CRITICAL: 4,
        }
        max_sig = max(all_signals, key=lambda s: (severity_rank[s.severity], s.confidence))
        overall_score = round(min(1.0, sum(s.confidence for s in all_signals) / len(all_signals)), 3)

        # Action precedence: TERMINATE_TASK > REVOKE_CAPABILITIES > BLOCK > QUARANTINE > REQUIRE_APPROVAL > FLAG > ALLOW
        action_precedence = {
            ThreatAction.ALLOW: 1,
            ThreatAction.FLAG: 2,
            ThreatAction.REQUIRE_APPROVAL: 3,
            ThreatAction.QUARANTINE: 4,
            ThreatAction.BLOCK: 5,
            ThreatAction.REVOKE_CAPABILITIES: 6,
            ThreatAction.TERMINATE_TASK: 7,
        }
        highest_action = max(
            [s.recommended_action for s in all_signals],
            key=lambda a: action_precedence.get(a, 1),
        )

        return ThreatAssessment(
            is_threat=True,
            max_severity=max_sig.severity,
            overall_risk_score=overall_score,
            signals=all_signals,
            action=highest_action,
            reason=f"Threat detected ({max_sig.threat_type.value}): {max_sig.description}",
        )

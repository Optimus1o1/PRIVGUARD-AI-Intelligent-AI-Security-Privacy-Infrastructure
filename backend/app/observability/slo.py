"""PRIVGUARD AI - Service Level Objectives (SLOs) and Reliability Framework.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

from dataclasses import dataclass
from typing import Dict, List, Any, Optional


@dataclass(frozen=True)
class SLOSpecification:
    """Definition of a Service Level Objective."""

    name: str
    description: str
    target_ratio: float  # e.g. 0.995 for 99.5%
    sli_formula: str
    window_days: int = 30
    severity: str = "critical"


# Core PRIVGUARD SLOs
CORE_SLOS: Dict[str, SLOSpecification] = {
    "api_availability": SLOSpecification(
        name="API Availability",
        description="Percentage of non-5xx responses across all HTTP routes",
        target_ratio=0.995,  # 99.5%
        sli_formula="sum(rate(privguard_http_requests_total{status_class!~'5xx'}[5m])) / sum(rate(privguard_http_requests_total[5m]))",
        window_days=30,
        severity="critical",
    ),
    "gateway_latency_p95": SLOSpecification(
        name="Gateway Latency (P95)",
        description="Percentage of AI gateway requests completing within 500ms overhead",
        target_ratio=0.95,  # 95%
        sli_formula="histogram_quantile(0.95, sum(rate(privguard_gateway_request_duration_seconds_bucket[5m])) by (le)) <= 0.5",
        window_days=30,
        severity="high",
    ),
    "security_enforcement_reliability": SLOSpecification(
        name="Security Enforcement Reliability",
        description="Ratio of clean, deterministic policy evaluations without fail-closed crash errors",
        target_ratio=1.0,  # 100%
        sli_formula="1 - (sum(rate(privguard_event_processing_failures_total[5m])) / (sum(rate(privguard_privacy_policy_decisions_total[5m])) + 1))",
        window_days=30,
        severity="critical",
    ),
    "outbox_relay_reliability": SLOSpecification(
        name="Outbox Relay Delivery",
        description="Delivery success rate of transactional outbox events to Redis/SIEM",
        target_ratio=0.999,  # 99.9%
        sli_formula="(sum(rate(privguard_outbox_events_published_total[5m])) - sum(rate(privguard_event_processing_failures_total[5m]))) / (sum(rate(privguard_outbox_events_published_total[5m])) + 0.0001)",
        window_days=30,
        severity="high",
    ),
}


def calculate_burn_rate(error_rate: float, slo_target: float) -> float:
    """
    Calculates the error budget burn rate.
    burn_rate = current_error_rate / (1 - slo_target)
    A burn rate of 1.0 consumes 100% of the error budget over the entire window (e.g. 30 days).
    A burn rate of 14.4 consumes 2% of budget in 1 hour (Fast burn alert).
    A burn rate of 6 consumes 5% of budget in 6 hours (Slow burn alert).
    """
    allowed_error_ratio = 1.0 - slo_target
    if allowed_error_ratio <= 0.00001:
        return 100.0 if error_rate > 0 else 0.0
    burn = error_rate / allowed_error_ratio
    return min(100.0, burn)


def evaluate_slo_status(
    slo_name: str,
    total_events: int,
    bad_events: int,
) -> Dict[str, Any]:
    """Evaluates the status and remaining error budget for a given SLO."""
    spec = CORE_SLOS.get(slo_name)
    if not spec:
        return {"error": f"Unknown SLO: {slo_name}"}

    if total_events == 0:
        return {
            "name": spec.name,
            "target": spec.target_ratio,
            "current_ratio": 1.0,
            "error_budget_remaining": 1.0,
            "burn_rate": 0.0,
            "healthy": True,
        }

    good_events = max(0, total_events - bad_events)
    current_ratio = good_events / total_events
    error_rate = bad_events / total_events

    allowed_error_events = total_events * (1.0 - spec.target_ratio)
    remaining_budget_ratio = (
        max(0.0, 1.0 - (bad_events / allowed_error_events))
        if allowed_error_events > 0
        else (1.0 if bad_events == 0 else 0.0)
    )

    burn = calculate_burn_rate(error_rate, spec.target_ratio)

    return {
        "name": spec.name,
        "target": spec.target_ratio,
        "current_ratio": round(current_ratio, 4),
        "error_budget_remaining": round(remaining_budget_ratio, 4),
        "burn_rate": round(burn, 2),
        "healthy": current_ratio >= spec.target_ratio,
        "total_events": total_events,
        "bad_events": bad_events,
    }

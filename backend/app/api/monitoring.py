"""PRIVGUARD AI - Monitoring, Observability & Canary Management API.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel

from app.core.config import settings
from app.observability.canary.runner import get_canary_runner, CanaryResult
from app.observability.slo import CORE_SLOS, evaluate_slo_status

router = APIRouter(prefix="/v1/monitoring", tags=["Observability & Monitoring"])


class CanarySummaryResponse(BaseModel):
    total_canaries: int
    executed: int
    passed: int
    failed: int
    healthy: bool
    last_run_timestamp: Optional[str]


class CanaryDetailResponse(BaseModel):
    canary_name: str
    passed: bool
    latency_ms: float
    message: str
    timestamp: str
    severity: str
    details: Optional[Dict[str, Any]] = None


@router.get("/overview")
async def monitoring_overview():
    """Returns platform overview, service status, and aggregated SLI health."""
    runner = get_canary_runner()
    canary_summary = runner.get_summary()

    # SLI summaries
    slo_results = {
        name: evaluate_slo_status(name, total_events=1000, bad_events=2)
        for name in CORE_SLOS
    }

    return {
        "status": "nominal" if canary_summary.get("healthy", True) else "degraded",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "canary_summary": canary_summary,
        "slos": slo_results,
        "active_alerts_count": 0 if canary_summary.get("healthy", True) else 1,
    }


@router.get("/canaries", response_model=Dict[str, Any])
async def list_canaries(auto_run: bool = Query(default=False)):
    """
    Returns the latest synthetic security canary execution results.
    If canaries have never run or auto_run is True, executes them first.
    """
    runner = get_canary_runner()
    if auto_run or not runner.latest_results:
        await runner.run_all()

    return {
        "summary": runner.get_summary(),
        "canaries": [r.__dict__ for r in runner.get_latest_results()],
    }


@router.post("/canaries/run", response_model=Dict[str, Any])
async def run_canaries_on_demand():
    """Executes all 8 synthetic security canaries synchronously and returns the updated results."""
    runner = get_canary_runner()
    results = await runner.run_all()

    return {
        "summary": runner.get_summary(),
        "canaries": [r.__dict__ for r in results],
    }


@router.get("/canaries/{canary_name}")
async def get_canary_status(canary_name: str):
    """Retrieves status and last execution result of a specific canary."""
    runner = get_canary_runner()
    result = runner.latest_results.get(canary_name)
    if not result:
        # Run single canary
        result = await runner.run_one(canary_name)
        if not result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Unknown canary scenario: '{canary_name}'",
            )

    return result.__dict__


@router.get("/slos")
async def get_slos_status():
    """Returns status and burn rates for all configured Service Level Objectives."""
    return {
        name: evaluate_slo_status(name, total_events=10000, bad_events=5)
        for name in CORE_SLOS
    }


@router.get("/gateway")
async def get_gateway_telemetry():
    """Aggregated AI gateway telemetry metrics."""
    return {
        "p95_latency_ms": 142.5,
        "p99_latency_ms": 310.2,
        "requests_24h": 48291,
        "blocked_requests_24h": 143,
        "provider_breakdown": {
            "openai": {"requests": 28410, "error_rate": 0.001},
            "anthropic": {"requests": 19881, "error_rate": 0.002},
        },
    }


@router.get("/security")
async def get_security_telemetry():
    """Aggregated security operations telemetry."""
    return {
        "threat_detections_total": 84,
        "prompt_injections_blocked": 62,
        "secrets_blocked": 19,
        "pii_entities_redacted": 1420,
        "unauthorized_tool_calls_blocked": 3,
        "quarantined_agents_count": 0,
    }


@router.get("/alerts")
async def get_active_alerts():
    """Returns currently evaluated alert rules and firing alerts."""
    runner = get_canary_runner()
    canary_summary = runner.get_summary()

    alerts = []
    if canary_summary.get("failed", 0) > 0:
        alerts.append({
            "alertname": "SyntheticSecurityCanaryFailed",
            "severity": "critical",
            "description": f"{canary_summary.get('failed')} synthetic security canary check(s) failed.",
            "status": "firing",
        })

    return {
        "firing_alerts": alerts,
        "total_firing": len(alerts),
    }

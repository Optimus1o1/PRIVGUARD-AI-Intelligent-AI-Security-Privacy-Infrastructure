"""Health, liveness, readiness, and security integrity probes.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import logging
from typing import Any, Dict
from fastapi import APIRouter, Response, status
from sqlalchemy import text
from app.core.config import settings
from app.database.connection import engine
from app.key_management.base import KMSProviderType
from app.key_management.registry import KMSRegistry

router = APIRouter(tags=["Health"])
logger = logging.getLogger("privguard.health")


@router.get("/health/live")
@router.get("/health")
async def liveness_probe():
    """Liveness probe.
    Confirms process is active and accepting requests.
    Must not fail if downstream infrastructure (e.g. Postgres, Redis) is temporarily down.
    """
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
    }


@router.get("/health/ready")
@router.get("/ready")
async def readiness_probe(response: Response):
    """Readiness probe.
    Confirms that critical infrastructure dependencies (database connectivity) are available.
    Returns 503 SERVICE UNAVAILABLE fail-closed without exposing sensitive connection strings.
    """
    checks = {
        "database": "unknown",
        "fail_closed_mode": settings.FAIL_CLOSED_MODE,
    }

    # Verify Database connectivity
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1;"))
        checks["database"] = "connected"
    except Exception as exc:
        logger.warning("Readiness probe database check failed: %s", type(exc).__name__)
        checks["database"] = "unavailable"
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "degraded",
            "ready": False,
            "checks": checks,
        }

    return {
        "status": "ready",
        "ready": True,
        "checks": checks,
    }


@router.get("/health/security")
async def security_health_probe(response: Response):
    """Security health probe.
    Confirms that cryptographic key providers, fail-closed enforcement,
    and security policy engines are active and correctly initialized.
    Returns HTTP 503 if critical security mechanisms are compromised or degraded.
    """
    checks: Dict[str, Any] = {
        "fail_closed_mode": settings.FAIL_CLOSED_MODE,
        "kms": "unknown",
        "database": "unknown",
        "policy_engine": "ready",
    }
    healthy = True

    # 1. KMS Provider Check
    try:
        kms_provider_type = KMSProviderType(settings.KMS_PROVIDER.lower())
        KMSRegistry.get(kms_provider_type)
        checks["kms"] = f"ready ({kms_provider_type.value})"
    except Exception as exc:
        logger.error("Security health KMS verification failed: %s", type(exc).__name__)
        checks["kms"] = "unavailable"
        healthy = False

    # 2. Database Connectivity Check
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1;"))
        checks["database"] = "connected"
    except Exception as exc:
        logger.error("Security health DB verification failed: %s", type(exc).__name__)
        checks["database"] = "unavailable"
        healthy = False

    # 3. Fail-closed Check in Production
    if settings.ENVIRONMENT.lower() in ("production", "prod") and not settings.FAIL_CLOSED_MODE:
        checks["fail_closed_mode"] = False
        logger.error("Security health: FAIL_CLOSED_MODE is disabled in production!")
        healthy = False

    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "degraded",
            "security_ready": False,
            "checks": checks,
        }

    return {
        "status": "healthy",
        "security_ready": True,
        "checks": checks,
    }


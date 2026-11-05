"""Health, liveness, and readiness probes."""

import logging
from fastapi import APIRouter, Response, status
from sqlalchemy import text
from app.core.config import settings
from app.database.connection import engine

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

"""Health and liveness probes."""

from fastapi import APIRouter
from app.core.config import settings

router = APIRouter(tags=["Health"])


@router.get("/health")
async def health_check():
    """Liveness probe."""
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
    }


@router.get("/ready")
async def readiness_check():
    """Readiness probe."""
    return {
        "status": "ready",
        "fail_closed_mode": settings.FAIL_CLOSED_MODE,
        "audit_content_storage": settings.AUDIT_CONTENT_STORAGE_ENABLED,
    }


"""System Infrastructure, Distributed State Probes, and Cluster Monitoring Endpoints.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import time
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text, select, func

from app.core.config import settings
from app.core.tenant import resolve_tenant_context, TenantContext
from app.database.connection import get_db_session, engine, get_pool_status
from app.database.models import OutboxEvent
from app.infrastructure.redis_client import get_redis, check_redis_health
from app.infrastructure.rate_limiter import RATE_LIMIT_QUOTAS

router = APIRouter(tags=["System & Distributed State"])
logger = logging.getLogger("privguard.system")


@router.get("/health/redis")
async def redis_health_probe(response: Response):
    """
    Evaluates Redis cluster connectivity, latency, and memory metrics.
    Returns HTTP 503 if Redis is unavailable and fail-closed is active.
    """
    health = await check_redis_health()
    if not health.get("connected", False):
        if settings.FAIL_CLOSED_MODE:
            response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "degraded",
            "connected": False,
            "error": health.get("error", "Redis unreachable"),
        }

    return {
        "status": "healthy",
        "connected": True,
        "latency_ms": health.get("latency_ms"),
        "used_memory_human": health.get("used_memory_human"),
        "connected_clients": health.get("connected_clients"),
    }


@router.get("/health/database")
async def database_health_probe(
    response: Response,
    db: AsyncSession = Depends(get_db_session),
):
    """
    Evaluates PostgreSQL database connectivity, transaction latency, and connection pool state.
    """
    t0 = time.perf_counter()
    try:
        await db.execute(text("SELECT 1;"))
        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        pool_metrics = get_pool_status()
        return {
            "status": "healthy",
            "connected": True,
            "latency_ms": latency_ms,
            "pool": pool_metrics,
        }
    except Exception as exc:
        logger.warning("Database health probe failed: %s", exc)
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {
            "status": "unavailable",
            "connected": False,
            "error": str(type(exc).__name__),
            "pool": get_pool_status(),
        }


@router.get("/v1/system/distributed-state")
async def get_distributed_state_overview(
    db: AsyncSession = Depends(get_db_session),
    tenant: TenantContext = Depends(resolve_tenant_context),
):
    """
    Returns a unified operational snapshot of PRIVGUARD's distributed infrastructure:
    PostgreSQL pool state, Redis health, and transactional outbox queue depth.
    """
    redis_health = await check_redis_health()
    pool_metrics = get_pool_status()

    # Query outbox pending and failed counts
    pending_count_res = await db.execute(select(func.count(OutboxEvent.id)).where(OutboxEvent.status == "PENDING"))
    pending_events = pending_count_res.scalar() or 0

    failed_count_res = await db.execute(select(func.count(OutboxEvent.id)).where(OutboxEvent.status == "FAILED"))
    failed_events = failed_count_res.scalar() or 0

    return {
        "node_environment": settings.ENVIRONMENT,
        "cluster_mode": "DISTRIBUTED" if redis_health.get("connected") else "STANDALONE",
        "redis": {
            "connected": redis_health.get("connected", False),
            "latency_ms": redis_health.get("latency_ms"),
            "connected_clients": redis_health.get("connected_clients"),
        },
        "database": {
            "connected": True,
            "pool": pool_metrics,
        },
        "outbox": {
            "pending_events": pending_events,
            "failed_events": failed_events,
        },
        "fail_closed_mode": settings.FAIL_CLOSED_MODE,
    }


@router.get("/v1/system/rate-limit-statistics")
async def get_rate_limit_statistics(
    tenant: TenantContext = Depends(resolve_tenant_context),
):
    """
    Returns the configured distributed rate limiting quotas and enforcement tiers.
    """
    quotas = {
        str(category): {
            "limit": quota.limit,
            "window_seconds": quota.window_seconds,
            "description": f"{quota.limit} requests per {quota.window_seconds}s",
        }
        for category, quota in RATE_LIMIT_QUOTAS.items()
    }

    return {
        "tenant_id": tenant.tenant_id,
        "algorithm": "SLIDING_WINDOW_LUA",
        "backend": "REDIS_SORTED_SET",
        "enforcement_tiers": quotas,
    }


@router.get("/v1/system/event-processing")
async def get_event_processing_status(
    db: AsyncSession = Depends(get_db_session),
    tenant: TenantContext = Depends(resolve_tenant_context),
):
    """
    Returns consumer lag, pending outbox events, and event bus status.
    """
    res = await db.execute(
        select(func.count(OutboxEvent.id)).where(
            OutboxEvent.tenant_id == tenant.tenant_id,
            OutboxEvent.status == "PENDING",
        )
    )
    tenant_pending = res.scalar() or 0

    return {
        "tenant_id": tenant.tenant_id,
        "event_bus": "REDIS_STREAMS",
        "consumer_group": "privguard_workers",
        "tenant_pending_outbox_events": tenant_pending,
    }

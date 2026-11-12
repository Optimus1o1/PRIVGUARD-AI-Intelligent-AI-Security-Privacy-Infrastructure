"""PRIVGUARD AI - Prometheus Metrics Scrape Endpoint.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

from fastapi import APIRouter, Response, Header, HTTPException, status
from app.core.config import settings
from app.observability.metrics import get_metrics_snapshot

router = APIRouter(tags=["Observability & Metrics"])


@router.get("/metrics")
async def prometheus_metrics(
    authorization: str = Header(default="", alias="Authorization"),
    x_metrics_token: str = Header(default="", alias="X-Metrics-Token"),
):
    """
    Prometheus pull metrics endpoint.
    Exposes application and security metrics in Prometheus exposition format.
    Low-cardinality labels only. Zero user prompt or sensitive data leakage.
    """
    # If METRICS_PROTECTED is enabled in production, verify token
    metrics_token = getattr(settings, "METRICS_SCRAPE_TOKEN", None)
    if metrics_token:
        provided = x_metrics_token or (
            authorization.replace("Bearer ", "") if authorization.startswith("Bearer ") else ""
        )
        if provided != metrics_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid metrics scrape credentials",
            )

    content = get_metrics_snapshot()
    return Response(
        content=content,
        media_type="text/plain; version=0.0.4; charset=utf-8",
    )

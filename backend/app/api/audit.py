"""Security Audit & Monitoring Query API."""

import json
from datetime import datetime
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.authentication import get_current_app
from app.database.connection import get_db_session
from app.database.models import Application
from app.monitoring.audit import audit_logger

router = APIRouter(prefix="/v1/audit", tags=["Audit & Monitoring"])


class AuditEventResponse(BaseModel):
    id: str
    request_id: str
    app_id: Optional[str]
    event_type: str
    data_category: Optional[str]
    action_taken: str
    risk_level: str
    entity_counts: Dict[str, Any]
    content_fingerprint: Optional[str]
    status: str
    timestamp: datetime


@router.get("/events", response_model=List[AuditEventResponse])
async def list_audit_events(
    event_type: Optional[str] = Query(None, description="Filter by event type"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> List[AuditEventResponse]:
    """
    Returns security audit events for monitoring.
    Strictly content-free: contains zero prompt/response/secret text.
    """
    # Non-admin applications can only query their own events
    query_app_id = current_app.id if current_app.id != "app_master_admin" else None
    events = await audit_logger.get_events(
        db=db,
        app_id=query_app_id,
        event_type=event_type,
        limit=limit,
        offset=offset,
    )

    return [
        AuditEventResponse(
            id=ev.id,
            request_id=ev.request_id,
            app_id=ev.app_id,
            event_type=ev.event_type,
            data_category=ev.data_category,
            action_taken=ev.action_taken,
            risk_level=ev.risk_level,
            entity_counts=json.loads(ev.entity_counts) if ev.entity_counts else {},
            content_fingerprint=ev.content_fingerprint,
            status=ev.status,
            timestamp=ev.timestamp,
        )
        for ev in events
    ]


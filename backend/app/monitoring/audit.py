"""Security audit logging module.
Guarantees content-free audit records (zero raw prompt/response storage).
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from app.database.models import AuditEvent


class AuditLogger:
    """Records security audit events without persisting sensitive content."""

    async def log_event(
        self,
        db: AsyncSession,
        request_id: str,
        app_id: Optional[str],
        event_type: str,
        action_taken: str,
        risk_level: str,
        data_category: Optional[str] = None,
        entity_counts: Optional[Dict[str, int]] = None,
        content_fingerprint: Optional[str] = None,
        status: str = "SUCCESS",
    ) -> AuditEvent:
        """
        Persists a content-free audit event record.
        Strictly excludes raw text, completions, and sensitive strings.
        """
        event = AuditEvent(
            request_id=request_id,
            app_id=app_id,
            event_type=event_type,
            data_category=data_category,
            action_taken=action_taken,
            risk_level=risk_level,
            entity_counts=json.dumps(entity_counts or {}),
            content_fingerprint=content_fingerprint,
            status=status,
            timestamp=datetime.now(timezone.utc),
        )
        db.add(event)
        await db.commit()
        await db.refresh(event)
        return event

    async def get_events(
        self,
        db: AsyncSession,
        app_id: Optional[str] = None,
        event_type: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[AuditEvent]:
        """Queries historical audit events."""
        query = select(AuditEvent).order_by(desc(AuditEvent.timestamp)).offset(offset).limit(limit)
        if app_id:
            query = query.where(AuditEvent.app_id == app_id)
        if event_type:
            query = query.where(AuditEvent.event_type == event_type)

        result = await db.execute(query)
        return list(result.scalars().all())


# Shared audit logger instance
audit_logger = AuditLogger()

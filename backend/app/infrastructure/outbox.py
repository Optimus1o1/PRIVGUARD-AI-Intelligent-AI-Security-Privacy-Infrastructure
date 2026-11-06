"""Transactional Outbox Pattern for Distributed Security State Events.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, update
import redis.asyncio as aioredis
from app.database.models import OutboxEvent, utcnow
from app.infrastructure.redis_client import RedisNamespace, format_redis_key, get_redis

logger = logging.getLogger("privguard.outbox")


def emit_outbox_event(
    session: AsyncSession,
    event_type: str,
    aggregate_id: str,
    payload: Dict[str, Any],
    tenant_id: str = "default_tenant",
    workspace_id: Optional[str] = None,
    aggregate_version: int = 1,
) -> OutboxEvent:
    """
    Creates an OutboxEvent within the active database transaction.
    Guarantees atomic commit between security state changes and event logs.
    """
    # Sanitize payload: strip any forbidden secret keys
    sanitized_payload = {
        k: v
        for k, v in payload.items()
        if not any(secret_term in k.lower() for secret_term in ("secret", "password", "token", "key", "dek", "kek"))
    }

    event = OutboxEvent(
        tenant_id=tenant_id,
        workspace_id=workspace_id,
        event_type=event_type,
        aggregate_id=aggregate_id,
        aggregate_version=aggregate_version,
        payload=json.dumps(sanitized_payload, sort_keys=True),
        status="PENDING",
        retry_count=0,
        created_at=utcnow(),
    )
    session.add(event)
    return event


class OutboxPublisher:
    """Transfers pending transactional outbox events to Redis Streams and Pub/Sub."""

    def __init__(self, custom_redis: Optional[aioredis.Redis] = None) -> None:
        self._custom_redis = custom_redis

    def _get_client(self) -> Optional[aioredis.Redis]:
        return self._custom_redis or get_redis()

    async def publish_pending_events(self, db: AsyncSession, batch_size: int = 50) -> int:
        """
        Polls uncommitted outbox events, pushes to Redis Streams, and updates event status.
        Returns count of successfully published events.
        """
        redis_client = self._get_client()
        if not redis_client:
            logger.debug("Redis client unavailable; outbox events remain pending in PostgreSQL.")
            return 0

        # Query pending events ordered by creation
        query = (
            select(OutboxEvent)
            .where(OutboxEvent.status == "PENDING")
            .order_by(OutboxEvent.created_at.asc())
            .limit(batch_size)
        )
        res = await db.execute(query)
        events = res.scalars().all()

        published_count = 0
        now = utcnow()

        for event in events:
            stream_key = format_redis_key(RedisNamespace.STREAM_EVENTS, event.tenant_id)
            channel_key = format_redis_key(RedisNamespace.CHANNEL_EVENTS, event.tenant_id)

            message_data = {
                "event_id": str(event.id),
                "tenant_id": str(event.tenant_id),
                "event_type": str(event.event_type),
                "aggregate_id": str(event.aggregate_id),
                "aggregate_version": str(event.aggregate_version),
                "payload": str(event.payload),
                "created_at": event.created_at.isoformat(),
            }

            try:
                # 1. Persistent Redis Stream entry
                await redis_client.xadd(stream_key, message_data, maxlen=10000)

                # 2. Ephemeral Pub/Sub notification for fast invalidation
                await redis_client.publish(
                    channel_key,
                    json.dumps(
                        {
                            "event_type": event.event_type,
                            "aggregate_id": event.aggregate_id,
                            "tenant_id": event.tenant_id,
                        }
                    ),
                )

                event.status = "PUBLISHED"
                event.published_at = now
                event.last_attempt_at = now
                published_count += 1
            except Exception as exc:
                event.retry_count += 1
                event.last_attempt_at = now
                logger.warning("Failed to publish outbox event %s: %s", event.id, exc)
                if event.retry_count >= 5:
                    event.status = "DEAD_LETTER"
                    # Mirror to dead-letter stream if possible
                    try:
                        dl_key = format_redis_key("stream:dead_letter", event.tenant_id)
                        await redis_client.xadd(dl_key, message_data)
                    except Exception:
                        pass

        if events:
            await db.commit()

        return published_count

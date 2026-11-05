"""Redis Streams Event Bus with Consumer Groups and Idempotent Dispatch.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import json
import logging
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set
import redis.asyncio as aioredis
from app.infrastructure.redis_client import RedisNamespace, format_redis_key, get_redis

logger = logging.getLogger("privguard.event_bus")

# Event Handler Type: async function taking event dict
EventHandler = Callable[[Dict[str, Any]], Coroutine[Any, Any, None]]


class EventBus:
    """Manages persistent stream processing, consumer groups, and idempotency."""

    def __init__(
        self,
        group_name: str = "privguard_workers",
        consumer_name: str = "worker_node_1",
        custom_redis: Optional[aioredis.Redis] = None,
    ) -> None:
        self.group_name = group_name
        self.consumer_name = consumer_name
        self._custom_redis = custom_redis
        self._handlers: Dict[str, List[EventHandler]] = {}
        # In-memory deduplication set for processed event IDs
        self._processed_events: Set[str] = set()

    def _get_client(self) -> Optional[aioredis.Redis]:
        return self._custom_redis or get_redis()

    def subscribe(self, event_type: str, handler: EventHandler) -> None:
        """Registers an asynchronous event handler for a specific security event type."""
        self._handlers.setdefault(event_type, []).append(handler)

    async def ensure_consumer_group(self, stream_key: str) -> None:
        """Creates consumer group on the specified stream if not already existing."""
        client = self._get_client()
        if not client:
            return
        try:
            await client.xgroup_create(stream_key, self.group_name, id="0", mkstream=True)
            logger.info("Created consumer group '%s' on stream '%s'.", self.group_name, stream_key)
        except Exception as exc:
            # Group already exists is expected on startup
            if "BUSYGROUP" not in str(exc):
                logger.warning("Could not create consumer group: %s", exc)

    async def read_and_dispatch(
        self, stream_key: str, count: int = 10, block_ms: int = 1000
    ) -> int:
        """
        Pulls messages from the consumer group, executes registered handlers idempotently,
        and acknowledges (XACK) upon successful processing.
        """
        client = self._get_client()
        if not client:
            return 0

        await self.ensure_consumer_group(stream_key)

        try:
            entries = await client.xreadgroup(
                self.group_name,
                self.consumer_name,
                {stream_key: ">"},
                count=count,
                block=block_ms,
            )
        except Exception as exc:
            logger.warning("Failed to read from stream %s: %s", stream_key, exc)
            return 0

        if not entries:
            return 0

        processed_count = 0

        for stream, messages in entries:
            for message_id, raw_fields in messages:
                event_id = raw_fields.get("event_id", message_id)
                event_type = raw_fields.get("event_type")

                # Idempotency check: Skip if already processed in this runtime
                if event_id in self._processed_events:
                    await client.xack(stream_key, self.group_name, message_id)
                    continue

                payload_str = raw_fields.get("payload", "{}")
                try:
                    payload = json.loads(payload_str)
                except Exception:
                    payload = {}

                event_dict = {
                    "event_id": event_id,
                    "stream_message_id": message_id,
                    "tenant_id": raw_fields.get("tenant_id", "default_tenant"),
                    "event_type": event_type,
                    "aggregate_id": raw_fields.get("aggregate_id"),
                    "aggregate_version": int(raw_fields.get("aggregate_version", 1)),
                    "payload": payload,
                    "created_at": raw_fields.get("created_at"),
                }

                # Dispatch to registered handlers
                handlers = self._handlers.get(event_type, [])
                handler_failed = False

                for handler in handlers:
                    try:
                        await handler(event_dict)
                    except Exception as handler_exc:
                        logger.error("Handler error for event %s: %s", event_type, handler_exc)
                        handler_failed = True
                        break

                if not handler_failed:
                    # Acknowledge stream message
                    await client.xack(stream_key, self.group_name, message_id)
                    self._processed_events.add(event_id)
                    processed_count += 1
                else:
                    logger.warning("Event %s failed handler execution; message left unacked for retry.", event_id)

        return processed_count


RedisEventBus = EventBus

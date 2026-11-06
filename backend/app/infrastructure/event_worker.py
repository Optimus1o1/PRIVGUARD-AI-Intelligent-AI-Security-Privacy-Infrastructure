"""Background Event Worker for Outbox Publishing and Stream Ingestion.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import asyncio
import logging
from typing import Optional
from app.database.connection import AsyncSessionLocal
from app.infrastructure.event_bus import EventBus
from app.infrastructure.outbox import OutboxPublisher
from app.infrastructure.redis_client import RedisNamespace, format_redis_key, get_redis

logger = logging.getLogger("privguard.worker")


class EventWorker:
    """Manages continuous background processing of Outbox events and Redis Streams."""

    def __init__(
        self,
        event_bus: Optional[EventBus] = None,
        publisher: Optional[OutboxPublisher] = None,
        poll_interval: float = 1.0,
    ) -> None:
        self.event_bus = event_bus or EventBus()
        self.publisher = publisher or OutboxPublisher()
        self.poll_interval = poll_interval
        self._is_running = False
        self._worker_task: Optional[asyncio.Task] = None

    async def start(self) -> None:
        """Starts the worker loop in the background."""
        self._is_running = True
        self._worker_task = asyncio.create_task(self._run_loop())
        logger.info("EventWorker started successfully.")

    async def stop(self) -> None:
        """Stops the worker loop gracefully."""
        self._is_running = False
        if self._worker_task:
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
            self._worker_task = None
        logger.info("EventWorker stopped.")

    async def _run_loop(self) -> None:
        """Main loop: transfers outbox records and dispatches stream messages."""
        default_stream = format_redis_key(RedisNamespace.STREAM_EVENTS, "default_tenant")

        while self._is_running:
            try:
                # 1. Transfer pending outbox records from PostgreSQL to Redis Streams
                async with AsyncSessionLocal() as session:
                    await self.publisher.publish_pending_events(session, batch_size=20)

                # 2. Ingest and dispatch stream events
                await self.event_bus.read_and_dispatch(default_stream, count=10, block_ms=500)

            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.error("Error in EventWorker loop: %s", exc)

            await asyncio.sleep(self.poll_interval)


# Global singleton worker
worker_instance = EventWorker()


if __name__ == "__main__":
    import signal

    async def main():
        logging.basicConfig(level=logging.INFO)
        from app.infrastructure.redis_client import init_redis

        await init_redis()
        worker = EventWorker()
        await worker.start()

        stop_event = asyncio.Event()

        def signal_handler():
            stop_event.set()

        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, signal_handler)
            except NotImplementedError:
                pass

        await stop_event.wait()
        await worker.stop()

    asyncio.run(main())

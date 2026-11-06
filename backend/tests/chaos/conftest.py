"""Deterministic Chaos Engineering Fixtures & Failure Injection Harnesses.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

import asyncio
import os
import tempfile
from typing import Any, Dict, List, Optional
import pytest
from httpx import AsyncClient, ASGITransport
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy import text

from app.core.config import settings
from app.database.connection import Base
from app.main import app


class ChaosRedisClient:
    """
    Deterministic Chaos Redis Client.
    Simulates network partitions, total outages, latency spikes, and corruptions.
    """

    def __init__(self, initial_online: bool = True):
        self.is_online = initial_online
        self.latency_seconds: float = 0.0
        self.store: Dict[str, Any] = {}
        self.zsets: Dict[str, List[tuple]] = {}
        self.streams: Dict[str, List[Dict[str, Any]]] = {}
        self.published_messages: List[Dict[str, Any]] = []

    def set_online(self, online: bool):
        self.is_online = online

    def set_latency(self, seconds: float):
        self.latency_seconds = seconds

    async def _simulate_network(self):
        if not self.is_online:
            import redis.exceptions

            raise redis.exceptions.ConnectionError("Chaos injection: Redis connection failed / network partition")
        if self.latency_seconds > 0:
            await asyncio.sleep(self.latency_seconds)

    async def ping(self) -> bool:
        await self._simulate_network()
        return True

    async def get(self, key: str) -> Optional[str]:
        await self._simulate_network()
        return self.store.get(key)

    async def set(self, key: str, value: str, ex: Optional[int] = None) -> bool:
        await self._simulate_network()
        self.store[key] = value
        return True

    async def delete(self, *keys: str) -> int:
        await self._simulate_network()
        count = 0
        for k in keys:
            if k in self.store:
                del self.store[k]
                count += 1
            if k in self.zsets:
                del self.zsets[k]
                count += 1
        return count

    async def eval(self, script: str, numkeys: int, *args: Any) -> List[Any]:
        await self._simulate_network()
        # Emulate the sliding-window rate limit lua script deterministically
        if "ZREMRANGEBYSCORE" in script:
            key = args[0]
            now_ms = int(args[1])
            window_ms = int(args[2])
            max_requests = int(args[3])
            req_id = str(args[4])
            clear_before = now_ms - window_ms

            entries = self.zsets.setdefault(key, [])
            # Purge expired
            entries = [e for e in entries if e[0] >= clear_before]
            self.zsets[key] = entries

            if len(entries) < max_requests:
                entries.append((now_ms, req_id))
                remaining = max_requests - len(entries)
                return [1, remaining, 0]
            else:
                oldest_ts = entries[0][0] if entries else now_ms
                retry_after_ms = max(0, (oldest_ts + window_ms) - now_ms)
                retry_sec = max(1, (retry_after_ms + 999) // 1000)
                return [0, 0, retry_sec]

        return [1, 0, 0]

    async def xadd(self, name: str, fields: Dict[str, Any], maxlen: Optional[int] = None) -> str:
        await self._simulate_network()
        stream = self.streams.setdefault(name, [])
        entry_id = f"{len(stream) + 1}-0"
        stream.append({"id": entry_id, "data": fields})
        return entry_id

    async def publish(self, channel: str, message: str) -> int:
        await self._simulate_network()
        self.published_messages.append({"channel": channel, "message": message})
        return 1


class ChaosKMSProvider:
    """
    Deterministic Chaos KMS Provider.
    Simulates KMS throttling, service timeouts, and decryption failures.
    """

    def __init__(self):
        self.is_available: bool = True
        self.should_timeout: bool = False
        self.should_fail_unwrap: bool = False

    def wrap_dek(self, key_id: str, plaintext_dek: bytes, tenant_id: str) -> bytes:
        if not self.is_available:
            raise RuntimeError("Chaos injection: KMS service unavailable (HTTP 503)")
        if self.should_timeout:
            raise TimeoutError("Chaos injection: KMS wrap operation timed out after 5.0s")
        # Deterministic mock wrap: prepend b"KMS_WRAPPED:"
        return b"KMS_WRAPPED:" + plaintext_dek

    def unwrap_dek(self, key_id: str, wrapped_dek: bytes, tenant_id: str) -> bytes:
        if not self.is_available:
            raise RuntimeError("Chaos injection: KMS service unavailable (HTTP 503)")
        if self.should_timeout:
            raise TimeoutError("Chaos injection: KMS unwrap operation timed out after 5.0s")
        if self.should_fail_unwrap or not wrapped_dek.startswith(b"KMS_WRAPPED:"):
            raise ValueError("Chaos injection: KMS Decryption failed / Invalid ciphertext tag")
        return wrapped_dek[len(b"KMS_WRAPPED:") :]


@pytest.fixture
def chaos_redis():
    """Provides a controllable ChaosRedisClient."""
    return ChaosRedisClient(initial_online=True)


@pytest.fixture
def chaos_kms():
    """Provides a controllable ChaosKMSProvider."""
    return ChaosKMSProvider()


@pytest.fixture
async def chaos_db_factory():
    """Provides a temporary WAL-enabled SQLite session factory supporting concurrent async sessions."""
    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    test_engine = create_async_engine(
        f"sqlite+aiosqlite:///{db_path}",
        connect_args={"check_same_thread": False, "timeout": 30.0},
    )
    async with test_engine.begin() as conn:
        await conn.execute(text("PRAGMA journal_mode=WAL;"))
        await conn.run_sync(Base.metadata.create_all)

    session_factory = async_sessionmaker(
        bind=test_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    try:
        yield session_factory
    finally:
        await test_engine.dispose()
        try:
            if os.path.exists(db_path):
                os.remove(db_path)
            wal_file = f"{db_path}-wal"
            if os.path.exists(wal_file):
                os.remove(wal_file)
            shm_file = f"{db_path}-shm"
            if os.path.exists(shm_file):
                os.remove(shm_file)
        except Exception:
            pass


@pytest.fixture
async def chaos_db_session(chaos_db_factory):
    """Provides an isolated database session for chaos testing."""
    async with chaos_db_factory() as session:
        yield session


@pytest.fixture
async def chaos_api_client():
    """Provides an HTTP test client connected to the application ASGI app."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client

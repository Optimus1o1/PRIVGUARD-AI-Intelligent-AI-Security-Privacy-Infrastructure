"""Base resource classes for synchronous and asynchronous endpoints."""

from privguard_sdk.transport.async_transport import AsyncTransport
from privguard_sdk.transport.sync import SyncTransport


class SyncResource:
    """Base class for synchronous resource handlers."""

    def __init__(self, transport: SyncTransport) -> None:
        self._transport = transport


class AsyncResource:
    """Base class for asynchronous resource handlers."""

    def __init__(self, transport: AsyncTransport) -> None:
        self._transport = transport


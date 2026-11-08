"""Abstract transport interfaces for PRIVGUARD SDK."""

from abc import ABC, abstractmethod

from privguard_sdk.config import PrivGuardConfig


class BaseTransport(ABC):
    """Abstract base class for synchronous and asynchronous HTTP transports."""

    def __init__(self, config: PrivGuardConfig) -> None:
        self.config = config

    @abstractmethod
    def close(self) -> None:
        """Closes transport connections."""

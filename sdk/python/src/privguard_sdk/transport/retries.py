"""Idempotency-aware retry policy and backoff calculation for PRIVGUARD SDK.

Moon Sanctum Labs - Decode. Build. Evolve.
"""

import random


class RetryPolicy:
    """Calculates backoff delays and determines retry eligibility.

    CRITICAL SECURITY INVARIANT:
    Non-idempotent operations (POST, PATCH, DELETE) are NEVER retried automatically
    upon network timeout or uncertain server state to prevent duplicate capability
    issuance, approval double-spends, or duplicate memory mutations.
    """

    IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 0.5,
        max_delay: float = 8.0,
    ) -> None:
        self.max_retries = max(0, max_retries)
        self.base_delay = base_delay
        self.max_delay = max_delay

    @classmethod
    def is_idempotent(cls, method: str) -> bool:
        """Determines if the HTTP method is mathematically idempotent."""
        return method.upper() in cls.IDEMPOTENT_METHODS

    def should_retry(
        self,
        method: str,
        attempt: int,
        status_code: int | None = None,
        is_network_error: bool = False,
    ) -> bool:
        """Determines whether a failed request should be retried."""
        if attempt >= self.max_retries:
            return False

        # If method is not idempotent, never automatically retry
        if not self.is_idempotent(method):
            return False

        # Retrying network drops or connection timeouts for idempotent reads is safe
        if is_network_error:
            return True

        # Retry transient server errors and rate limits for idempotent reads
        if status_code in (429, 502, 503, 504):
            return True

        return False

    def compute_delay(self, attempt: int, retry_after: float | None = None) -> float:
        """Computes exponential backoff with full jitter, respecting Retry-After."""
        if retry_after is not None and retry_after > 0:
            return min(retry_after, self.max_delay)

        # Full jitter exponential backoff: delay * 2^attempt * uniform(0.75, 1.25)
        raw_backoff = self.base_delay * (2**attempt)
        jitter = random.uniform(0.75, 1.25)
        return min(self.max_delay, raw_backoff * jitter)

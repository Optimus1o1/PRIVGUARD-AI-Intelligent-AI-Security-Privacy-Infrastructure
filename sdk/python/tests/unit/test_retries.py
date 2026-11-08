"""Unit tests for idempotency-aware retries and backoff calculation."""

from privguard_sdk.transport.retries import RetryPolicy


def test_idempotency_classification():
    assert RetryPolicy.is_idempotent("GET") is True
    assert RetryPolicy.is_idempotent("HEAD") is True
    assert RetryPolicy.is_idempotent("OPTIONS") is True

    assert RetryPolicy.is_idempotent("POST") is False
    assert RetryPolicy.is_idempotent("PATCH") is False
    assert RetryPolicy.is_idempotent("DELETE") is False
    assert RetryPolicy.is_idempotent("PUT") is False


def test_should_retry_invariants():
    policy = RetryPolicy(max_retries=3, base_delay=0.1)

    # 1. Non-idempotent writes must NEVER retry automatically even on network crash
    assert policy.should_retry("POST", attempt=1, is_network_error=True) is False
    assert policy.should_retry("POST", attempt=1, status_code=503) is False
    assert policy.should_retry("PATCH", attempt=1, status_code=429) is False
    assert policy.should_retry("DELETE", attempt=1, status_code=504) is False

    # 2. Idempotent reads retry on network error, 429, 502, 503, 504
    assert policy.should_retry("GET", attempt=1, is_network_error=True) is True
    assert policy.should_retry("GET", attempt=1, status_code=429) is True
    assert policy.should_retry("GET", attempt=1, status_code=503) is True
    assert policy.should_retry("GET", attempt=2, status_code=502) is True

    # 3. Non-retryable client errors on GET must not retry
    assert policy.should_retry("GET", attempt=1, status_code=401) is False
    assert policy.should_retry("GET", attempt=1, status_code=403) is False
    assert policy.should_retry("GET", attempt=1, status_code=404) is False

    # 4. Exhausted attempts must stop
    assert policy.should_retry("GET", attempt=3, status_code=503) is False


def test_compute_delay():
    policy = RetryPolicy(max_retries=3, base_delay=0.5, max_delay=4.0)

    # Explicit Retry-After header
    delay = policy.compute_delay(attempt=1, retry_after=2.0)
    assert delay == 2.0

    # Exponential jittered delay
    d0 = policy.compute_delay(attempt=0)
    assert 0.3 <= d0 <= 0.7  # 0.5 * 2^0 * [0.75, 1.25]

    d1 = policy.compute_delay(attempt=1)
    assert 0.7 <= d1 <= 1.3  # 0.5 * 2^1 * [0.75, 1.25]


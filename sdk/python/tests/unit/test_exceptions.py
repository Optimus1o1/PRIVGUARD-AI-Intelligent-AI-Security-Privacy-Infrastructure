"""Unit tests for exception hierarchy and error parsing."""

from privguard_sdk.exceptions import (
    AuthenticationError,
    AuthorizationError,
    ConflictError,
    NotFoundError,
    PayloadTooLargeError,
    PrivGuardError,
    RateLimitError,
    ServerError,
    ValidationError,
    exception_from_response,
)


def test_exception_hierarchy():
    err = AuthenticationError("Invalid key", request_id="req_123")
    assert isinstance(err, PrivGuardError)
    assert err.status_code == 401
    assert err.error_code == "AUTHENTICATION_FAILED"
    assert err.request_id == "req_123"
    assert err.retryable is False
    assert "[AUTHENTICATION_FAILED]" in str(err)
    assert "req_123" in str(err)


def test_exception_from_response_mapping():
    # 401
    e401 = exception_from_response(401, {"error": {"message": "Bad key"}}, request_id="r1")
    assert isinstance(e401, AuthenticationError)
    assert e401.message == "Bad key"

    # 403
    e403 = exception_from_response(403, {"error": {"message": "Forbidden", "code": "NO_ACCESS"}})
    assert isinstance(e403, AuthorizationError)
    assert e403.error_code == "NO_ACCESS"

    # 404
    e404 = exception_from_response(404, {"detail": "Agent not found"})
    assert isinstance(e404, NotFoundError)
    assert "Agent not found" in e404.message

    # 409
    e409 = exception_from_response(409, {"error": {"message": "Replay detected", "code": "REPLAY"}})
    assert isinstance(e409, ConflictError)

    # 413
    e413 = exception_from_response(413, {"error": {"message": "Too large"}})
    assert isinstance(e413, PayloadTooLargeError)

    # 422
    e422 = exception_from_response(422, {"detail": "Unprocessable entity"})
    assert isinstance(e422, ValidationError)

    # 429 with retry_after
    e429 = exception_from_response(429, {"error": {"message": "Rate limit"}}, retry_after=5.5)
    assert isinstance(e429, RateLimitError)
    assert e429.retry_after == 5.5
    assert e429.retryable is True

    # 500
    e500 = exception_from_response(500, {"error": {"message": "DB down"}})
    assert isinstance(e500, ServerError)
    assert e500.retryable is False

    # 503
    e503 = exception_from_response(503, {"error": {"message": "Fail closed"}})
    assert isinstance(e503, ServerError)
    assert e503.retryable is True


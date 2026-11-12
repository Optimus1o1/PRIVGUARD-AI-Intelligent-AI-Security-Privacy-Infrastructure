"""Hierarchical, status-coded, and safe exception hierarchy for PRIVGUARD SDK.

Moon Sanctum Labs - Decode. Build. Evolve.
"""

from typing import Any


class PrivGuardError(Exception):
    """Base exception for all PRIVGUARD SDK errors.

    Guarantees that raw credentials, private keys, or sensitive payload data
    are never leaked into exception string representations.
    """

    def __init__(
        self,
        message: str,
        status_code: int | None = None,
        error_code: str | None = None,
        details: dict[str, Any] | None = None,
        request_id: str | None = None,
        retryable: bool = False,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.details = details or {}
        self.request_id = request_id
        self.retryable = retryable

    def __repr__(self) -> str:
        parts = [f"message={self.message!r}"]
        if self.status_code:
            parts.append(f"status_code={self.status_code}")
        if self.error_code:
            parts.append(f"error_code={self.error_code!r}")
        if self.request_id:
            parts.append(f"request_id={self.request_id!r}")
        parts.append(f"retryable={self.retryable}")
        return f"{self.__class__.__name__}({', '.join(parts)})"

    def __str__(self) -> str:
        base = self.message
        if self.error_code:
            base = f"[{self.error_code}] {base}"
        if self.status_code:
            base = f"(HTTP {self.status_code}) {base}"
        if self.request_id:
            base = f"{base} [Request ID: {self.request_id}]"
        return base


class AuthenticationError(PrivGuardError):
    """Raised when authentication fails (HTTP 401: Invalid or missing API key)."""

    def __init__(
        self,
        message: str = "Authentication failed. Provide a valid API key via 'X-API-Key' or 'Authorization: Bearer'.",
        details: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=401,
            error_code="AUTHENTICATION_FAILED",
            details=details,
            request_id=request_id,
            retryable=False,
        )


class AuthorizationError(PrivGuardError):
    """Raised when caller lacks permission for the requested action or tenant (HTTP 403)."""

    def __init__(
        self,
        message: str = "Access forbidden. Caller lacks required permission or tenant scope.",
        error_code: str = "PERMISSION_DENIED",
        details: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=403,
            error_code=error_code,
            details=details,
            request_id=request_id,
            retryable=False,
        )


class NotFoundError(PrivGuardError):
    """Raised when the requested resource is not found (HTTP 404)."""

    def __init__(
        self,
        message: str = "Requested resource not found.",
        details: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=404,
            error_code="NOT_FOUND",
            details=details,
            request_id=request_id,
            retryable=False,
        )


class ConflictError(PrivGuardError):
    """Raised when a state conflict or anti-replay violation occurs (HTTP 409)."""

    def __init__(
        self,
        message: str = "Resource state conflict or anti-replay violation.",
        error_code: str = "STATE_CONFLICT",
        details: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=409,
            error_code=error_code,
            details=details,
            request_id=request_id,
            retryable=False,
        )


class PayloadTooLargeError(PrivGuardError):
    """Raised when the request payload exceeds edge bounding limits (HTTP 413)."""

    def __init__(
        self,
        message: str = "Request payload exceeds maximum allowed size limit.",
        details: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=413,
            error_code="PAYLOAD_TOO_LARGE",
            details=details,
            request_id=request_id,
            retryable=False,
        )


class ValidationError(PrivGuardError):
    """Raised when input parameters fail schema validation (HTTP 422)."""

    def __init__(
        self,
        message: str = "Input validation failed.",
        details: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=422,
            error_code="VALIDATION_ERROR",
            details=details,
            request_id=request_id,
            retryable=False,
        )


class RateLimitError(PrivGuardError):
    """Raised when distributed rate limits or step quotas are exceeded (HTTP 429)."""

    def __init__(
        self,
        message: str = "Rate limit or execution quota exceeded.",
        retry_after: float | None = None,
        details: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=429,
            error_code="RATE_LIMIT_EXCEEDED",
            details=details,
            request_id=request_id,
            retryable=True,
        )
        self.retry_after = retry_after


class ServerError(PrivGuardError):
    """Raised when PRIVGUARD AI encounters an internal error or fail-closed state (HTTP 500, 502, 503, 504)."""

    def __init__(
        self,
        message: str = "Internal security server error or service unavailable.",
        status_code: int = 500,
        error_code: str = "INTERNAL_SERVER_ERROR",
        details: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> None:
        # 502, 503, 504 are potentially retryable if the operation is idempotent
        is_retryable = status_code in (502, 503, 504)
        super().__init__(
            message=message,
            status_code=status_code,
            error_code=error_code,
            details=details,
            request_id=request_id,
            retryable=is_retryable,
        )


class ConnectionError(PrivGuardError):
    """Raised when transport connection or DNS resolution fails."""

    def __init__(
        self,
        message: str = "Failed to establish network connection to PRIVGUARD instance.",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=None,
            error_code="CONNECTION_FAILED",
            details=details,
            retryable=True,
        )


class TimeoutError(PrivGuardError):
    """Raised when a request exceeds configured connection, read, or write timeouts."""

    def __init__(
        self,
        message: str = "Request to PRIVGUARD instance timed out.",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=None,
            error_code="TIMEOUT",
            details=details,
            retryable=True,
        )


class StreamingError(PrivGuardError):
    """Raised when an error occurs during SSE stream decoding or premature termination."""

    def __init__(
        self,
        message: str = "Streaming response decoding failed or connection terminated unexpectedly.",
        details: dict[str, Any] | None = None,
        request_id: str | None = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=None,
            error_code="STREAMING_ERROR",
            details=details,
            request_id=request_id,
            retryable=False,
        )


class SignatureVerificationError(PrivGuardError):
    """Raised when cryptographic evidence, audit manifest, or artifact verification fails."""

    def __init__(
        self,
        message: str = "Cryptographic signature or artifact digest verification failed.",
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(
            message=message,
            status_code=None,
            error_code="SIGNATURE_VERIFICATION_FAILED",
            details=details,
            retryable=False,
        )


def exception_from_response(
    status_code: int,
    data: Any,
    request_id: str | None = None,
    retry_after: float | None = None,
) -> PrivGuardError:
    """Parses a backend error payload and converts it into the appropriate typed exception."""
    message = "Unknown error occurred"
    error_code = None
    details = None

    if isinstance(data, dict):
        if "error" in data and isinstance(data["error"], dict):
            err_dict = data["error"]
            message = err_dict.get("message", message)
            error_code = err_dict.get("code")
            details = err_dict.get("details")
        elif "detail" in data:
            message = str(data["detail"])
        elif "message" in data:
            message = str(data["message"])

    if status_code == 401:
        return AuthenticationError(message=message, details=details, request_id=request_id)
    if status_code == 403:
        return AuthorizationError(
            message=message, error_code=error_code or "PERMISSION_DENIED", details=details, request_id=request_id
        )
    if status_code == 404:
        return NotFoundError(message=message, details=details, request_id=request_id)
    if status_code == 409:
        return ConflictError(
            message=message, error_code=error_code or "STATE_CONFLICT", details=details, request_id=request_id
        )
    if status_code == 413:
        return PayloadTooLargeError(message=message, details=details, request_id=request_id)
    if status_code == 422:
        return ValidationError(message=message, details=details, request_id=request_id)
    if status_code == 429:
        return RateLimitError(message=message, retry_after=retry_after, details=details, request_id=request_id)
    if status_code >= 500:
        return ServerError(
            message=message,
            status_code=status_code,
            error_code=error_code or "INTERNAL_SERVER_ERROR",
            details=details,
            request_id=request_id,
        )

    return PrivGuardError(
        message=message,
        status_code=status_code,
        error_code=error_code,
        details=details,
        request_id=request_id,
        retryable=False,
    )

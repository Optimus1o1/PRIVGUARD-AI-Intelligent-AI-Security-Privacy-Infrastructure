"""Security and runtime exception taxonomy for PRIVGUARD AI."""

from typing import Any, Dict, Optional


class PrivGuardException(Exception):
    """Base exception for all PRIVGUARD security and runtime errors."""

    def __init__(
        self,
        message: str,
        status_code: int = 400,
        error_code: str = "SECURITY_VIOLATION",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.error_code = error_code
        self.details = details or {}


class AuthenticationError(PrivGuardException):
    """Raised when application authentication fails."""

    def __init__(self, message: str = "Invalid or missing application credentials"):
        super().__init__(
            message=message,
            status_code=401,
            error_code="AUTHENTICATION_FAILED",
        )


class SecretDetectedError(PrivGuardException):
    """Raised when a secret or credential is detected in input data."""

    def __init__(
        self,
        secret_type: str,
        match_preview: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            message=f"Request blocked: Sensitive credential of type '{secret_type}' was detected.",
            status_code=403,
            error_code="CRITICAL_SECRET_DETECTED",
            details={
                "secret_type": secret_type,
                "preview": match_preview,
                **(details or {}),
            },
        )


class PolicyViolationError(PrivGuardException):
    """Raised when content violates an enforced security policy."""

    def __init__(
        self,
        category: str,
        action: str,
        reason: str,
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            message=f"Security Policy Violation: Content category '{category}' triggered action '{action}'. Reason: {reason}",
            status_code=403,
            error_code="POLICY_VIOLATION",
            details={"category": category, "action": action, "reason": reason, **(details or {})},
        )


class UnauthorizedToolError(PrivGuardException):
    """Raised when an agent attempts to execute an unpermitted or expired tool."""

    def __init__(self, tool_name: str, reason: str = "Unauthorized tool execution"):
        super().__init__(
            message=f"Agent Broker Rejected: Execution of tool '{tool_name}' denied. {reason}",
            status_code=403,
            error_code="TOOL_EXECUTION_UNAUTHORIZED",
            details={"tool_name": tool_name, "reason": reason},
        )


class ApprovalRequiredError(PrivGuardException):
    """Raised when an operation requires explicit human approval before execution."""

    def __init__(self, approval_id: str, tool_name: str, message: str = "Human approval required"):
        super().__init__(
            message=message,
            status_code=402,
            error_code="HUMAN_APPROVAL_REQUIRED",
            details={"approval_id": approval_id, "tool_name": tool_name},
        )


class FailClosedError(PrivGuardException):
    """Raised when a security engine subsystem fails and fail-closed is active."""

    def __init__(self, subsystem: str, reason: str):
        super().__init__(
            message=f"Security perimeter fail-closed triggered in '{subsystem}': {reason}",
            status_code=500,
            error_code="SECURITY_FAIL_CLOSED",
            details={"subsystem": subsystem, "reason": reason},
        )


class UpstreamProviderError(PrivGuardException):
    """Raised when communication with the upstream LLM provider fails."""

    def __init__(self, message: str = "Upstream model provider encountered an error", status_code: int = 502, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            status_code=status_code,
            error_code="UPSTREAM_PROVIDER_ERROR",
            details=details or {},
        )


class UpstreamTimeoutError(PrivGuardException):
    """Raised when the upstream LLM provider exceeds the timeout limit."""

    def __init__(self, timeout_seconds: float):
        super().__init__(
            message=f"Upstream model provider timed out after {timeout_seconds} seconds.",
            status_code=504,
            error_code="UPSTREAM_TIMEOUT",
            details={"timeout_seconds": timeout_seconds},
        )


class UpstreamAuthenticationError(PrivGuardException):
    """Raised when the gateway cannot authenticate with the upstream provider."""

    def __init__(self, message: str = "Upstream provider authentication failed. Check server-side configuration."):
        super().__init__(
            message=message,
            status_code=502,
            error_code="UPSTREAM_AUTHENTICATION_ERROR",
        )


class UpstreamRateLimitError(PrivGuardException):
    """Raised when the upstream provider rate-limits requests."""

    def __init__(self, retry_after: Optional[str] = None):
        details = {"retry_after": retry_after} if retry_after else {}
        super().__init__(
            message="Upstream model provider rate limit exceeded.",
            status_code=429,
            error_code="UPSTREAM_RATE_LIMITED",
            details=details,
        )


class ResponseSecurityViolationError(PrivGuardException):
    """Raised when the model output contains a detected secret or violates policy."""

    def __init__(self, violation_type: str, preview: str, reason: str):
        super().__init__(
            message=f"Model response blocked: {reason} Detected type: '{violation_type}'.",
            status_code=502,
            error_code="RESPONSE_SECURITY_VIOLATION",
            details={
                "violation_type": violation_type,
                "preview": preview,
                "reason": reason,
            },
        )


class ModelNotConfiguredError(PrivGuardException):
    """Raised when a requested model is not registered or supported."""

    def __init__(self, model_name: str):
        super().__init__(
            message=f"Model '{model_name}' is not configured in the server provider registry.",
            status_code=400,
            error_code="MODEL_NOT_CONFIGURED",
            details={"model": model_name},
        )



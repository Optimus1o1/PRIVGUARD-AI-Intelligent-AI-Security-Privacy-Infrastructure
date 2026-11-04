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

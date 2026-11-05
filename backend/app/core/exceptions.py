"""Security and runtime exception taxonomy for PRIVGUARD AI."""

from typing import Any, Dict, List, Optional


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
        self.approval_id = approval_id
        self.tool_name = tool_name


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


class MemorySecurityError(PrivGuardException):
    """Base exception for Memory Vault security violations."""

    def __init__(self, message: str = "Memory security violation", status_code: int = 403, error_code: str = "MEMORY_SECURITY_ERROR", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            status_code=status_code,
            error_code=error_code,
            details=details or {},
        )


class MemoryTamperingError(MemorySecurityError):
    """Raised when memory ciphertext, authentication tag, or envelope metadata fails cryptographic verification."""

    def __init__(self, memory_id: str = "unknown"):
        super().__init__(
            message=f"Cryptographic verification failed for memory record '{memory_id}'. Possible tampering or corrupted key.",
            status_code=403,
            error_code="MEMORY_INTEGRITY_COMPROMISED",
            details={"memory_id": memory_id},
        )


class MemoryNotFoundError(PrivGuardException):
    """Raised when a requested memory record or proposal does not exist or access is denied."""

    def __init__(self, memory_id: str):
        super().__init__(
            message=f"Memory record '{memory_id}' not found or access denied.",
            status_code=404,
            error_code="MEMORY_NOT_FOUND",
            details={"memory_id": memory_id},
        )


class MemoryPermissionError(MemorySecurityError):
    """Raised when an agent or user lacks required granular permission for memory operation."""

    def __init__(self, operation: str, agent_id: str, resource: str = "vault"):
        super().__init__(
            message=f"Access denied: Operation '{operation}' by agent '{agent_id}' is not authorized on '{resource}'.",
            status_code=403,
            error_code="MEMORY_ACCESS_DENIED",
            details={"operation": operation, "agent_id": agent_id, "resource": resource},
        )


class MemoryPoisoningError(MemorySecurityError):
    """Raised when proposed memory content fails security inspection (prompt injection, imperative override)."""

    def __init__(self, reason: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=f"Memory proposal rejected due to poisoning / security violation: {reason}",
            status_code=400,
            error_code="MEMORY_POISONING_DETECTED",
            details=details or {},
        )


# ==============================================================================
# STAGE 8: MCP SECURITY EXCEPTIONS
# ==============================================================================

class MCPSecurityError(PrivGuardException):
    """Base exception for Model Context Protocol security gateway violations."""

    def __init__(
        self,
        message: str = "MCP security policy violation.",
        status_code: int = 403,
        error_code: str = "MCP_SECURITY_VIOLATION",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(
            message=message,
            status_code=status_code,
            error_code=error_code,
            details=details or {},
        )


class MCPSSRFError(MCPSecurityError):
    """Raised when an MCP endpoint targets loopback, private networks, or metadata services."""

    def __init__(self, destination: str, reason: str):
        super().__init__(
            message=f"SSRF protection blocked destination '{destination}': {reason}",
            status_code=403,
            error_code="MCP_SSRF_BLOCKED",
            details={"destination": destination, "reason": reason},
        )


class MCPToolPoisoningError(MCPSecurityError):
    """Raised when an external MCP tool definition contains prompt injection or imperative instructions."""

    def __init__(self, tool_name: str, reason: str, signals: Optional[List[str]] = None):
        super().__init__(
            message=f"MCP tool '{tool_name}' rejected: {reason}",
            status_code=400,
            error_code="MCP_TOOL_POISONING_DETECTED",
            details={"tool_name": tool_name, "reason": reason, "signals": signals or []},
        )


class MCPCatalogDriftError(MCPSecurityError):
    """Raised when an approved MCP tool definition changes without re-approval."""

    def __init__(self, server_id: str, tool_name: str):
        super().__init__(
            message=f"Tool definition for '{tool_name}' on server '{server_id}' has drifted and requires human re-approval.",
            status_code=403,
            error_code="MCP_CATALOG_DRIFT_UNAPPROVED",
            details={"server_id": server_id, "tool_name": tool_name},
        )


class MCPProtocolError(MCPSecurityError):
    """Raised when an MCP request violates the 2026-07-28 specification."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            status_code=400,
            error_code="MCP_PROTOCOL_VIOLATION",
            details=details or {},
        )


class MCPStdioSandboxError(MCPSecurityError):
    """Raised when a local stdio MCP server fails execution policy or sandboxing."""

    def __init__(self, command: str, reason: str):
        super().__init__(
            message=f"stdio execution blocked for '{command}': {reason}",
            status_code=403,
            error_code="MCP_STDIO_BLOCKED",
            details={"command": command, "reason": reason},
        )


class AuthorizationError(PrivGuardException):
    """Raised when an actor lacks permission to perform a requested action."""

    def __init__(self, message: str = "Access forbidden.", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            status_code=403,
            error_code="FORBIDDEN",
            details=details or {},
        )


class SecurityPolicyViolationError(PrivGuardException):
    """Raised when an operation violates cryptographic integrity or an enterprise security policy."""

    def __init__(self, message: str = "Security policy violation.", details: Optional[Dict[str, Any]] = None):
        super().__init__(
            message=message,
            status_code=403,
            error_code="SECURITY_POLICY_VIOLATION",
            details=details or {},
        )





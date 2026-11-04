"""Sandboxed demonstration tool executors with strict boundary isolation."""

import os
from pathlib import Path
from typing import Any, Dict
from app.core.exceptions import PrivGuardException

# Base sandbox directory for safe file operations
SANDBOX_DIR = Path(os.path.abspath("./sandbox")).resolve()


def ensure_sandbox():
    """Ensures the sandbox directory exists."""
    SANDBOX_DIR.mkdir(parents=True, exist_ok=True)


def resolve_sandbox_path(user_path: str) -> Path:
    """
    Resolves and strictly bounds file paths within the designated sandbox directory.
    Prevents directory traversal (../..) or absolute host filesystem access.
    """
    ensure_sandbox()
    clean_path = user_path.strip().lstrip("/\\")

    # Reject blatant directory traversal sequences
    if ".." in clean_path or clean_path.startswith("/") or clean_path.startswith("\\"):
        raise PrivGuardException(
            message=f"Path traversal rejected: '{user_path}' attempts to escape sandbox boundary.",
            status_code=403,
            error_code="PATH_TRAVERSAL_DETECTED",
        )

    resolved = (SANDBOX_DIR / clean_path).resolve()

    # Enforce jail: resolved path MUST be inside SANDBOX_DIR
    try:
        resolved.relative_to(SANDBOX_DIR)
    except ValueError:
        raise PrivGuardException(
            message=f"Access denied: '{user_path}' escapes the designated sandbox perimeter.",
            status_code=403,
            error_code="SANDBOX_BOUNDARY_VIOLATION",
        )

    return resolved


class ToolExecutor:
    """Safe execution handlers for demonstration tools."""

    @staticmethod
    async def execute_read_file(params: Dict[str, Any]) -> str:
        """Reads a file strictly jailed inside ./sandbox/."""
        path_str = params.get("path")
        if not path_str:
            raise PrivGuardException("Missing required parameter: 'path'", status_code=400)

        target_file = resolve_sandbox_path(path_str)
        if not target_file.exists() or not target_file.is_file():
            raise PrivGuardException(f"File '{path_str}' not found in sandbox.", status_code=404)

        return target_file.read_text(encoding="utf-8")

    @staticmethod
    async def execute_delete_file(params: Dict[str, Any]) -> str:
        """Deletes a file strictly jailed inside ./sandbox/."""
        path_str = params.get("path")
        if not path_str:
            raise PrivGuardException("Missing required parameter: 'path'", status_code=400)

        target_file = resolve_sandbox_path(path_str)
        if not target_file.exists():
            raise PrivGuardException(f"File '{path_str}' not found in sandbox.", status_code=404)

        target_file.unlink()
        return f"File '{path_str}' successfully deleted from sandbox."

    @staticmethod
    async def execute_search_web(params: Dict[str, Any]) -> str:
        """Simulated sandboxed web search adapter."""
        query = params.get("query")
        if not query:
            raise PrivGuardException("Missing required parameter: 'query'", status_code=400)
        domain = params.get("domain", "all")
        return f"[SEARCH_RESULTS] Top results for '{query}' (domain: {domain}): 1. Verified Public Document 2. Technical Reference Guide"

    @staticmethod
    async def execute_send_email(params: Dict[str, Any]) -> str:
        """Simulated quarantine outbound email dispatcher."""
        recipient = params.get("recipient")
        subject = params.get("subject", "No Subject")
        body = params.get("body", "")

        if not recipient:
            raise PrivGuardException("Missing required parameter: 'recipient'", status_code=400)

        return f"[EMAIL_DISPATCHED] Message to '{recipient}' queued for quarantine dispatch. Subject: '{subject}', Characters: {len(body)}"

    @staticmethod
    async def execute_code(params: Dict[str, Any]) -> str:
        """Disabled in v0.1 pending micro-sandbox containerization."""
        raise PrivGuardException(
            message="Tool 'execute_code' is disabled in PRIVGUARD AI v0.1 until containerized gVisor sandbox is active.",
            status_code=403,
            error_code="TOOL_DISABLED",
        )


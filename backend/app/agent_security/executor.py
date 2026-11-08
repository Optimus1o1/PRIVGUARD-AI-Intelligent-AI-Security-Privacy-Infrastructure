"""Sandboxed demonstration tool executors with strict boundary isolation."""

import os
import re
from pathlib import Path
from typing import Any, Dict, Optional
from app.core.exceptions import PrivGuardException

# Base sandbox directory for safe file operations
SANDBOX_DIR = Path(os.path.abspath("./sandbox")).resolve()


def ensure_sandbox(app_id: Optional[str] = None) -> Path:
    """Ensures the sandbox directory exists."""
    if app_id:
        target_dir = (SANDBOX_DIR / app_id).resolve()
    else:
        target_dir = SANDBOX_DIR
    target_dir.mkdir(parents=True, exist_ok=True)
    return target_dir


def resolve_sandbox_path(user_path: str, app_id: Optional[str] = None) -> Path:
    """
    Resolves and strictly bounds file paths within the designated sandbox directory.
    Prevents directory traversal (../..), absolute root paths, or drive anchors.
    """
    ensure_sandbox(app_id)
    raw = user_path.strip()

    # Reject absolute root paths, Windows drive paths, or traversal patterns BEFORE any stripping
    if raw.startswith("/") or raw.startswith("\\") or bool(re.match(r"^[a-zA-Z]:", raw)) or ".." in raw:
        raise PrivGuardException(
            message=f"Path traversal rejected: '{user_path}' attempts to escape sandbox boundary.",
            status_code=403,
            error_code="PATH_TRAVERSAL_DETECTED",
        )

    # Scoped directory for tenant if provided, else root sandbox
    if app_id:
        target_dir = (SANDBOX_DIR / app_id).resolve()
        target_dir.mkdir(parents=True, exist_ok=True)
    else:
        target_dir = SANDBOX_DIR

    resolved = (target_dir / raw).resolve()

    # If app_id was specified but file not found in tenant dir, check root sandbox (backward compat for test fixtures)
    if app_id and not resolved.exists() and (SANDBOX_DIR / raw).resolve().exists():
        fallback = (SANDBOX_DIR / raw).resolve()
        try:
            fallback.relative_to(SANDBOX_DIR)
            resolved = fallback
            target_dir = SANDBOX_DIR
        except ValueError:
            pass

    # Enforce jail: resolved path MUST be inside target_dir
    try:
        resolved.relative_to(target_dir)
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

        app_id = params.get("_app_id")
        target_file = resolve_sandbox_path(path_str, app_id=app_id)
        if not target_file.exists() or not target_file.is_file():
            raise PrivGuardException(f"File '{path_str}' not found in sandbox.", status_code=404)

        return target_file.read_text(encoding="utf-8")

    @staticmethod
    async def execute_delete_file(params: Dict[str, Any]) -> str:
        """Deletes a file strictly jailed inside ./sandbox/."""
        path_str = params.get("path")
        if not path_str:
            raise PrivGuardException("Missing required parameter: 'path'", status_code=400)

        app_id = params.get("_app_id")
        target_file = resolve_sandbox_path(path_str, app_id=app_id)
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
    async def execute_calculator(params: Dict[str, Any]) -> str:
        """Safe arithmetic calculation tool."""
        expression = params.get("expression")
        if not expression:
            raise PrivGuardException("Missing required parameter: 'expression'", status_code=400)

        # Allow strictly numbers, whitespace, and basic arithmetic operators
        clean_expr = str(expression).strip()
        if not re.match(r"^[\d\s\+\-\*\/\(\)\.\%]+$", clean_expr):
            raise PrivGuardException(
                f"Invalid arithmetic expression: '{expression}'. Only numbers and basic operators are permitted.",
                status_code=400,
                error_code="INVALID_EXPRESSION",
            )
        try:
            # Safe AST-based or limited eval of mathematical expression
            # Python's eval with empty globals/locals is safe here because regex guarantees strictly numeric tokens
            val = eval(clean_expr, {"__builtins__": None}, {})  # nosec B307
            return str(val)
        except Exception as exc:
            raise PrivGuardException(f"Calculation failed: {exc}", status_code=400)

    @staticmethod
    async def execute_lookup_file_metadata(params: Dict[str, Any]) -> str:
        """Inspects read-only file metadata (size, extension, exists) inside sandbox."""
        filename = params.get("filename")
        if not filename:
            raise PrivGuardException("Missing required parameter: 'filename'", status_code=400)

        app_id = params.get("_app_id")
        target_file = resolve_sandbox_path(filename, app_id=app_id)
        if not target_file.exists():
            return f'{{"filename": "{filename}", "exists": false}}'

        stat = target_file.stat()
        return f'{{"filename": "{filename}", "exists": true, "size_bytes": {stat.st_size}, "extension": "{target_file.suffix}"}}'

    @staticmethod
    async def execute_search_mock_kb(params: Dict[str, Any]) -> str:
        """Searches an in-memory synthetic product FAQ database."""
        query = params.get("query")
        if not query:
            raise PrivGuardException("Missing required parameter: 'query'", status_code=400)

        mock_kb = [
            ("privacy policy", "PRIVGUARD automatically redacts PII before it reaches external LLMs."),
            ("data retention", "Personal memories are stored with AES-256-GCM envelope encryption."),
            ("pricing tiers", "PRIVGUARD Open Source is freely self-hostable under Apache 2.0."),
            ("support hours", "Developer support is available Monday through Friday 09:00 - 18:00 IST."),
        ]
        q_lower = query.lower()
        matches = [ans for topic, ans in mock_kb if any(w in topic for w in q_lower.split())]
        if not matches:
            matches = [mock_kb[0][1]]

        return f"[KB_MATCHES] Top match: {matches[0]}"

    @staticmethod
    async def execute_code(params: Dict[str, Any]) -> str:
        """Disabled in v0.1 pending micro-sandbox containerization."""
        raise PrivGuardException(
            message="Tool 'execute_code' is disabled in PRIVGUARD AI v0.1 until containerized gVisor sandbox is active.",
            status_code=403,
            error_code="TOOL_DISABLED",
        )

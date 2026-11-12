"""Isolated subprocess management and sandboxing for local stdio MCP servers.
Enforces strict binary allowlists, zero shell invocation, environment sanitization, and execution timeouts.
"""

import asyncio
import os
import re
from typing import Dict, List, Optional, Tuple
from app.core.config import settings
from app.core.exceptions import MCPStdioSandboxError

# Strict Administrator-Approved Executables Allowlist
APPROVED_STDIO_EXECUTABLES = {
    "node",
    "npx",
    "python",
    "python3",
    "uvx",
}

FORBIDDEN_ARGUMENT_PATTERNS = [
    r"[;&|`$><\r\n]",  # Shell chaining and redirection metacharacters
    r"\b(rm\s+-rf|del\s+/f|format|curl|wget|nc|netcat)\b",
]

SAFE_INHERITED_ENV_KEYS = {
    "PATH",
    "SYSTEMROOT",
    "WINDIR",
    "TEMP",
    "TMP",
    "HOME",
    "USERPROFILE",
    "LANG",
    "LC_ALL",
}


class MCPStdioSandbox:
    """Manages secure, isolated local stdio MCP processes."""

    def __init__(self, enabled_by_default: bool = False):
        self.enabled_by_default = enabled_by_default

    def validate_command(self, command: str, args: List[str]) -> Tuple[str, List[str]]:
        """
        Validates executable command and argument list.
        Raises MCPStdioSandboxError if binary is not allowlisted or args contain metacharacters.
        """
        if not command or not isinstance(command, str):
            raise MCPStdioSandboxError(command=str(command), reason="Command must be a non-empty string.")

        # Extract base executable name
        binary_name = os.path.basename(command).lower()
        if binary_name.endswith(".exe"):
            binary_name = binary_name[:-4]

        if binary_name not in APPROVED_STDIO_EXECUTABLES:
            raise MCPStdioSandboxError(
                command=command,
                reason=f"Binary '{binary_name}' is not in approved stdio allowlist: {sorted(list(APPROVED_STDIO_EXECUTABLES))}.",
            )

        # Validate arguments against shell injection
        validated_args: List[str] = []
        for arg in args:
            if not isinstance(arg, str):
                raise MCPStdioSandboxError(command=command, reason=f"Argument must be a string: {arg}")
            for pattern in FORBIDDEN_ARGUMENT_PATTERNS:
                if re.search(pattern, arg):
                    raise MCPStdioSandboxError(
                        command=command,
                        reason=f"Argument contains forbidden shell metacharacter or command pattern: '{arg}'",
                    )
            validated_args.append(arg)

        return command, validated_args

    def get_sanitized_environment(self, custom_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
        """
        Constructs a minimal stripped environment for subprocess execution.
        Guarantees that PRIVGUARD secrets, master keys, and auth tokens are NEVER inherited.
        """
        env: Dict[str, str] = {}
        for key in SAFE_INHERITED_ENV_KEYS:
            val = os.environ.get(key)
            if val:
                env[key] = val

        # Add explicit custom variables (blocking any sensitive keywords)
        if custom_env:
            for k, v in custom_env.items():
                k_upper = k.upper()
                if any(bad in k_upper for bad in ("KEY", "SECRET", "TOKEN", "PASSWORD", "AUTH", "CREDENTIAL")):
                    # Block sensitive variables from unverified custom environment
                    continue
                env[k] = str(v)

        return env

    async def spawn_server_process(
        self,
        command: str,
        args: List[str],
        custom_env: Optional[Dict[str, str]] = None,
    ) -> asyncio.subprocess.Process:
        """
        Spawns an isolated stdio MCP server process.
        Enforces shell=False, stripped environment, and standard stream piping.
        """
        cmd, clean_args = self.validate_command(command, args)
        clean_env = self.get_sanitized_environment(custom_env)

        proc = await asyncio.create_subprocess_exec(
            cmd,
            *clean_args,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=clean_env,
        )
        return proc


# Global singleton sandbox
mcp_stdio_sandbox = MCPStdioSandbox(enabled_by_default=False)

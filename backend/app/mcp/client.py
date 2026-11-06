"""Protected MCP Client for connecting to upstream MCP servers.
Enforces SSRF validation, isolated stdio sandboxing, server-side authentication,
and strict adherence to the 2026-07-28 Model Context Protocol specification.
"""

import json
from typing import Any, Dict, List, Optional
import httpx

from app.core.exceptions import (
    MCPProtocolError,
    MCPSSRFError,
    PrivGuardException,
)
from app.mcp.ssrf import destination_validator
from app.mcp.stdio_sandbox import mcp_stdio_sandbox


class ProtectedMCPClient:
    """Manages connections to remote Streamable HTTP and local stdio MCP servers."""

    def __init__(self, timeout: float = 15.0, allow_test_loopback: bool = False):
        self.timeout = timeout
        self.allow_test_loopback = allow_test_loopback

    async def list_tools(
        self,
        endpoint_url: Optional[str] = None,
        transport_type: str = "streamable_http",
        command: Optional[str] = None,
        args: Optional[List[str]] = None,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Discovers tools from an upstream MCP server.
        Sends standard JSON-RPC 2.0 'tools/list' request with 2026-07-28 headers.
        """
        if transport_type == "streamable_http":
            if not endpoint_url:
                raise PrivGuardException("endpoint_url is required for streamable_http transport", status_code=400)

            # Enforce SSRF validation
            if not self.allow_test_loopback:
                destination_validator.validate_url(endpoint_url)

            headers = {
                "Content-Type": "application/json",
                "mcp-version": "2026-07-28",
                "mcp-method": "tools/list",
                **(auth_headers or {}),
            }
            payload = {
                "jsonrpc": "2.0",
                "id": "privguard_req_tools_list",
                "method": "tools/list",
                "params": {},
            }

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                try:
                    resp = await client.post(endpoint_url, headers=headers, json=payload)
                except httpx.RequestError as e:
                    raise PrivGuardException(f"Failed to connect to MCP server: {str(e)}", status_code=502)

                if resp.status_code != 200:
                    raise MCPProtocolError(
                        message=f"Upstream MCP server returned HTTP {resp.status_code}",
                        details={"status_code": resp.status_code, "body": resp.text[:500]},
                    )

                data = resp.json()
                if "error" in data:
                    raise MCPProtocolError(
                        message=f"MCP server error: {data['error'].get('message', 'Unknown error')}",
                        details=data["error"],
                    )

                result = data.get("result", {})
                return result.get("tools", [])

        elif transport_type == "stdio":
            if not command:
                raise PrivGuardException("command is required for stdio transport", status_code=400)
            # Stdio transport discovery
            proc = await mcp_stdio_sandbox.spawn_server_process(command, args or [])
            req = (
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": "privguard_req_stdio_list",
                        "method": "tools/list",
                        "params": {},
                    }
                )
                + "\n"
            )
            stdout, stderr = await proc.communicate(input=req.encode("utf-8"))
            if proc.returncode != 0 and not stdout:
                raise MCPProtocolError(f"stdio MCP process failed with code {proc.returncode}: {stderr.decode()[:200]}")
            data = json.loads(stdout.decode("utf-8").strip().split("\n")[-1])
            return data.get("result", {}).get("tools", [])

        raise PrivGuardException(f"Unsupported transport type '{transport_type}'", status_code=400)

    async def call_tool(
        self,
        endpoint_url: Optional[str] = None,
        transport_type: str = "streamable_http",
        command: Optional[str] = None,
        args: Optional[List[str]] = None,
        tool_name: str = "",
        arguments: Optional[Dict[str, Any]] = None,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Executes a tool on the upstream MCP server.
        Sends standard JSON-RPC 2.0 'tools/call' request with 2026-07-28 headers.
        """
        if transport_type == "streamable_http":
            if not endpoint_url:
                raise PrivGuardException("endpoint_url is required for streamable_http transport", status_code=400)

            # Enforce SSRF validation
            if not self.allow_test_loopback:
                destination_validator.validate_url(endpoint_url)

            headers = {
                "Content-Type": "application/json",
                "mcp-version": "2026-07-28",
                "mcp-method": "tools/call",
                "mcp-name": tool_name,
                **(auth_headers or {}),
            }
            payload = {
                "jsonrpc": "2.0",
                "id": f"privguard_req_call_{tool_name}",
                "method": "tools/call",
                "params": {
                    "name": tool_name,
                    "arguments": arguments or {},
                },
            }

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                try:
                    resp = await client.post(endpoint_url, headers=headers, json=payload)
                except httpx.RequestError as e:
                    raise PrivGuardException(f"Failed to communicate with MCP server: {str(e)}", status_code=502)

                if resp.status_code != 200:
                    raise MCPProtocolError(
                        message=f"Upstream MCP server returned HTTP {resp.status_code}",
                        details={"status_code": resp.status_code, "body": resp.text[:500]},
                    )

                data = resp.json()
                if "error" in data:
                    raise MCPProtocolError(
                        message=f"MCP tool call error: {data['error'].get('message', 'Unknown error')}",
                        details=data["error"],
                    )

                return data.get("result", {})

        elif transport_type == "stdio":
            if not command:
                raise PrivGuardException("command is required for stdio transport", status_code=400)
            proc = await mcp_stdio_sandbox.spawn_server_process(command, args or [])
            req = (
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": f"privguard_stdio_call_{tool_name}",
                        "method": "tools/call",
                        "params": {"name": tool_name, "arguments": arguments or {}},
                    }
                )
                + "\n"
            )
            stdout, stderr = await proc.communicate(input=req.encode("utf-8"))
            if proc.returncode != 0 and not stdout:
                raise MCPProtocolError(f"stdio process failed with code {proc.returncode}: {stderr.decode()[:200]}")
            data = json.loads(stdout.decode("utf-8").strip().split("\n")[-1])
            return data.get("result", {})

        raise PrivGuardException(f"Unsupported transport type '{transport_type}'", status_code=400)

    async def list_resources(
        self,
        endpoint_url: str,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> List[Dict[str, Any]]:
        """Lists available resources from upstream MCP server."""
        if not self.allow_test_loopback:
            destination_validator.validate_url(endpoint_url)

        headers = {
            "Content-Type": "application/json",
            "mcp-version": "2026-07-28",
            "mcp-method": "resources/list",
            **(auth_headers or {}),
        }
        payload = {
            "jsonrpc": "2.0",
            "id": "privguard_req_res_list",
            "method": "resources/list",
            "params": {},
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(endpoint_url, headers=headers, json=payload)
            if resp.status_code != 200:
                raise MCPProtocolError(f"Failed to query resources: HTTP {resp.status_code}")
            return resp.json().get("result", {}).get("resources", [])

    async def read_resource(
        self,
        endpoint_url: str,
        uri: str,
        auth_headers: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """Reads a specific resource content from upstream MCP server."""
        if not self.allow_test_loopback:
            destination_validator.validate_url(endpoint_url)

        headers = {
            "Content-Type": "application/json",
            "mcp-version": "2026-07-28",
            "mcp-method": "resources/read",
            **(auth_headers or {}),
        }
        payload = {
            "jsonrpc": "2.0",
            "id": "privguard_req_res_read",
            "method": "resources/read",
            "params": {"uri": uri},
        }
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(endpoint_url, headers=headers, json=payload)
            if resp.status_code != 200:
                raise MCPProtocolError(f"Failed to read resource '{uri}': HTTP {resp.status_code}")
            return resp.json().get("result", {})


# Global singleton client
mcp_client = ProtectedMCPClient(allow_test_loopback=False)
test_mcp_client = ProtectedMCPClient(allow_test_loopback=True)

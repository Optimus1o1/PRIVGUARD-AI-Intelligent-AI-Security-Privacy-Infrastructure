"""PRIVGUARD AI - Model Context Protocol (MCP) Python SDK Client."""

from typing import Any, Dict, List, Optional
import httpx


class PrivGuardMCPClient:
    """Client for PRIVGUARD MCP Security Gateway."""

    def __init__(
        self,
        base_url: str = "http://localhost:8000",
        api_key: Optional[str] = None,
        timeout: float = 30.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    async def register_server(
        self,
        name: str,
        transport_type: str = "streamable_http",
        endpoint_url: Optional[str] = None,
        command: Optional[str] = None,
        args: Optional[List[str]] = None,
        description: Optional[str] = None,
        auth_type: str = "NONE",
        auth_credential_ref: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Registers an upstream MCP server after server-side SSRF validation."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/v1/mcp/servers",
                headers=self._get_headers(),
                json={
                    "name": name,
                    "transport_type": transport_type,
                    "endpoint_url": endpoint_url,
                    "command": command,
                    "args": args or [],
                    "description": description,
                    "auth_type": auth_type,
                    "auth_credential_ref": auth_credential_ref,
                },
            )
            resp.raise_for_status()
            return resp.json()

    async def list_servers(self) -> List[Dict[str, Any]]:
        """Lists registered MCP servers."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(
                f"{self.base_url}/v1/mcp/servers",
                headers=self._get_headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def get_server(self, server_id: str) -> Dict[str, Any]:
        """Gets server details and catalog drift status."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(
                f"{self.base_url}/v1/mcp/servers/{server_id}",
                headers=self._get_headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def sync_catalog(self, server_id: str) -> Dict[str, Any]:
        """Discovers tools from upstream server, validates schemas, and checks for drift."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/v1/mcp/servers/{server_id}/sync",
                headers=self._get_headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def approve_catalog(self, server_id: str) -> Dict[str, Any]:
        """Approves drifted tool catalog, lifting quarantine status."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/v1/mcp/servers/{server_id}/approve",
                headers=self._get_headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def disable_server(self, server_id: str) -> Dict[str, Any]:
        """Disables an MCP server."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/v1/mcp/servers/{server_id}/disable",
                headers=self._get_headers(),
            )
            resp.raise_for_status()
            return resp.json()

    async def delete_server(self, server_id: str) -> bool:
        """Removes an MCP server registration."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.delete(
                f"{self.base_url}/v1/mcp/servers/{server_id}",
                headers=self._get_headers(),
            )
            return resp.status_code == 204

    async def list_tools(
        self,
        server_id: Optional[str] = None,
        risk_level: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Lists registered tools with risk classifications."""
        params: Dict[str, Any] = {}
        if server_id:
            params["server_id"] = server_id
        if risk_level:
            params["risk_level"] = risk_level

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(
                f"{self.base_url}/v1/mcp/tools",
                headers=self._get_headers(),
                params=params,
            )
            resp.raise_for_status()
            return resp.json()

    async def call_tool(
        self,
        server_id: str,
        tool_name: str,
        parameters: Optional[Dict[str, Any]] = None,
        agent_id: Optional[str] = None,
        task_id: Optional[str] = None,
        capability_token: Optional[str] = None,
        approval_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Executes an MCP tool with full broker security mediation."""
        payload: Dict[str, Any] = {"parameters": parameters or {}}
        if agent_id:
            payload["agent_id"] = agent_id
        if task_id:
            payload["task_id"] = task_id
        if capability_token:
            payload["capability_token"] = capability_token
        if approval_id:
            payload["approval_id"] = approval_id

        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(
                f"{self.base_url}/v1/mcp/servers/{server_id}/tools/{tool_name}/call",
                headers=self._get_headers(),
                json=payload,
            )
            resp.raise_for_status()
            return resp.json()

    async def list_activity(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Lists content-free MCP security audit events."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.get(
                f"{self.base_url}/v1/mcp/activity",
                headers=self._get_headers(),
                params={"limit": limit},
            )
            resp.raise_for_status()
            return resp.json()

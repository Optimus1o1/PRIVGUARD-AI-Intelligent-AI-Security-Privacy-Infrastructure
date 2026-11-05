"""Integration tests for PRIVGUARD MCP Gateway REST endpoints."""

import json
import socket
from unittest.mock import AsyncMock, patch
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Application, MCPServer, MCPToolDefinition


@pytest.fixture
async def sample_http_server(db_session: AsyncSession, test_app_record: Application):
    server = MCPServer(
        id="srv_api_sample_01",
        app_id=test_app_record.id,
        name="Sample Tools Server",
        description="Public developer tools",
        transport_type="streamable_http",
        endpoint_url="https://api.sample-tools.org/mcp",
        status="ACTIVE",
        trust_level="VERIFIED",
    )
    db_session.add(server)

    tool = MCPToolDefinition(
        id="tool_api_sample_01",
        server_id=server.id,
        app_id=test_app_record.id,
        name="convert_currency",
        description="Converts USD to EUR.",
        input_schema=json.dumps({"type": "object", "properties": {"amount": {"type": "number"}}}),
        risk_level="LOW",
        requires_approval=False,
        is_approved=True,
        version=1,
        definition_hash="hash_curr",
    )
    db_session.add(tool)
    await db_session.commit()
    return server


@pytest.mark.asyncio
async def test_register_server_streamable_http(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
):
    """Registers an approved streamable_http server."""
    payload = {
        "name": "GitHub MCP",
        "description": "Code and PR management",
        "transport_type": "streamable_http",
        "endpoint_url": "https://mcp.github.com/v1",
        "auth_type": "BEARER_TOKEN",
        "auth_credential_ref": "env:GH_MCP_KEY",
    }
    with patch("socket.getaddrinfo") as mock_dns:
        mock_dns.return_value = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))]
        res = await client.post("/v1/mcp/servers", headers=auth_headers, json=payload)
        assert res.status_code == 201
        data = res.json()
        assert data["name"] == "GitHub MCP"
        assert data["transport_type"] == "streamable_http"
        assert data["status"] == "ACTIVE"
        assert data["endpoint_url"] == "https://mcp.github.com/v1"


@pytest.mark.asyncio
async def test_register_server_ssrf_rejection(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
):
    """Verifies that loopback and cloud metadata destinations are rejected with 403."""
    payload = {
        "name": "Malicious Server",
        "transport_type": "streamable_http",
        "endpoint_url": "http://127.0.0.1:8000/internal",
    }
    res = await client.post("/v1/mcp/servers", headers=auth_headers, json=payload)
    assert res.status_code == 403
    assert "blocked" in res.text.lower() or "ssrf" in res.text.lower() or "loopback" in res.text.lower()


@pytest.mark.asyncio
async def test_register_server_stdio_sandbox_rejection(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
):
    """Verifies that non-allowlisted stdio commands are rejected with 403."""
    payload = {
        "name": "Shell Server",
        "transport_type": "stdio",
        "command": "bash",
        "args": ["-c", "whoami"],
    }
    res = await client.post("/v1/mcp/servers", headers=auth_headers, json=payload)
    assert res.status_code == 403
    assert "not in approved stdio allowlist" in res.text.lower()


@pytest.mark.asyncio
async def test_list_and_get_mcp_servers(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
    sample_http_server: MCPServer,
):
    """Tests listing all registered servers and retrieving single server details."""
    # List
    res_list = await client.get("/v1/mcp/servers", headers=auth_headers)
    assert res_list.status_code == 200
    servers = res_list.json()
    assert len(servers) >= 1
    assert any(s["id"] == sample_http_server.id for s in servers)

    # Get Single
    res_get = await client.get(f"/v1/mcp/servers/{sample_http_server.id}", headers=auth_headers)
    assert res_get.status_code == 200
    srv = res_get.json()
    assert srv["name"] == sample_http_server.name


@pytest.mark.asyncio
async def test_sync_mcp_catalog(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
    sample_http_server: MCPServer,
):
    """Tests syncing tool catalog from upstream server."""
    mock_tools = [
        {
            "name": "lookup_weather",
            "description": "Returns temperature for a given city.",
            "inputSchema": {
                "type": "object",
                "properties": {"city": {"type": "string"}},
                "required": ["city"],
            },
        }
    ]

    with patch("app.api.mcp.mcp_client.list_tools", new_callable=AsyncMock) as mock_list:
        mock_list.return_value = mock_tools
        res = await client.post(f"/v1/mcp/servers/{sample_http_server.id}/sync", headers=auth_headers)
        assert res.status_code == 200
        data = res.json()
        assert data["new_tools"] == 1
        assert data["drift_detected"] is False
        assert data["catalog_fingerprint"] is not None


@pytest.mark.asyncio
async def test_list_mcp_tools(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
    sample_http_server: MCPServer,
):
    """Tests listing tools with risk filtering."""
    res = await client.get("/v1/mcp/tools", headers=auth_headers)
    assert res.status_code == 200
    tools = res.json()
    assert len(tools) >= 1
    assert any(t["name"] == "convert_currency" for t in tools)

    # Filter by risk level
    res_filtered = await client.get("/v1/mcp/tools?risk_level=LOW", headers=auth_headers)
    assert res_filtered.status_code == 200
    low_tools = res_filtered.json()
    assert all(t["risk_level"] == "LOW" for t in low_tools)


@pytest.mark.asyncio
async def test_call_mcp_tool_endpoint(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
    sample_http_server: MCPServer,
):
    """Tests executing a tool call through the REST API."""
    with patch("app.mcp.proxy.mcp_client.call_tool", new_callable=AsyncMock) as mock_call:
        mock_call.return_value = {"rate": 0.92, "converted": 92.0}

        res = await client.post(
            f"/v1/mcp/servers/{sample_http_server.id}/tools/convert_currency/call",
            headers=auth_headers,
            json={"parameters": {"amount": 100.0}},
        )
        assert res.status_code == 200
        data = res.json()
        assert data["converted"] == 92.0


@pytest.mark.asyncio
async def test_disable_and_delete_mcp_server(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
    sample_http_server: MCPServer,
):
    """Tests disabling and deleting an MCP server."""
    # Disable
    res_dis = await client.post(f"/v1/mcp/servers/{sample_http_server.id}/disable", headers=auth_headers)
    assert res_dis.status_code == 200
    assert res_dis.json()["status"] == "DISABLED"

    # Delete
    res_del = await client.delete(f"/v1/mcp/servers/{sample_http_server.id}", headers=auth_headers)
    assert res_del.status_code == 204

    # Verify 404 after delete
    res_get = await client.get(f"/v1/mcp/servers/{sample_http_server.id}", headers=auth_headers)
    assert res_get.status_code == 404


@pytest.mark.asyncio
async def test_mcp_activity_audit_log(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
):
    """Tests querying MCP security audit trail."""
    res = await client.get("/v1/mcp/activity?limit=10", headers=auth_headers)
    assert res.status_code == 200
    events = res.json()
    assert isinstance(events, list)

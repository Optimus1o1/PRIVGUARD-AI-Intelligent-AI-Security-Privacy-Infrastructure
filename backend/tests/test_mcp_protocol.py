"""Unit and integration tests for MCP 2026-07-28 Streamable HTTP Protocol Facade.
Validates JSON-RPC 2.0 compliance, header-based routing, method mismatch rejection, and version checks.
"""

import json
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from app.database.models import Application, MCPServer, MCPToolDefinition


@pytest.fixture
async def active_mcp_server(db_session: AsyncSession, test_app_record: Application):
    server = MCPServer(
        id="srv_proto_test_01",
        app_id=test_app_record.id,
        name="Protocol Test Server",
        description="Server for testing 2026-07-28 protocol compliance",
        transport_type="streamable_http",
        endpoint_url="https://api.external-tools.com/mcp",
        status="ACTIVE",
        trust_level="VERIFIED",
    )
    db_session.add(server)

    tool = MCPToolDefinition(
        id="tool_proto_calc",
        server_id=server.id,
        app_id=test_app_record.id,
        name="calculate_sum",
        description="Calculates the sum of two integers.",
        input_schema=json.dumps({
            "type": "object",
            "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
            "required": ["a", "b"],
        }),
        risk_level="LOW",
        requires_approval=False,
        is_approved=True,
        version=1,
        definition_hash="hash_sum_01",
    )
    db_session.add(tool)
    await db_session.commit()
    return server


@pytest.mark.asyncio
async def test_mcp_protocol_version_validation(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
    active_mcp_server: MCPServer,
):
    """Verifies that missing or invalid mcp-version headers are rejected."""
    # 1. Missing mcp-version header
    res_missing = await client.post(
        "/mcp",
        headers={**auth_headers, "mcp-method": "tools/list"},
        json={"jsonrpc": "2.0", "id": "req-1", "method": "tools/list", "params": {}},
    )
    assert res_missing.status_code in (200, 400)
    data_missing = res_missing.json()
    assert "error" in data_missing
    assert data_missing["error"]["code"] == -32600
    assert "mcp-version" in data_missing["error"]["message"]

    # 2. Unsupported version
    res_old = await client.post(
        "/mcp",
        headers={**auth_headers, "mcp-version": "2024-11-05", "mcp-method": "tools/list"},
        json={"jsonrpc": "2.0", "id": "req-2", "method": "tools/list", "params": {}},
    )
    assert res_old.status_code in (200, 400)
    data_old = res_old.json()
    assert "error" in data_old
    assert data_old["error"]["code"] == -32600
    assert "Unsupported MCP version" in data_old["error"]["message"]


@pytest.mark.asyncio
async def test_mcp_protocol_header_method_mismatch(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
    active_mcp_server: MCPServer,
):
    """Verifies that header mcp-method mismatch with JSON-RPC body method is rejected."""
    res = await client.post(
        "/mcp",
        headers={
            **auth_headers,
            "mcp-version": "2026-07-28",
            "mcp-method": "tools/list",  # Header says tools/list
        },
        json={
            "jsonrpc": "2.0",
            "id": "req-3",
            "method": "tools/call",  # Body says tools/call
            "params": {"name": "calculate_sum", "arguments": {"a": 2, "b": 3}},
        },
    )
    assert res.status_code in (200, 400)
    data = res.json()
    assert "error" in data
    assert data["error"]["code"] == -32600
    assert "mismatch" in data["error"]["message"].lower()


@pytest.mark.asyncio
async def test_mcp_protocol_header_name_mismatch(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
    active_mcp_server: MCPServer,
):
    """Verifies that mcp-name header mismatch with tool call name is rejected."""
    res = await client.post(
        "/mcp",
        headers={
            **auth_headers,
            "mcp-version": "2026-07-28",
            "mcp-method": "tools/call",
            "mcp-name": "other_tool",  # Header says other_tool
        },
        json={
            "jsonrpc": "2.0",
            "id": "req-4",
            "method": "tools/call",
            "params": {"name": "calculate_sum", "arguments": {"a": 2, "b": 3}},
        },
    )
    assert res.status_code in (200, 400)
    data = res.json()
    assert "error" in data
    assert data["error"]["code"] == -32600
    assert "tool name" in data["error"]["message"].lower()


@pytest.mark.asyncio
async def test_mcp_protocol_malformed_jsonrpc(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
):
    """Verifies that non-JSON-RPC 2.0 payloads or missing ID are rejected."""
    # 1. Invalid version in body
    res_bad_ver = await client.post(
        "/mcp",
        headers={
            **auth_headers,
            "mcp-version": "2026-07-28",
            "mcp-method": "tools/list",
        },
        json={"jsonrpc": "1.0", "id": "req-5", "method": "tools/list", "params": {}},
    )
    assert res_bad_ver.status_code in (200, 400)
    assert res_bad_ver.json()["error"]["code"] == -32600

    # 2. Missing method
    res_no_method = await client.post(
        "/mcp",
        headers={
            **auth_headers,
            "mcp-version": "2026-07-28",
            "mcp-method": "tools/list",
        },
        json={"jsonrpc": "2.0", "id": "req-6", "params": {}},
    )
    assert res_no_method.status_code in (200, 400)
    assert res_no_method.json()["error"]["code"] == -32600


@pytest.mark.asyncio
async def test_mcp_protocol_unknown_method(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
):
    """Verifies that unknown JSON-RPC methods return -32601 Method Not Found."""
    res = await client.post(
        "/mcp",
        headers={
            **auth_headers,
            "mcp-version": "2026-07-28",
            "mcp-method": "system/reboot",
        },
        json={"jsonrpc": "2.0", "id": "req-7", "method": "system/reboot", "params": {}},
    )
    assert res.status_code in (200, 404)
    data = res.json()
    assert "error" in data
    assert data["error"]["code"] == -32601
    assert "not implemented" in data["error"]["message"].lower() or "not found" in data["error"]["message"].lower()


@pytest.mark.asyncio
async def test_mcp_protocol_tools_list_success(
    client: AsyncClient,
    test_app_record: Application,
    auth_headers: dict,
    active_mcp_server: MCPServer,
):
    """Verifies that compliant tools/list returns active approved tools."""
    res = await client.post(
        "/mcp",
        headers={
            **auth_headers,
            "mcp-version": "2026-07-28",
            "mcp-method": "tools/list",
        },
        json={"jsonrpc": "2.0", "id": "req-8", "method": "tools/list", "params": {}},
    )
    assert res.status_code == 200
    data = res.json()
    assert "result" in data
    assert "tools" in data["result"]
    tools = data["result"]["tools"]
    assert len(tools) >= 1
    tool_names = [t["name"] for t in tools]
    assert "calculate_sum" in tool_names

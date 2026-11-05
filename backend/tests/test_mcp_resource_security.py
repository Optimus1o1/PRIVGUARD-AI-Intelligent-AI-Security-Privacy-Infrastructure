"""Unit and integration tests for MCP Resource Discovery and Content Security."""

from unittest.mock import AsyncMock
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import PrivGuardException, ResponseSecurityViolationError
from app.database.models import Application, MCPServer
from app.mcp.client import ProtectedMCPClient
from app.mcp.proxy import MCPSecurityProxy


@pytest.fixture
def mock_mcp_client():
    mock = AsyncMock(spec=ProtectedMCPClient)
    mock.read_resource.return_value = {
        "contents": [
            {
                "uri": "postgres://schema/public",
                "mimeType": "application/json",
                "text": '{"tables": ["users", "orders", "products"]}',
            }
        ]
    }
    return mock


@pytest.fixture
async def active_resource_server(db_session: AsyncSession, test_app_record: Application):
    server = MCPServer(
        id="srv_res_sec_01",
        app_id=test_app_record.id,
        name="Resource Server",
        transport_type="streamable_http",
        endpoint_url="https://api.upstream-resources.com/mcp",
        status="ACTIVE",
        trust_level="VERIFIED",
    )
    db_session.add(server)
    await db_session.commit()
    return server


@pytest.mark.asyncio
async def test_read_mcp_resource_success(
    db_session: AsyncSession,
    test_app_record: Application,
    active_resource_server: MCPServer,
    mock_mcp_client: AsyncMock,
):
    proxy = MCPSecurityProxy(client=mock_mcp_client)
    res = await proxy.read_mcp_resource(
        db=db_session,
        app=test_app_record,
        server_id=active_resource_server.id,
        uri="postgres://schema/public",
    )
    assert "contents" in res
    assert res["contents"][0]["uri"] == "postgres://schema/public"
    assert mock_mcp_client.read_resource.called


@pytest.mark.asyncio
async def test_read_mcp_resource_blocks_secret_leakage(
    db_session: AsyncSession,
    test_app_record: Application,
    active_resource_server: MCPServer,
    mock_mcp_client: AsyncMock,
):
    # Resource text containing raw API key
    mock_mcp_client.read_resource.return_value = {
        "contents": [
            {
                "uri": "config://env",
                "mimeType": "text/plain",
                "text": "AWS_SECRET_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nghp_112233445566778899001122334455667788",
            }
        ]
    }
    proxy = MCPSecurityProxy(client=mock_mcp_client)
    with pytest.raises(ResponseSecurityViolationError):
        await proxy.read_mcp_resource(
            db=db_session,
            app=test_app_record,
            server_id=active_resource_server.id,
            uri="config://env",
        )


@pytest.mark.asyncio
async def test_read_mcp_resource_cross_tenant_isolation(
    db_session: AsyncSession,
    test_app_record: Application,
    active_resource_server: MCPServer,
    mock_mcp_client: AsyncMock,
):
    # Other application tenant
    other_app = Application(
        id="app_other_tenant_99",
        name="Other Organization App",
        api_key_hash="hash_other",
    )
    db_session.add(other_app)
    await db_session.commit()

    proxy = MCPSecurityProxy(client=mock_mcp_client)
    # Attempting to read App 1's server using App 2 credentials
    with pytest.raises(PrivGuardException) as exc:
        await proxy.read_mcp_resource(
            db=db_session,
            app=other_app,
            server_id=active_resource_server.id,
            uri="postgres://schema/public",
        )
    assert exc.value.status_code == 404

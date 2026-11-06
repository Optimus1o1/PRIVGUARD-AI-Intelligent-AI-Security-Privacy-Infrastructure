"""PRIVGUARD AI - Model Context Protocol (MCP) Security Gateway Endpoints.
Provides upstream server management, catalog sync, tool mediation, and the 2026-07-28 Protected MCP Server Facade.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, Query, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import select, delete
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.authentication import get_current_app
from app.core.exceptions import (
    MCPCatalogDriftError,
    MCPProtocolError,
    MCPSSRFError,
    MCPStdioSandboxError,
    MCPToolPoisoningError,
    PrivGuardException,
    ResponseSecurityViolationError,
    SecretDetectedError,
)
from app.database.connection import get_db_session
from app.database.models import (
    Application,
    MCPAuditEvent,
    MCPResourceDefinition,
    MCPServer,
    MCPToolDefinition,
    utcnow,
)
from app.mcp.client import mcp_client
from app.mcp.proxy import mcp_security_proxy
from app.mcp.registry import mcp_tool_registry
from app.mcp.ssrf import destination_validator
from app.mcp.stdio_sandbox import mcp_stdio_sandbox

router = APIRouter(tags=["MCP Security Gateway"])


# --- Pydantic Schemas ---


class ServerRegisterRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    transport_type: str = Field(default="streamable_http", pattern="^(streamable_http|stdio)$")
    endpoint_url: Optional[str] = Field(None, max_length=512)
    command: Optional[str] = Field(None, max_length=255)
    args: Optional[List[str]] = Field(default_factory=list)
    auth_type: str = Field(default="NONE", pattern="^(NONE|API_KEY|BEARER_TOKEN|OAUTH2)$")
    auth_credential_ref: Optional[str] = Field(None, max_length=255)


class ServerResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    transport_type: str
    endpoint_url: Optional[str]
    command: Optional[str]
    args: List[str]
    status: str
    trust_level: str
    catalog_fingerprint: Optional[str]
    auth_type: str
    last_connected_at: Optional[datetime]
    created_at: datetime
    updated_at: datetime


class ToolResponse(BaseModel):
    id: str
    server_id: str
    name: str
    description: Optional[str]
    input_schema: Dict[str, Any]
    risk_level: str
    requires_approval: bool
    is_approved: bool
    version: int
    definition_hash: str
    created_at: datetime


class ToolCallRequest(BaseModel):
    parameters: Dict[str, Any] = Field(default_factory=dict)
    agent_id: Optional[str] = None
    task_id: Optional[str] = None
    capability_token: Optional[str] = None
    approval_id: Optional[str] = None


class CatalogSyncResponse(BaseModel):
    server_id: str
    server_status: str
    new_tools: int
    updated_tools: int
    drift_detected: bool
    catalog_fingerprint: Optional[str]


class MCPAuditResponse(BaseModel):
    id: str
    server_id: Optional[str]
    agent_id: Optional[str]
    tool_name: Optional[str]
    action: str
    status: str
    details: Dict[str, Any]
    timestamp: datetime


# --- Management REST Endpoints ---


@router.post("/v1/mcp/servers", response_model=ServerResponse, status_code=status.HTTP_201_CREATED)
async def register_mcp_server(
    payload: ServerRegisterRequest,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> ServerResponse:
    """Registers an approved upstream MCP server after strict destination validation."""
    if payload.transport_type == "streamable_http":
        if not payload.endpoint_url:
            raise PrivGuardException("endpoint_url is required for streamable_http transport", status_code=400)
        # SSRF validation on target destination
        destination_validator.validate_url(payload.endpoint_url)

    elif payload.transport_type == "stdio":
        if not payload.command:
            raise PrivGuardException("command is required for stdio transport", status_code=400)
        # Command allowlist & arguments validation
        mcp_stdio_sandbox.validate_command(payload.command, payload.args or [])

    server = MCPServer(
        app_id=current_app.id,
        name=payload.name,
        description=payload.description,
        transport_type=payload.transport_type,
        endpoint_url=payload.endpoint_url,
        command=payload.command,
        args=json.dumps(payload.args or []),
        status="ACTIVE",
        trust_level="PROBATION",
        auth_type=payload.auth_type,
        auth_credential_ref=payload.auth_credential_ref,
        created_at=utcnow(),
        updated_at=utcnow(),
    )
    db.add(server)
    await db.commit()
    await db.refresh(server)

    audit_evt = MCPAuditEvent(
        app_id=current_app.id,
        server_id=server.id,
        action="REGISTER_SERVER",
        status="SUCCESS",
        details=json.dumps({"name": server.name, "transport": server.transport_type}),
        timestamp=utcnow(),
    )
    db.add(audit_evt)
    await db.commit()

    return ServerResponse(
        id=server.id,
        name=server.name,
        description=server.description,
        transport_type=server.transport_type,
        endpoint_url=server.endpoint_url,
        command=server.command,
        args=json.loads(server.args or "[]"),
        status=server.status,
        trust_level=server.trust_level,
        catalog_fingerprint=server.catalog_fingerprint,
        auth_type=server.auth_type,
        last_connected_at=server.last_connected_at,
        created_at=server.created_at,
        updated_at=server.updated_at,
    )


@router.get("/v1/mcp/servers", response_model=List[ServerResponse])
async def list_mcp_servers(
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> List[ServerResponse]:
    """Lists registered upstream MCP servers for authenticated tenant."""
    stmt = select(MCPServer).where(MCPServer.app_id == current_app.id).order_by(MCPServer.created_at.desc())
    res = await db.execute(stmt)
    servers = res.scalars().all()

    return [
        ServerResponse(
            id=s.id,
            name=s.name,
            description=s.description,
            transport_type=s.transport_type,
            endpoint_url=s.endpoint_url,
            command=s.command,
            args=json.loads(s.args or "[]"),
            status=s.status,
            trust_level=s.trust_level,
            catalog_fingerprint=s.catalog_fingerprint,
            auth_type=s.auth_type,
            last_connected_at=s.last_connected_at,
            created_at=s.created_at,
            updated_at=s.updated_at,
        )
        for s in servers
    ]


@router.get("/v1/mcp/servers/{server_id}", response_model=ServerResponse)
async def get_mcp_server(
    server_id: str,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> ServerResponse:
    """Gets details for an individual registered MCP server."""
    stmt = select(MCPServer).where(MCPServer.id == server_id, MCPServer.app_id == current_app.id)
    res = await db.execute(stmt)
    server = res.scalar_one_or_none()
    if not server:
        raise PrivGuardException(f"MCP server '{server_id}' not found.", status_code=404)

    return ServerResponse(
        id=server.id,
        name=server.name,
        description=server.description,
        transport_type=server.transport_type,
        endpoint_url=server.endpoint_url,
        command=server.command,
        args=json.loads(server.args or "[]"),
        status=server.status,
        trust_level=server.trust_level,
        catalog_fingerprint=server.catalog_fingerprint,
        auth_type=server.auth_type,
        last_connected_at=server.last_connected_at,
        created_at=server.created_at,
        updated_at=server.updated_at,
    )


@router.post("/v1/mcp/servers/{server_id}/sync", response_model=CatalogSyncResponse)
async def sync_server_catalog(
    server_id: str,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> CatalogSyncResponse:
    """Discovers tools from upstream MCP server, runs poisoning inspection, and checks for catalog drift."""
    stmt = select(MCPServer).where(MCPServer.id == server_id, MCPServer.app_id == current_app.id)
    res = await db.execute(stmt)
    server = res.scalar_one_or_none()
    if not server:
        raise PrivGuardException(f"MCP server '{server_id}' not found.", status_code=404)

    # Fetch tools via client
    discovered = await mcp_client.list_tools(
        endpoint_url=server.endpoint_url,
        transport_type=server.transport_type,
        command=server.command,
        args=json.loads(server.args or "[]"),
    )

    new_cnt, upd_cnt, drift = await mcp_tool_registry.sync_server_catalog(
        db=db,
        app_id=current_app.id,
        server=server,
        discovered_tools=discovered,
    )

    return CatalogSyncResponse(
        server_id=server.id,
        server_status=server.status,
        new_tools=new_cnt,
        updated_tools=upd_cnt,
        drift_detected=drift,
        catalog_fingerprint=server.catalog_fingerprint,
    )


@router.post("/v1/mcp/servers/{server_id}/approve", response_model=ServerResponse)
async def approve_catalog_drift(
    server_id: str,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> ServerResponse:
    """Human user approves drifted MCP tool catalog, lifting quarantine status."""
    server = await mcp_tool_registry.approve_catalog_drift(
        db=db,
        app_id=current_app.id,
        server_id=server_id,
    )
    return ServerResponse(
        id=server.id,
        name=server.name,
        description=server.description,
        transport_type=server.transport_type,
        endpoint_url=server.endpoint_url,
        command=server.command,
        args=json.loads(server.args or "[]"),
        status=server.status,
        trust_level=server.trust_level,
        catalog_fingerprint=server.catalog_fingerprint,
        auth_type=server.auth_type,
        last_connected_at=server.last_connected_at,
        created_at=server.created_at,
        updated_at=server.updated_at,
    )


@router.post("/v1/mcp/servers/{server_id}/disable", response_model=ServerResponse)
async def disable_mcp_server(
    server_id: str,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> ServerResponse:
    """Disables an MCP server, immediately blocking all its tool executions."""
    stmt = select(MCPServer).where(MCPServer.id == server_id, MCPServer.app_id == current_app.id)
    res = await db.execute(stmt)
    server = res.scalar_one_or_none()
    if not server:
        raise PrivGuardException(f"MCP server '{server_id}' not found.", status_code=404)

    server.status = "DISABLED"
    server.updated_at = utcnow()
    await db.commit()

    return ServerResponse(
        id=server.id,
        name=server.name,
        description=server.description,
        transport_type=server.transport_type,
        endpoint_url=server.endpoint_url,
        command=server.command,
        args=json.loads(server.args or "[]"),
        status=server.status,
        trust_level=server.trust_level,
        catalog_fingerprint=server.catalog_fingerprint,
        auth_type=server.auth_type,
        last_connected_at=server.last_connected_at,
        created_at=server.created_at,
        updated_at=server.updated_at,
    )


@router.delete("/v1/mcp/servers/{server_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_mcp_server(
    server_id: str,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> None:
    """Removes an MCP server registration and its tool catalog."""
    stmt = select(MCPServer).where(MCPServer.id == server_id, MCPServer.app_id == current_app.id)
    res = await db.execute(stmt)
    server = res.scalar_one_or_none()
    if not server:
        raise PrivGuardException(f"MCP server '{server_id}' not found.", status_code=404)

    # Delete tools
    await db.execute(delete(MCPToolDefinition).where(MCPToolDefinition.server_id == server_id))
    # Delete resources
    await db.execute(delete(MCPResourceDefinition).where(MCPResourceDefinition.server_id == server_id))
    # Delete server
    await db.delete(server)
    await db.commit()


@router.get("/v1/mcp/tools", response_model=List[ToolResponse])
async def list_mcp_tools(
    server_id: Optional[str] = Query(None),
    risk_level: Optional[str] = Query(None),
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> List[ToolResponse]:
    """Lists registered tools across connected MCP servers."""
    stmt = select(MCPToolDefinition).where(MCPToolDefinition.app_id == current_app.id)
    if server_id:
        stmt = stmt.where(MCPToolDefinition.server_id == server_id)
    if risk_level:
        stmt = stmt.where(MCPToolDefinition.risk_level == risk_level)

    res = await db.execute(stmt)
    tools = res.scalars().all()

    return [
        ToolResponse(
            id=t.id,
            server_id=t.server_id,
            name=t.name,
            description=t.description,
            input_schema=json.loads(t.input_schema or "{}"),
            risk_level=t.risk_level,
            requires_approval=t.requires_approval,
            is_approved=t.is_approved,
            version=t.version,
            definition_hash=t.definition_hash,
            created_at=t.created_at,
        )
        for t in tools
    ]


@router.post("/v1/mcp/servers/{server_id}/tools/{tool_name}/call")
async def call_mcp_tool(
    server_id: str,
    tool_name: str,
    payload: ToolCallRequest,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> Dict[str, Any]:
    """Executes a tool on an approved MCP server through PRIVGUARD's full security proxy."""
    return await mcp_security_proxy.execute_mcp_tool(
        db=db,
        app=current_app,
        server_id=server_id,
        tool_name=tool_name,
        parameters=payload.parameters,
        agent_id=payload.agent_id,
        task_id=payload.task_id,
        capability_token=payload.capability_token,
        approval_id=payload.approval_id,
    )


@router.get("/v1/mcp/activity", response_model=List[MCPAuditResponse])
async def list_mcp_activity(
    limit: int = Query(50, ge=1, le=100),
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> List[MCPAuditResponse]:
    """Lists content-free MCP gateway audit events."""
    stmt = (
        select(MCPAuditEvent)
        .where(MCPAuditEvent.app_id == current_app.id)
        .order_by(MCPAuditEvent.timestamp.desc())
        .limit(limit)
    )
    res = await db.execute(stmt)
    events = res.scalars().all()

    return [
        MCPAuditResponse(
            id=e.id,
            server_id=e.server_id,
            agent_id=e.agent_id,
            tool_name=e.tool_name,
            action=e.action,
            status=e.status,
            details=json.loads(e.details or "{}"),
            timestamp=e.timestamp,
        )
        for e in events
    ]


# --- 2026-07-28 Protected MCP Server Facade (POST /mcp) ---


@router.post("/mcp")
async def mcp_server_facade(
    request: Request,
    current_app: Application = Depends(get_current_app),
    mcp_version: Optional[str] = Header(None, alias="mcp-version"),
    mcp_method: Optional[str] = Header(None, alias="mcp-method"),
    mcp_name: Optional[str] = Header(None, alias="mcp-name"),
    db: AsyncSession = Depends(get_db_session),
) -> JSONResponse:
    """
    Standard MCP Streamable HTTP / JSON-RPC 2.0 endpoint conforming to 2026-07-28 specification.
    Enforces header-based routing consistency, caller authentication, and tool exposure scoping.
    """
    # 1. Parse JSON-RPC Body
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={
                "jsonrpc": "2.0",
                "id": None,
                "error": {"code": -32700, "message": "Parse error: Invalid JSON payload."},
            },
        )

    if not isinstance(body, dict) or body.get("jsonrpc") != "2.0":
        return JSONResponse(
            status_code=400,
            content={
                "jsonrpc": "2.0",
                "id": body.get("id") if isinstance(body, dict) else None,
                "error": {"code": -32600, "message": "Invalid Request: jsonrpc must be '2.0'."},
            },
        )

    req_id = body.get("id")
    method = body.get("method")
    params = body.get("params") or {}

    # 2. 2026-07-28 Version & Header Consistency Checks
    if not mcp_version or mcp_version != "2026-07-28":
        return JSONResponse(
            status_code=400,
            content={
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32600,
                    "message": f"Unsupported MCP version or missing header 'mcp-version: 2026-07-28' (received '{mcp_version}').",
                },
            },
        )

    if mcp_method and mcp_method != method:
        return JSONResponse(
            status_code=400,
            content={
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {
                    "code": -32600,
                    "message": f"Header routing mismatch: 'mcp-method' ({mcp_method}) does not match JSON-RPC method ({method}).",
                },
            },
        )

    # 3. Handle Supported Methods
    if method == "tools/list":
        # Return authorized tools for authenticated caller
        stmt = (
            select(MCPToolDefinition, MCPServer)
            .join(MCPServer, MCPToolDefinition.server_id == MCPServer.id)
            .where(
                MCPToolDefinition.app_id == current_app.id,
                MCPToolDefinition.is_approved.is_(True),
                MCPToolDefinition.risk_level != "CRITICAL",
                MCPServer.status == "ACTIVE",
            )
        )
        res = await db.execute(stmt)
        tools = []
        for t, s in res.all():
            tools.append(
                {
                    "name": t.name,
                    "description": f"[{s.name}] {t.description or ''}".strip(),
                    "inputSchema": json.loads(t.input_schema or "{}"),
                }
            )
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"tools": tools},
            }
        )

    elif method == "tools/call":
        tool_name = params.get("name")
        args = params.get("arguments") or {}

        if not tool_name:
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32602, "message": "Invalid params: 'name' is required."},
                },
            )

        if mcp_name and mcp_name != tool_name:
            return JSONResponse(
                status_code=400,
                content={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32600,
                        "message": f"Header mismatch: 'mcp-name' ({mcp_name}) does not match tool name ({tool_name}).",
                    },
                },
            )

        # Locate tool and parent server
        stmt = select(MCPToolDefinition).where(
            MCPToolDefinition.name == tool_name,
            MCPToolDefinition.app_id == current_app.id,
        )
        res = await db.execute(stmt)
        tool_def = res.scalar_one_or_none()
        if not tool_def:
            return JSONResponse(
                status_code=404,
                content={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32601, "message": f"Method not found: Tool '{tool_name}' not available."},
                },
            )

        # Execute through Security Proxy
        try:
            result = await mcp_security_proxy.execute_mcp_tool(
                db=db,
                app=current_app,
                server_id=tool_def.server_id,
                tool_name=tool_name,
                parameters=args,
            )
            return JSONResponse(
                content={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": result,
                }
            )
        except PrivGuardException as exc:
            return JSONResponse(
                status_code=exc.status_code,
                content={
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {"code": -32000, "message": exc.message, "data": exc.details},
                },
            )

    elif method == "resources/list":
        stmt = select(MCPResourceDefinition).where(MCPResourceDefinition.app_id == current_app.id)
        res = await db.execute(stmt)
        resources = [
            {"uri": r.uri, "name": r.name, "description": r.description, "mimeType": r.mime_type}
            for r in res.scalars().all()
        ]
        return JSONResponse(
            content={
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {"resources": resources},
            }
        )

    return JSONResponse(
        status_code=404,
        content={
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": -32601, "message": f"Method '{method}' not implemented."},
        },
    )

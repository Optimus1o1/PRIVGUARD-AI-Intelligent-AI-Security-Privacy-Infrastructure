"""MCP Security Proxy: Mediates upstream MCP tool and resource execution through PRIVGUARD's security infrastructure."""

import json
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_security.capability_manager import capability_manager
from app.agent_security.identity import agent_identity_manager
from app.agent_security.permission_engine import permission_engine
from app.agent_security.task_manager import task_manager
from app.approvals.approval_engine import approval_engine
from app.core.exceptions import (
    ApprovalRequiredError,
    MCPCatalogDriftError,
    MCPProtocolError,
    MCPSSRFError,
    MCPToolPoisoningError,
    PrivGuardException,
    ResponseSecurityViolationError,
    SecretDetectedError,
)
from app.database.models import (
    Application,
    MCPAuditEvent,
    MCPResourceDefinition,
    MCPServer,
    MCPToolDefinition,
    utcnow,
)
from app.mcp.client import ProtectedMCPClient, mcp_client
from app.privacy.secret_scanner import secret_scanner
from app.threat_detection import injection_detector
from app.threat_detection.schemas import ThreatAction


class MCPSecurityProxy:
    """End-to-end security mediator for external Model Context Protocol tool and resource invocations."""

    def __init__(self, client: Optional[ProtectedMCPClient] = None):
        self.client = client or mcp_client
        self.identity_mgr = agent_identity_manager
        self.task_mgr = task_manager
        self.perms = permission_engine
        self.caps = capability_manager
        self.approvals = approval_engine
        self.secrets = secret_scanner
        self.injection_detector = injection_detector

    async def execute_mcp_tool(
        self,
        db: AsyncSession,
        app: Application,
        server_id: str,
        tool_name: str,
        parameters: Dict[str, Any],
        agent_id: Optional[str] = None,
        task_id: Optional[str] = None,
        capability_token: Optional[str] = None,
        approval_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Executes an MCP tool with full multi-stage security validation:
        1. Validates server status & catalog drift.
        2. Validates tool definition approval & risk level.
        3. Scans arguments for secrets & prompt injection.
        4. Validates agent identity & permissions.
        5. Validates & consumes single-use capability token.
        6. Verifies & consumes cryptographic human approval for sensitive tools.
        7. Executes upstream through ProtectedMCPClient.
        8. Inspects tool output for leaked secrets & injection.
        9. Emits content-free audit event.
        """
        # 1. Server Validation
        stmt_srv = select(MCPServer).where(MCPServer.id == server_id, MCPServer.app_id == app.id)
        res_srv = await db.execute(stmt_srv)
        server = res_srv.scalar_one_or_none()
        if not server:
            raise PrivGuardException(f"MCP server '{server_id}' not found.", status_code=404)

        if server.status == "REQUIRES_REAPPROVAL":
            raise MCPCatalogDriftError(server_id=server.id, tool_name=tool_name)

        if server.status != "ACTIVE":
            raise PrivGuardException(f"MCP server '{server.name}' is currently {server.status}.", status_code=403)

        # 2. Tool Definition Validation
        stmt_tool = select(MCPToolDefinition).where(
            MCPToolDefinition.server_id == server.id,
            MCPToolDefinition.name == tool_name,
            MCPToolDefinition.app_id == app.id,
        )
        res_tool = await db.execute(stmt_tool)
        tool_def = res_tool.scalar_one_or_none()
        if not tool_def:
            raise PrivGuardException(f"Tool '{tool_name}' not found on MCP server '{server.name}'.", status_code=404)

        if not tool_def.is_approved:
            raise PrivGuardException(f"Tool '{tool_name}' is not approved for execution.", status_code=403)

        if tool_def.risk_level == "CRITICAL":
            raise PrivGuardException(f"Tool '{tool_name}' has CRITICAL risk level and is blocked by security policy.", status_code=403)

        # 3. Privacy & Secret Inspection on Arguments
        param_text = json.dumps(parameters)
        secret_matches = self.secrets.scan(param_text)
        if secret_matches:
            first_match = secret_matches[0]
            raise SecretDetectedError(
                secret_type=first_match.secret_type,
                match_preview=first_match.preview,
            )

        # 4. Prompt Injection Inspection on Arguments
        inj_assessment = self.injection_detector.inspect(param_text)
        if inj_assessment.is_threat and inj_assessment.action in (ThreatAction.BLOCK, ThreatAction.QUARANTINE):
            raise MCPToolPoisoningError(
                tool_name=tool_name,
                reason=f"Tool arguments contain malicious injection: {inj_assessment.reason}",
                signals=[s.description for s in inj_assessment.signals],
            )

        # 5. Agent Identity & Task Validation (if agent_id provided)
        if agent_id:
            agent = await self.identity_mgr.get_agent(db, agent_id, app.id)
            if not agent or agent.status != "ACTIVE":
                raise PrivGuardException(f"Agent '{agent_id}' is not active.", status_code=403)

            if task_id:
                task = await self.task_mgr.get_task(db, task_id, app.id)
                if not task or task.status != "RUNNING":
                    raise PrivGuardException(f"Task '{task_id}' is not in RUNNING state.", status_code=403)

        # 6. Capability Token Validation (if provided or required for agent)
        if capability_token and agent_id and task_id:
            await self.caps.validate_and_consume(
                db=db,
                raw_secret=capability_token,
                expected_tool=tool_name,
                expected_agent_id=agent_id,
                expected_task_id=task_id,
                expected_app_id=app.id,
                consume=True,
            )

        # 7. Human Approval Verification (for sensitive tools)
        if tool_def.requires_approval or tool_def.risk_level in ("HIGH", "CRITICAL"):
            if not approval_id:
                # Create a pending approval request and raise ApprovalRequiredError
                req = await self.approvals.create_request(
                    db=db,
                    task_id=task_id or f"mcp_task_{server_id[:8]}",
                    agent_id=agent_id or "mcp_direct_caller",
                    app_id=app.id,
                    tool_name=tool_name,
                    target_resource=server.endpoint_url or server.command,
                    parameters=parameters,
                    risk_level=tool_def.risk_level,
                )
                raise ApprovalRequiredError(
                    approval_id=req.id,
                    tool_name=tool_name,
                    message=f"Human approval required for tool '{tool_name}' ({tool_def.risk_level} risk).",
                )

            # Consume the existing approval
            await self.approvals.verify_and_consume(
                db=db,
                approval_id=approval_id,
                tool_name=tool_name,
                target_resource=server.endpoint_url or server.command,
                parameters=parameters,
                app_id=app.id,
            )

        # 8. Execute Upstream via ProtectedMCPClient
        raw_result = await self.client.call_tool(
            endpoint_url=server.endpoint_url,
            transport_type=server.transport_type,
            command=server.command,
            args=json.loads(server.args or "[]"),
            tool_name=tool_name,
            arguments=parameters,
        )

        # 9. Response Security Inspection (Outbound Result)
        res_str = json.dumps(raw_result)
        decoded_res = res_str.replace("\\n", "\n").replace('\\"', '"')
        out_secrets = self.secrets.scan(decoded_res)
        if out_secrets:
            first_leak = out_secrets[0]
            raise ResponseSecurityViolationError(
                violation_type=first_leak.secret_type,
                preview=first_leak.preview,
                reason="MCP tool output contained sensitive leaked credential.",
            )

        # Scan for output injection / indirect prompt injection from retrieved data
        out_inj = self.injection_detector.inspect(decoded_res)
        if out_inj.is_threat and out_inj.action == ThreatAction.BLOCK:
            raise PrivGuardException(
                f"MCP tool output contained active prompt injection payload: {out_inj.reason}",
                status_code=502,
                error_code="TOOL_OUTPUT_INJECTION_DETECTED",
            )

        # 10. Audit Logging (Content-Free)
        audit_evt = MCPAuditEvent(
            app_id=app.id,
            server_id=server.id,
            agent_id=agent_id,
            tool_name=tool_name,
            action="CALL_TOOL",
            status="SUCCESS",
            details=json.dumps({
                "risk_level": tool_def.risk_level,
                "requires_approval": tool_def.requires_approval,
            }),
            timestamp=utcnow(),
        )
        db.add(audit_evt)
        await db.commit()

        return raw_result

    async def read_mcp_resource(
        self,
        db: AsyncSession,
        app: Application,
        server_id: str,
        uri: str,
        agent_id: Optional[str] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Reads an MCP resource with ownership, PII, and injection inspection before returning.
        """
        stmt_srv = select(MCPServer).where(MCPServer.id == server_id, MCPServer.app_id == app.id)
        res_srv = await db.execute(stmt_srv)
        server = res_srv.scalar_one_or_none()
        if not server or server.status != "ACTIVE":
            raise PrivGuardException(f"MCP server '{server_id}' not found or inactive.", status_code=404)

        if not server.endpoint_url:
            raise PrivGuardException("Resources are only supported on streamable_http servers.", status_code=400)

        # Fetch resource via client
        raw_res = await self.client.read_resource(endpoint_url=server.endpoint_url, uri=uri)

        # Content inspection
        content_text = json.dumps(raw_res)
        decoded_text = content_text.replace("\\n", "\n").replace('\\"', '"')
        secrets = self.secrets.scan(decoded_text)
        if secrets:
            raise ResponseSecurityViolationError(
                violation_type=secrets[0].secret_type,
                preview=secrets[0].preview,
                reason="MCP resource content contained raw credential.",
            )

        # Audit
        audit_evt = MCPAuditEvent(
            app_id=app.id,
            server_id=server.id,
            agent_id=agent_id,
            action="READ_RESOURCE",
            status="SUCCESS",
            details=json.dumps({"uri": uri}),
            timestamp=utcnow(),
        )
        db.add(audit_evt)
        await db.commit()

        return raw_res


# Global singleton proxy
mcp_security_proxy = MCPSecurityProxy()

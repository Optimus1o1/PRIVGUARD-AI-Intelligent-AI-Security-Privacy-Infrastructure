"""MCP Tool Catalog Registry, Inspection, and Drift Defense.
Inspects external tool schemas, detects prompt injection & imperative smuggling in tool descriptions,
and enforces catalog fingerprinting and human re-approval on tool definition changes.
"""

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import (
    MCPCatalogDriftError,
    MCPToolPoisoningError,
    PrivGuardException,
)
from app.database.models import MCPServer, MCPToolDefinition, MCPAuditEvent, utcnow
from app.privacy.secret_scanner import secret_scanner
from app.threat_detection import injection_detector
from app.threat_detection.schemas import ThreatAction

SENSITIVE_TOOL_PATTERNS = {
    "CRITICAL": [
        r"(?i)\b(execute|run|exec|shell|bash|eval|system|cmd|powershell)\b",
        r"(?i)\b(transfer|pay|wire|fund|wallet|crypto|billing)\b",
        r"(?i)\b(drop|truncate|format_disk|destroy)\b",
    ],
    "HIGH": [
        r"(?i)\b(send|email|mail|notify|broadcast|tweet|slack_post)\b",
        r"(?i)\b(delete|remove|unlink|purge|wipe)\b",
        r"(?i)\b(write|update|modify|patch|commit|push|insert|alter)\b",
    ],
    "LOW": [
        r"(?i)\b(get_time|clock|calculator|echo|ping|math|version|status)\b",
    ],
}

FORBIDDEN_IMPERATIVES = [
    "always send",
    "forward all",
    "never ask confirmation",
    "skip security",
    "override permissions",
    "ignore instructions",
    "grant root",
    "bypass policy",
    "disable guardrails",
    "exfiltrate",
    "secretly send",
]


class MCPToolRegistry:
    """Manages MCP tool discovery, schema validation, description poisoning inspection, and catalog drift."""

    def __init__(self):
        self.injection_detector = injection_detector
        self.secret_scanner = secret_scanner

    def classify_tool_risk(self, name: str, description: Optional[str] = None) -> Tuple[str, bool]:
        """
        Classifies tool risk level and determines if human approval is required.
        Returns (risk_level, requires_approval).
        """
        combined = f"{name} {description or ''}".lower()

        # Check CRITICAL
        for pattern in SENSITIVE_TOOL_PATTERNS["CRITICAL"]:
            if re.search(pattern, combined):
                return "CRITICAL", True

        # Check HIGH
        for pattern in SENSITIVE_TOOL_PATTERNS["HIGH"]:
            if re.search(pattern, combined):
                return "HIGH", True

        # Check LOW
        for pattern in SENSITIVE_TOOL_PATTERNS["LOW"]:
            if re.search(pattern, combined):
                return "LOW", False

        return "MEDIUM", False

    def inspect_tool_definition(self, name: str, description: str, input_schema: Dict[str, Any]) -> str:
        """
        Inspects external tool definition for prompt injection, hidden directives, and schema integrity.
        Returns canonical SHA-256 definition hash.
        Raises MCPToolPoisoningError if security checks fail.
        """
        if not name or not isinstance(name, str) or not re.match(r"^[a-zA-Z0-9_-]{1,100}$", name):
            raise MCPToolPoisoningError(
                tool_name=str(name),
                reason="Invalid tool name. Must be 1-100 alphanumeric characters, hyphens, or underscores.",
            )

        desc = description or ""

        # 1. Check for raw secrets in tool description
        secret_matches = self.secret_scanner.scan(desc)
        if secret_matches:
            first_match = secret_matches[0]
            raise MCPToolPoisoningError(
                tool_name=name,
                reason=f"Tool description contains raw credential '{first_match.secret_type}'.",
                signals=[first_match.secret_type],
            )

        # 2. Check for prompt injection in tool description
        assessment = self.injection_detector.inspect(desc)
        if assessment.is_threat and assessment.action in (ThreatAction.BLOCK, ThreatAction.QUARANTINE):
            raise MCPToolPoisoningError(
                tool_name=name,
                reason=f"Tool description rejected due to prompt injection: {assessment.reason}",
                signals=[s.description for s in assessment.signals],
            )

        # 3. Check for suspicious imperative commands
        desc_lower = desc.lower()
        for imp in FORBIDDEN_IMPERATIVES:
            if imp in desc_lower:
                raise MCPToolPoisoningError(
                    tool_name=name,
                    reason=f"Tool description contains forbidden imperative directive '{imp}'.",
                    signals=[imp],
                )

        # 4. Validate input JSON schema structure
        if not isinstance(input_schema, dict):
            raise MCPToolPoisoningError(
                tool_name=name,
                reason="Invalid input schema: must be a JSON object dictionary.",
            )

        # Compute canonical definition hash
        canonical = json.dumps(
            {"name": name, "description": desc.strip(), "input_schema": input_schema},
            sort_keys=True,
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    async def sync_server_catalog(
        self,
        db: AsyncSession,
        app_id: str,
        server: MCPServer,
        discovered_tools: List[Dict[str, Any]],
    ) -> Tuple[int, int, bool]:
        """
        Syncs and inspects discovered tool catalog from upstream MCP server.
        Detects drift and flags security re-approval when approved tools change.
        Returns (new_tools_count, updated_tools_count, drift_detected).
        """
        # Fetch existing tool definitions for this server
        stmt = select(MCPToolDefinition).where(
            MCPToolDefinition.server_id == server.id,
            MCPToolDefinition.app_id == app_id,
        )
        res = await db.execute(stmt)
        existing_tools = {t.name: t for t in res.scalars().all()}

        new_count = 0
        updated_count = 0
        drift_detected = False

        validated_hashes = []

        for tool_data in discovered_tools:
            name = tool_data.get("name")
            desc = tool_data.get("description", "")
            schema = tool_data.get("inputSchema") or tool_data.get("input_schema") or {}

            # Inspect definition & compute hash (raises on injection/poisoning)
            def_hash = self.inspect_tool_definition(name=name, description=desc, input_schema=schema)
            validated_hashes.append(def_hash)

            risk_level, req_approval = self.classify_tool_risk(name, desc)

            # Block CRITICAL tools (e.g. execute_shell) in MVP
            if risk_level == "CRITICAL":
                # Mark as not approved by default
                is_approved = False
            else:
                is_approved = True

            if name in existing_tools:
                ext = existing_tools[name]
                if ext.definition_hash != def_hash:
                    # DRIFT DETECTED: Definition changed!
                    drift_detected = True
                    updated_count += 1
                    ext.description = desc
                    ext.input_schema = json.dumps(schema)
                    ext.risk_level = risk_level
                    ext.requires_approval = req_approval
                    ext.version += 1
                    ext.definition_hash = def_hash
                    ext.updated_at = utcnow()
                    # Security rule: If previously approved tool drifts, require human re-approval!
                    ext.is_approved = False
            else:
                # New tool
                new_count += 1
                new_tool = MCPToolDefinition(
                    server_id=server.id,
                    app_id=app_id,
                    name=name,
                    description=desc,
                    input_schema=json.dumps(schema),
                    risk_level=risk_level,
                    requires_approval=req_approval,
                    is_approved=is_approved,
                    version=1,
                    definition_hash=def_hash,
                    created_at=utcnow(),
                    updated_at=utcnow(),
                )
                db.add(new_tool)

        # Compute catalog fingerprint across all sorted definition hashes
        sorted_hashes = sorted(validated_hashes)
        catalog_fingerprint = hashlib.sha256("".join(sorted_hashes).encode("utf-8")).hexdigest()

        server.catalog_fingerprint = catalog_fingerprint
        server.last_connected_at = utcnow()

        if drift_detected:
            server.status = "REQUIRES_REAPPROVAL"
            # Emit audit event for catalog drift
            audit_evt = MCPAuditEvent(
                app_id=app_id,
                server_id=server.id,
                action="CATALOG_DRIFT_DETECTED",
                status="QUARANTINED",
                details=json.dumps({
                    "updated_tools_count": updated_count,
                    "catalog_fingerprint": catalog_fingerprint,
                }),
                timestamp=utcnow(),
            )
            db.add(audit_evt)

        await db.commit()
        return new_count, updated_count, drift_detected

    async def approve_catalog_drift(
        self,
        db: AsyncSession,
        app_id: str,
        server_id: str,
    ) -> MCPServer:
        """User explicitly grants human approval for drifted MCP tool catalog."""
        stmt = select(MCPServer).where(MCPServer.id == server_id, MCPServer.app_id == app_id)
        res = await db.execute(stmt)
        server = res.scalar_one_or_none()
        if not server:
            raise PrivGuardException(f"MCP server '{server_id}' not found", status_code=404)

        # Approve all tools for server (except CRITICAL tools)
        stmt_tools = (
            update(MCPToolDefinition)
            .where(
                MCPToolDefinition.server_id == server_id,
                MCPToolDefinition.app_id == app_id,
                MCPToolDefinition.risk_level != "CRITICAL",
            )
            .values(is_approved=True, updated_at=utcnow())
        )
        await db.execute(stmt_tools)

        server.status = "ACTIVE"
        server.updated_at = utcnow()

        audit_evt = MCPAuditEvent(
            app_id=app_id,
            server_id=server.id,
            action="APPROVE_CATALOG",
            status="SUCCESS",
            details=json.dumps({"catalog_fingerprint": server.catalog_fingerprint}),
            timestamp=utcnow(),
        )
        db.add(audit_evt)
        await db.commit()
        return server

    async def approve_server_catalog(
        self,
        db: AsyncSession,
        app_id: str,
        server: MCPServer,
    ) -> MCPServer:
        """Alias for approving catalog drift accepting MCPServer model object."""
        return await self.approve_catalog_drift(db=db, app_id=app_id, server_id=server.id)


# Global singleton tool registry
mcp_tool_registry = MCPToolRegistry()

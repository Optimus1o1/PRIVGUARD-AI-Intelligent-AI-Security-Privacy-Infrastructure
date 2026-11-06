"""Agent Permission Engine enforcing least privilege and resource-level authorization."""

import json
from typing import Dict, List, Optional
from app.core.exceptions import PrivGuardException, UnauthorizedToolError
from app.database.models import Agent


class PermissionEngine:
    """Evaluates agent permissions, allowed tool lists, and resource-level constraints."""

    def check_agent_tool_permission(self, agent: Agent, tool_name: str) -> None:
        """
        Enforces that the agent's granted scope explicitly contains the requested tool.
        Default DENY: If not explicitly allowlisted on the agent, denies execution.
        """
        try:
            allowed_list = json.loads(agent.allowed_tools) if agent.allowed_tools else []
        except Exception:
            allowed_list = []

        if tool_name not in allowed_list and "*" not in allowed_list:
            raise UnauthorizedToolError(
                tool_name=tool_name,
                reason=f"Agent '{agent.id}' is not granted permission to use tool '{tool_name}'.",
            )

    def check_resource_access(
        self,
        granted_resource: Optional[str],
        requested_resource: Optional[str],
    ) -> None:
        """Enforces that the requested resource matches the granted resource pattern."""
        if not granted_resource:
            return  # No specific resource restriction on grant

        if not requested_resource:
            raise PrivGuardException(
                message="Resource-scoped capability requires an explicit target resource.",
                status_code=403,
                error_code="RESOURCE_REQUIRED",
            )

        if granted_resource != "*" and granted_resource != requested_resource:
            raise PrivGuardException(
                message=f"Access denied: Granted resource '{granted_resource}' does not permit access to '{requested_resource}'.",
                status_code=403,
                error_code="RESOURCE_ACCESS_DENIED",
            )


# Shared permission engine instance
permission_engine = PermissionEngine()

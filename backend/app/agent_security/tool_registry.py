"""Central tool registry enforcing strict allowlisting, schemas, and risk tiers."""

from typing import Any, Callable, Coroutine, Dict, List, Optional
from pydantic import BaseModel
from app.agent_security.executor import ToolExecutor
from app.core.exceptions import PrivGuardException, UnauthorizedToolError


class RegisteredTool(BaseModel):
    """Metadata and execution configuration for a registered tool."""

    name: str
    description: str
    required_parameters: List[str]
    optional_parameters: List[str]
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    requires_approval: bool
    is_enabled: bool = True
    timeout_seconds: float = 10.0


class ToolRegistry:
    """Manages authorized tools and enforces strict parameter schemas."""

    def __init__(self):
        self._tools: Dict[str, RegisteredTool] = {}
        self._handlers: Dict[str, Callable[[Dict[str, Any]], Coroutine[Any, Any, str]]] = {}
        self._register_default_tools()

    def _register_default_tools(self):
        # 1. read_file
        self.register(
            RegisteredTool(
                name="read_file",
                description="Read contents of a file located strictly in the sandbox directory.",
                required_parameters=["path"],
                optional_parameters=[],
                risk_level="LOW",
                requires_approval=False,
                timeout_seconds=5.0,
            ),
            ToolExecutor.execute_read_file,
        )

        # 2. search_web
        self.register(
            RegisteredTool(
                name="search_web",
                description="Search authorized internet domains for reference information.",
                required_parameters=["query"],
                optional_parameters=["domain"],
                risk_level="LOW",
                requires_approval=False,
                timeout_seconds=10.0,
            ),
            ToolExecutor.execute_search_web,
        )

        # 3. send_email
        self.register(
            RegisteredTool(
                name="send_email",
                description="Send an email to a colleague or external contact. High risk: requires approval.",
                required_parameters=["recipient", "subject", "body"],
                optional_parameters=[],
                risk_level="HIGH",
                requires_approval=True,
                timeout_seconds=10.0,
            ),
            ToolExecutor.execute_send_email,
        )

        # 4. delete_file
        self.register(
            RegisteredTool(
                name="delete_file",
                description="Permanently delete a file from the sandbox directory. High risk: requires approval.",
                required_parameters=["path"],
                optional_parameters=[],
                risk_level="HIGH",
                requires_approval=True,
                timeout_seconds=5.0,
            ),
            ToolExecutor.execute_delete_file,
        )

        # 5. execute_code (Disabled by default in v0.1)
        self.register(
            RegisteredTool(
                name="execute_code",
                description="Execute arbitrary Python code. Disabled in v0.1.",
                required_parameters=["code"],
                optional_parameters=["language"],
                risk_level="CRITICAL",
                requires_approval=True,
                is_enabled=False,
                timeout_seconds=5.0,
            ),
            ToolExecutor.execute_code,
        )

    def register(
        self,
        tool: RegisteredTool,
        handler: Callable[[Dict[str, Any]], Coroutine[Any, Any, str]],
    ):
        """Registers a new tool and its async execution handler."""
        self._tools[tool.name] = tool
        self._handlers[tool.name] = handler

    def get_tool(self, tool_name: str) -> RegisteredTool:
        """Retrieves registered tool specification or raises UnauthorizedToolError."""
        tool = self._tools.get(tool_name)
        if not tool:
            raise UnauthorizedToolError(
                tool_name=tool_name,
                reason="Tool is not registered in the PRIVGUARD tool allowlist.",
            )
        if not tool.is_enabled:
            raise UnauthorizedToolError(
                tool_name=tool_name,
                reason="Tool is disabled by administrator policy.",
            )
        return tool

    def get_handler(self, tool_name: str) -> Callable[[Dict[str, Any]], Coroutine[Any, Any, str]]:
        """Returns the handler function for a registered tool."""
        self.get_tool(tool_name)
        return self._handlers[tool_name]

    def validate_parameters(self, tool_name: str, parameters: Dict[str, Any]) -> None:
        """Enforces schema compliance and rejects unexpected or missing arguments."""
        tool = self.get_tool(tool_name)

        # 1. Check all required parameters are present
        missing = [req for req in tool.required_parameters if req not in parameters]
        if missing:
            raise PrivGuardException(
                message=f"Missing required parameter(s) for tool '{tool_name}': {', '.join(missing)}",
                status_code=400,
                error_code="INVALID_TOOL_PARAMETERS",
            )

        # 2. Reject unexpected parameters (strict schema enforcement)
        allowed_params = set(tool.required_parameters + tool.optional_parameters)
        unexpected = [p for p in parameters.keys() if p not in allowed_params]
        if unexpected:
            raise PrivGuardException(
                message=f"Unexpected parameter(s) for tool '{tool_name}': {', '.join(unexpected)}",
                status_code=400,
                error_code="UNEXPECTED_TOOL_PARAMETERS",
            )

    def list_tools(self) -> List[RegisteredTool]:
        """Returns all registered tools."""
        return list(self._tools.values())


# Shared tool registry instance
tool_registry = ToolRegistry()

"""Tool Registry and Controlled Execution Endpoints."""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from app.agent_security.tool_broker import tool_broker
from app.agent_security.tool_registry import RegisteredTool, tool_registry
from app.core.authentication import get_current_app
from app.database.connection import get_db_session
from app.database.models import Application

router = APIRouter(prefix="/v1/tools", tags=["Agent Security - Execution Broker"])


class ExecuteToolPayload(BaseModel):
    agent_id: str = Field(..., description="ID of the executing agent")
    task_id: str = Field(..., description="ID of the active task session")
    capability_token: str = Field(..., description="Opaque capability token issued by PRIVGUARD")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Parameters matching tool schema")
    approval_id: Optional[str] = Field(None, description="Approval ID if operation required authorization")


class ExecuteToolResponse(BaseModel):
    execution_id: str
    status: str
    tool: str
    output: str
    duration_ms: float


@router.get("", response_model=List[RegisteredTool])
async def list_tools(
    current_app: Application = Depends(get_current_app),
) -> List[RegisteredTool]:
    """Lists all tools currently registered in the PRIVGUARD allowlist."""
    return tool_registry.list_tools()


@router.post("/{tool_name}/execute", response_model=ExecuteToolResponse)
async def execute_tool(
    tool_name: str,
    payload: ExecuteToolPayload,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> ExecuteToolResponse:
    """
    Executes a registered tool through the PRIVGUARD Agent Security Broker.
    Enforces identity, capabilities, parameters schema, sandboxing, and human approvals.
    """
    res = await tool_broker.execute(
        db=db,
        app=current_app,
        agent_id=payload.agent_id,
        task_id=payload.task_id,
        tool_name=tool_name,
        parameters=payload.parameters,
        capability_token=payload.capability_token,
        approval_id=payload.approval_id,
    )
    return ExecuteToolResponse(**res)

"""Agent Identity Management Endpoints."""

import json
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from app.agent_security.identity import agent_identity_manager
from app.core.authentication import get_current_app
from app.database.connection import get_db_session
from app.database.models import Application

router = APIRouter(prefix="/v1/agents", tags=["Agent Security - Identity"])


class AgentRegisterRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    description: Optional[str] = Field(None, max_length=255)
    allowed_tools: Optional[List[str]] = Field(default_factory=lambda: ["read_file", "search_web"])


class AgentResponse(BaseModel):
    id: str
    name: str
    description: Optional[str]
    status: str
    allowed_tools: List[str]
    created_at: datetime
    last_activity_at: datetime


@router.post("/register", response_model=AgentResponse)
async def register_agent(
    payload: AgentRegisterRequest,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> AgentResponse:
    """Registers an AI agent bound to the authenticated application identity."""
    agent = await agent_identity_manager.register_agent(
        db=db,
        app_id=current_app.id,
        name=payload.name,
        description=payload.description,
        allowed_tools=payload.allowed_tools,
    )
    return AgentResponse(
        id=agent.id,
        name=agent.name,
        description=agent.description,
        status=agent.status,
        allowed_tools=json.loads(agent.allowed_tools),
        created_at=agent.created_at,
        last_activity_at=agent.last_activity_at,
    )


@router.get("", response_model=List[AgentResponse])
async def list_agents(
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> List[AgentResponse]:
    """Lists registered agents belonging to caller application."""
    agents = await agent_identity_manager.list_agents(db=db, app_id=current_app.id)
    return [
        AgentResponse(
            id=a.id,
            name=a.name,
            description=a.description,
            status=a.status,
            allowed_tools=json.loads(a.allowed_tools),
            created_at=a.created_at,
            last_activity_at=a.last_activity_at,
        )
        for a in agents
    ]


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: str,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> AgentResponse:
    """Retrieves agent details enforcing caller ownership."""
    agent = await agent_identity_manager.get_agent(db=db, agent_id=agent_id, app_id=current_app.id)
    return AgentResponse(
        id=agent.id,
        name=agent.name,
        description=agent.description,
        status=agent.status,
        allowed_tools=json.loads(agent.allowed_tools),
        created_at=agent.created_at,
        last_activity_at=agent.last_activity_at,
    )


@router.post("/{agent_id}/disable", response_model=AgentResponse)
async def disable_agent(
    agent_id: str,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> AgentResponse:
    """Disables an agent, immediately blocking all further tool executions."""
    agent = await agent_identity_manager.set_status(
        db=db, agent_id=agent_id, app_id=current_app.id, new_status="DISABLED"
    )
    return AgentResponse(
        id=agent.id,
        name=agent.name,
        description=agent.description,
        status=agent.status,
        allowed_tools=json.loads(agent.allowed_tools),
        created_at=agent.created_at,
        last_activity_at=agent.last_activity_at,
    )


@router.post("/{agent_id}/revoke", response_model=AgentResponse)
async def revoke_agent(
    agent_id: str,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> AgentResponse:
    """Permanently revokes an agent."""
    agent = await agent_identity_manager.set_status(
        db=db, agent_id=agent_id, app_id=current_app.id, new_status="REVOKED"
    )
    return AgentResponse(
        id=agent.id,
        name=agent.name,
        description=agent.description,
        status=agent.status,
        allowed_tools=json.loads(agent.allowed_tools),
        created_at=agent.created_at,
        last_activity_at=agent.last_activity_at,
    )


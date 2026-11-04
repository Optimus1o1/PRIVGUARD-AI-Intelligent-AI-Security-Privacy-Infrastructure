"""Task Management Endpoints."""

from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession
from app.agent_security.task_manager import task_manager
from app.core.authentication import get_current_app
from app.database.connection import get_db_session
from app.database.models import Application

router = APIRouter(prefix="/v1/tasks", tags=["Agent Security - Tasks"])


class CreateTaskRequest(BaseModel):
    agent_id: str = Field(..., description="ID of registered agent performing the task")
    description: Optional[str] = Field(None, max_length=255)
    ttl_seconds: int = Field(600, ge=30, le=86400, description="Task session validity window in seconds")


class TaskResponse(BaseModel):
    id: str
    agent_id: str
    status: str
    description: Optional[str]
    created_at: datetime
    expires_at: datetime
    completed_at: Optional[datetime]


@router.post("", response_model=TaskResponse)
async def create_task(
    payload: CreateTaskRequest,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> TaskResponse:
    """Initializes a new task session bound to an authenticated agent."""
    task = await task_manager.create_task(
        db=db,
        agent_id=payload.agent_id,
        app_id=current_app.id,
        description=payload.description,
        ttl_seconds=payload.ttl_seconds,
    )
    return TaskResponse(
        id=task.id,
        agent_id=task.agent_id,
        status=task.status,
        description=task.description,
        created_at=task.created_at,
        expires_at=task.expires_at,
        completed_at=task.completed_at,
    )


@router.get("/{task_id}", response_model=TaskResponse)
async def get_task(
    task_id: str,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> TaskResponse:
    """Retrieves task status and boundaries."""
    task = await task_manager.get_task(db=db, task_id=task_id, app_id=current_app.id)
    return TaskResponse(
        id=task.id,
        agent_id=task.agent_id,
        status=task.status,
        description=task.description,
        created_at=task.created_at,
        expires_at=task.expires_at,
        completed_at=task.completed_at,
    )


@router.post("/{task_id}/cancel", response_model=TaskResponse)
async def cancel_task(
    task_id: str,
    current_app: Application = Depends(get_current_app),
    db: AsyncSession = Depends(get_db_session),
) -> TaskResponse:
    """Cancels task and immediately revokes all associated capability grants."""
    task = await task_manager.cancel_task(db=db, task_id=task_id, app_id=current_app.id)
    return TaskResponse(
        id=task.id,
        agent_id=task.agent_id,
        status=task.status,
        description=task.description,
        created_at=task.created_at,
        expires_at=task.expires_at,
        completed_at=task.completed_at,
    )

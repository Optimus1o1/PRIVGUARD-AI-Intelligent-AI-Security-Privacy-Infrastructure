"""Task session management models for PRIVGUARD SDK."""

from datetime import datetime

from pydantic import BaseModel, Field

from privguard_sdk.types import TaskStatus


class CreateTaskRequest(BaseModel):
    """Payload to create a task session."""

    agent_id: str = Field(..., description="ID of registered agent bound to this task")
    description: str | None = Field(None, max_length=255, description="Task context description")
    ttl_seconds: int = Field(600, ge=30, le=86400, description="Task session validity window in seconds")
    max_steps: int | None = Field(None, ge=1, le=500, description="Upper-bounded step quota")


class TaskResponse(BaseModel):
    """Task session record."""

    id: str
    agent_id: str
    status: TaskStatus
    description: str | None = None
    created_at: datetime
    expires_at: datetime
    completed_at: datetime | None = None
    step_count: int | None = 0
    max_steps: int | None = 50

"""Health and readiness models for PRIVGUARD SDK."""

from typing import Any

from pydantic import BaseModel, Field


class LivenessResponse(BaseModel):
    """Response returned by /health/live probe."""

    status: str = Field(..., description="Service status ('healthy')")
    service: str = Field(..., description="Service name ('privguard')")
    version: str = Field(..., description="Service version")
    environment: str = Field(..., description="Deployment environment")


class ReadinessResponse(BaseModel):
    """Response returned by /health/ready probe."""

    status: str = Field(default="ready", description="Overall readiness status")
    checks: dict[str, Any] = Field(default_factory=dict, description="Component connectivity checks")

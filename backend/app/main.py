"""PRIVGUARD AI - Independent Security & Privacy Enforcement Layer.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api import agents, approvals, audit, capabilities, gateway, health, policies, privacy, tasks, threats, tools
from app.core.config import settings
from app.core.exceptions import (
    AuthenticationError,
    FailClosedError,
    PolicyViolationError,
    PrivGuardException,
    SecretDetectedError,
    UnauthorizedToolError,
)
from app.database.connection import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown lifecycle management."""
    # Initialize SQLite tables and WAL mode
    await init_db()
    yield


app = FastAPI(
    title="PRIVGUARD AI",
    description="Independent security and privacy enforcement layer between AI applications, data sources, models, and tools.",
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS Middleware for Dashboard / Local Developer Client
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Global Exception Handlers enforcing Fail-Closed Security
@app.exception_handler(SecretDetectedError)
async def secret_detected_handler(request: Request, exc: SecretDetectedError):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.error_code,
                "message": exc.message,
                "details": exc.details,
            }
        },
    )


@app.exception_handler(AuthenticationError)
async def authentication_error_handler(request: Request, exc: AuthenticationError):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.error_code,
                "message": exc.message,
            }
        },
    )


@app.exception_handler(PolicyViolationError)
async def policy_violation_handler(request: Request, exc: PolicyViolationError):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.error_code,
                "message": exc.message,
                "details": exc.details,
            }
        },
    )


@app.exception_handler(UnauthorizedToolError)
async def unauthorized_tool_handler(request: Request, exc: UnauthorizedToolError):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.error_code,
                "message": exc.message,
                "details": exc.details,
            }
        },
    )


@app.exception_handler(PrivGuardException)
async def generic_privguard_handler(request: Request, exc: PrivGuardException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.error_code,
                "message": exc.message,
                "details": exc.details,
            }
        },
    )


# Register Module Routers
app.include_router(health.router)
app.include_router(gateway.router)
app.include_router(privacy.router)
app.include_router(policies.router)
app.include_router(audit.router)
app.include_router(agents.router)
app.include_router(tasks.router)
app.include_router(capabilities.router)
app.include_router(approvals.router)
app.include_router(tools.router)
app.include_router(threats.router)



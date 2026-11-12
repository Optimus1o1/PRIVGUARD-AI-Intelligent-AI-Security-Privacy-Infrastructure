"""PRIVGUARD AI - Independent Security & Privacy Enforcement Layer.
Moon Sanctum Labs - Decode. Build. Evolve.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from app.api import (
    agents,
    approvals,
    audit,
    capabilities,
    compliance,
    dashboard,
    enterprise,
    fleet,
    gateway,
    health,
    identity,
    incidents,
    keys,
    mcp,
    memory,
    policies,
    privacy,
    secrets,
    system,
    metrics,
    monitoring,
    tasks,
    threats,
    tools,
    workspaces,
)
from app.core.config import settings
from app.core.middleware import RequestSizeLimitMiddleware, PayloadTooLargeException
from starlette.exceptions import HTTPException as StarletteHTTPException
from app.observability import init_observability
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
    # In development/test mode, auto-create SQLite tables; in production, Alembic handles migrations
    if settings.ENVIRONMENT.lower() not in ("production", "prod"):
        await init_db()
    # Initialize redis pool if configured
    try:
        from app.infrastructure.redis_client import init_redis, close_redis

        await init_redis()
    except Exception:
        pass
    yield
    try:
        from app.infrastructure.redis_client import close_redis

        await close_redis()
    except Exception:
        pass


app = FastAPI(
    title="PRIVGUARD AI",
    description="Independent security and privacy enforcement layer between AI applications, data sources, models, and tools.",
    version=settings.VERSION,
    lifespan=lifespan,
    docs_url="/docs" if settings.ENVIRONMENT.lower() not in ("production", "prod") else None,
    redoc_url="/redoc" if settings.ENVIRONMENT.lower() not in ("production", "prod") else None,
)

init_observability(app)

# Request Size Limit Middleware: Rejects payloads > settings.MAX_REQUEST_SIZE_BYTES (10 MB)
app.add_middleware(RequestSizeLimitMiddleware)

# CORS Middleware: strictly bounded origin whitelist, restricted methods and headers
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Content-Type",
        "Authorization",
        "X-API-Key",
        "X-Tenant-ID",
        "X-Workspace-ID",
        "X-User-ID",
        "mcp-version",
        "mcp-method",
        "mcp-name",
    ],
    max_age=600,
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


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    # Unpack payload size exceptions wrapped by AnyIO / Starlette BaseHTTPMiddleware TaskGroups
    cause = exc.__cause__
    if cause:
        if isinstance(cause, PayloadTooLargeException):
            return JSONResponse(
                status_code=413,
                content={
                    "error": {
                        "code": "PAYLOAD_TOO_LARGE",
                        "message": f"Request body exceeds maximum allowed size of {cause.max_bytes} bytes.",
                        "details": {"max_allowed_bytes": cause.max_bytes},
                    }
                },
            )
        if isinstance(cause, BaseExceptionGroup):
            for sub_exc in cause.exceptions:
                if isinstance(sub_exc, PayloadTooLargeException):
                    return JSONResponse(
                        status_code=413,
                        content={
                            "error": {
                                "code": "PAYLOAD_TOO_LARGE",
                                "message": f"Request body exceeds maximum allowed size of {sub_exc.max_bytes} bytes.",
                                "details": {"max_allowed_bytes": sub_exc.max_bytes},
                            }
                        },
                    )
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
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
app.include_router(dashboard.router)
app.include_router(memory.router)
app.include_router(mcp.router)
app.include_router(enterprise.router)
app.include_router(workspaces.router)
app.include_router(fleet.router)
app.include_router(identity.router)
app.include_router(system.router)
app.include_router(keys.router)
app.include_router(secrets.router)
app.include_router(incidents.router)
app.include_router(metrics.router)
app.include_router(monitoring.router)
app.include_router(compliance.router)

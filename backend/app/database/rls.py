"""PostgreSQL Row-Level Security (RLS) definitions and tenant context interceptors."""

from typing import List
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

# List of tables requiring PostgreSQL Row-Level Security enforcement
TENANT_OWNED_TABLES: List[str] = [
    "applications",
    "agents",
    "agent_tasks",
    "policy_rules",
    "capability_grants",
    "approval_requests",
    "tool_execution_records",
    "audit_events",
    "threat_events",
    "memory_records",
    "memory_proposals",
    "memory_permissions",
    "memory_versions",
    "memory_deletion_jobs",
    "memory_audit_events",
    "mcp_servers",
    "mcp_tool_definitions",
    "mcp_resource_definitions",
    "mcp_audit_events",
    "workspaces",
    "policy_bundles",
    "fleet_resources",
    "integration_credentials",
    "enterprise_audit_events",
    "audit_export_jobs",
    "outbox_events",
    "managed_keys",
    "key_rotation_jobs",
    "key_migration_jobs",
    "secret_metadata_records",
    "secret_rotation_jobs",
    "key_access_events",
]


def generate_rls_ddl() -> str:
    """
    Generates PostgreSQL DDL to enforce Row-Level Security across all tenant-owned tables.
    Uses FORCE ROW LEVEL SECURITY to guarantee table owners cannot bypass policies.
    """
    ddl_statements = [
        "-- PRIVGUARD AI Enterprise Row-Level Security (RLS) Configuration",
        "-- Requires PostgreSQL 12+ with non-superuser application role 'privguard_app'",
        "",
    ]

    for table in TENANT_OWNED_TABLES:
        ddl_statements.extend(
            [
                f"-- Table: {table}",
                f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;",
                f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;",
                f"DROP POLICY IF EXISTS tenant_isolation_{table} ON {table};",
                f"CREATE POLICY tenant_isolation_{table} ON {table}",
                "    AS RESTRICTIVE",
                "    FOR ALL",
                "    TO privguard_app",
                "    USING (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), ''))",
                "    WITH CHECK (tenant_id = NULLIF(current_setting('app.current_tenant_id', true), ''));",
                "",
            ]
        )

    return "\n".join(ddl_statements)


async def set_db_tenant_context(session: AsyncSession, tenant_id: str) -> None:
    """
    Sets the transaction-local PostgreSQL session variable for the current tenant.
    This informs PostgreSQL RLS policies of the active tenant context.
    If the database is SQLite, this safely no-ops.
    """
    bind = session.bind
    if bind and "sqlite" in bind.dialect.name:
        # SQLite does not support custom GUCs or RLS; application queries enforce isolation
        return

    # In PostgreSQL, execute SET LOCAL app.current_tenant_id
    # Clean and validate tenant_id to prevent injection
    safe_tenant_id = tenant_id.replace("'", "''").strip()
    await session.execute(text(f"SET LOCAL app.current_tenant_id = '{safe_tenant_id}';"))


async def reset_db_tenant_context(session: AsyncSession) -> None:
    """Resets the transaction-local PostgreSQL tenant variable."""
    bind = session.bind
    if bind and "sqlite" in bind.dialect.name:
        return
    await session.execute(text("RESET app.current_tenant_id;"))

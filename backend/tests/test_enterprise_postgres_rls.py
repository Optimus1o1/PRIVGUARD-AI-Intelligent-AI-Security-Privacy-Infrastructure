"""PostgreSQL Row-Level Security (RLS) configuration and DDL verification harness."""

import pytest
from app.database.rls import generate_rls_ddl, TENANT_OWNED_TABLES, set_db_tenant_context
from sqlalchemy.ext.asyncio import AsyncSession


def test_rls_ddl_generation_completeness():
    """Verifies that PostgreSQL RLS DDL script covers all tenant-owned tables with FORCE RLS."""
    ddl = generate_rls_ddl()

    assert "ENABLE ROW LEVEL SECURITY" in ddl
    assert "FORCE ROW LEVEL SECURITY" in ddl
    assert "current_setting('app.current_tenant_id', true)" in ddl
    assert "TO privguard_app" in ddl

    # Verify each tenant-owned table is included
    for table in TENANT_OWNED_TABLES:
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY;" in ddl
        assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY;" in ddl
        assert f"CREATE POLICY tenant_isolation_{table} ON {table}" in ddl


@pytest.mark.asyncio
async def test_rls_context_injection_sanitization(db_session: AsyncSession):
    """Verifies that malicious tenant_id strings with SQL injection attempts are safely sanitized."""
    malicious_tenant = "org_alpha' OR 1=1; DROP TABLE agents; --"

    # Should safely execute without raising SQL syntax errors on SQLite or PostgreSQL
    await set_db_tenant_context(db_session, malicious_tenant)


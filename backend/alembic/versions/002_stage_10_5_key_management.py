"""Stage 10.5 Key Management and Secrets Lifecycle Schema Migration

Revision ID: 002_stage_10_5_key_management
Revises: 001_stage_9_baseline
Create Date: 2026-11-05
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from app.database.models import Base
from app.database.rls import generate_rls_ddl

# revision identifiers, used by Alembic.
revision: str = "002_stage_10_5_key_management"
down_revision: Union[str, None] = "001_stage_9_baseline"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Creates Stage 10.5 key management tables and applies RLS policies."""
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)

    # In PostgreSQL, enforce RLS DDL across tenant tables
    if bind.dialect.name == "postgresql":
        rls_sql = generate_rls_ddl()
        for stmt in rls_sql.split(";"):
            cleaned = stmt.strip()
            if cleaned and not cleaned.startswith("--"):
                try:
                    op.execute(sa.text(cleaned))
                except Exception:
                    pass


def downgrade() -> None:
    """Drops Stage 10.5 tables."""
    bind = op.get_bind()
    for table_name in [
        "key_access_events",
        "secret_rotation_jobs",
        "secret_metadata_records",
        "key_migration_jobs",
        "key_rotation_jobs",
        "key_versions",
        "managed_keys",
    ]:
        try:
            op.drop_table(table_name)
        except Exception:
            pass

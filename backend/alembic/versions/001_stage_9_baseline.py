"""Initial Stage 9 Baseline Schema Migration

Revision ID: 001_stage_9_baseline
Revises: None
Create Date: 2026-11-05
"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa
from app.database.models import Base
from app.database.rls import generate_rls_ddl

# revision identifiers, used by Alembic.
revision: str = "001_stage_9_baseline"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Creates all Stage 1-9 tables, indices, and PostgreSQL Row-Level Security policies."""
    bind = op.get_bind()
    Base.metadata.create_all(bind=bind)

    # If executing against PostgreSQL, enforce RLS DDL
    if bind.dialect.name == "postgresql":
        rls_sql = generate_rls_ddl()
        for stmt in rls_sql.split(";"):
            cleaned = stmt.strip()
            if cleaned and not cleaned.startswith("--"):
                op.execute(sa.text(cleaned))


def downgrade() -> None:
    """Drops all tables and RLS policies."""
    bind = op.get_bind()
    Base.metadata.drop_all(bind=bind)

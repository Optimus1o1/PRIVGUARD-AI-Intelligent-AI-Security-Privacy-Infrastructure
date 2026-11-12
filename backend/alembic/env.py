import asyncio
from logging.config import fileConfig
import os
import sys
from pathlib import Path

from sqlalchemy import pool, text
from sqlalchemy.engine import Connection
from sqlalchemy.ext.asyncio import async_engine_from_config

from alembic import context

# Add backend directory to sys.path so app modules can be imported
backend_dir = Path(__file__).resolve().parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.core.config import settings
from app.database.models import Base
from app.database.rls import generate_rls_ddl

# this is the Alembic Config object
config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Model metadata for autogenerate and migrations
target_metadata = Base.metadata

# Set database URL dynamically from PRIVGUARD settings
database_url = settings.DATABASE_URL
# In alembic async runner, ensure driver matches asyncpg or aiosqlite
config.set_main_option("sqlalchemy.url", database_url)


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection: Connection) -> None:
    """Execute migrations against active connection."""
    context.configure(connection=connection, target_metadata=target_metadata)

    with context.begin_transaction():
        context.run_migrations()

        # If connected to PostgreSQL, enforce Row-Level Security policies after migration
        if connection.dialect.name == "postgresql":
            rls_sql = generate_rls_ddl()
            for statement in rls_sql.split(";"):
                stmt = statement.strip()
                if stmt and not stmt.startswith("--"):
                    connection.execute(text(stmt))


async def run_async_migrations() -> None:
    """Create async engine and run migrations."""
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = settings.DATABASE_URL

    connectable = async_engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    async with connectable.connect() as connection:
        await connection.run_sync(do_run_migrations)

    await connectable.dispose()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode."""
    asyncio.run(run_async_migrations())


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()

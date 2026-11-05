-- ==============================================================================
-- PRIVGUARD AI - PostgreSQL Database Initialization Script
-- Moon Sanctum Labs - Decode. Build. Evolve.
-- ==============================================================================

-- 1. Create Migration Role (Owns schema, executes DDL, NO superuser)
DO
$do$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'privguard_migrator') THEN
      CREATE ROLE privguard_migrator WITH LOGIN PASSWORD 'migration_placeholder_pw';
   END IF;
END
$do$;

-- 2. Create Runtime Application Role (Restricted DML, NOBYPASSRLS)
DO
$do$
BEGIN
   IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'privguard_app') THEN
      CREATE ROLE privguard_app WITH LOGIN NOBYPASSRLS NOSUPERUSER NOCREATEDB NOCREATEROLE;
   END IF;
END
$do$;

-- 3. Grant schema permissions to migrator
GRANT ALL PRIVILEGES ON SCHEMA public TO privguard_migrator;

-- 4. Default privileges: Allow runtime application role to read/write tables created by migrator
ALTER DEFAULT PRIVILEGES FOR ROLE privguard_migrator IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO privguard_app;

ALTER DEFAULT PRIVILEGES FOR ROLE privguard_migrator IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO privguard_app;

GRANT USAGE ON SCHEMA public TO privguard_app;

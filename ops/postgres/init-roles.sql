-- ops/postgres/init-roles.sql (R11)
--
-- Provisions the two least-privilege PostgreSQL roles for the AI engine:
--
--   ira_aml_migrator — separate MIGRATION/OWNER role: owns the database and every
--       object the migrations create (alembic runs with this role via
--       MIGRATION_DATABASE_URL). NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS.
--   ira_aml_app — the application role: non-owner, NOSUPERUSER NOCREATEDB
--       NOCREATEROLE NOBYPASSRLS, data-plane grants only. Every service worker
--       and API process runs with this role — never with BYPASSRLS.
--
-- NO passwords live in this file. Provision secrets out-of-band (secret store),
-- then set them, e.g.:
--     ALTER ROLE ira_aml_migrator PASSWORD :'migrator_password';
--     ALTER ROLE ira_aml_app      PASSWORD :'app_password';
--
-- Idempotent. Run as a superuser against EACH database the engine uses:
--     psql -d <db> -v db_name=<db> -v ON_ERROR_STOP=1 -f ops/postgres/init-roles.sql
--
-- Post-conditions asserted by ai-engine/tests/integration/test_postgres_rls.py:
--   * ira_aml_app: NOSUPERUSER/NOCREATEROLE/NOCREATEDB/NOBYPASSRLS, owns no table,
--     no schema, member of no role; cannot execute DDL (role_cannot_ddl).
--   * All institutional data tables are FORCEd under RLS (owned by migrations);
--     the app role reaches rows only through the tenant policy.

\set on_error_stop on
\if :{?db_name}
\else
\echo 'missing -v db_name=<database>'
\quit
\endif

-- 1) Roles (cluster-wide; idempotent). Neither role is a superuser, can create
--    databases/roles, or bypass RLS.
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ira_aml_migrator') THEN
        CREATE ROLE ira_aml_migrator LOGIN
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'ira_aml_app') THEN
        CREATE ROLE ira_aml_app LOGIN
            NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOREPLICATION;
    END IF;
END
$$;

-- 2) The migration role owns the database (and thereby schema public via
--    pg_database_owner); it is the only role that may run DDL.
ALTER DATABASE :"db_name" OWNER TO ira_aml_migrator;

-- 3) Schema access: lock the default down, then grant explicitly.
REVOKE ALL ON SCHEMA public FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO ira_aml_app;
REVOKE CREATE ON SCHEMA public FROM ira_aml_app;

-- 4) Minimal data-plane grants for the app role. Tables are owned by the
--    migration role; the app role gets DML only — no TRUNCATE/REFERENCES/TRIGGER,
--    no ownership, no DDL.
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ira_aml_app;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO ira_aml_app;
ALTER DEFAULT PRIVILEGES FOR ROLE ira_aml_migrator IN SCHEMA public
    GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO ira_aml_app;
ALTER DEFAULT PRIVILEGES FOR ROLE ira_aml_migrator IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO ira_aml_app;

\echo 'init-roles: roles provisioned, grants applied for database :"db_name"'

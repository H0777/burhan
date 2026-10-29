-- ops/postgres/staging-init.sql (H04)
--
-- Staging-only provisioning step that runs ONCE on first cluster init, AFTER
-- ops/postgres/init-roles.sql (which is reused verbatim — never rewritten).
-- It provisions the out-of-band-generated passwords for the two least-privilege
-- roles. NO secret values live in any committed file: the passwords arrive as
-- psql variables supplied by staging-init.sh from the deployment environment
-- (infra/staging/.env, gitignored).
--
-- Post-conditions (asserted by ai-engine/tests/integration/test_postgres_rls.py):
--   * ira_aml_migrator and ira_aml_app can log in with their provisioned
--     passwords; both remain NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE.
--
-- Idempotent (ALTER ROLE ... PASSWORD is safe to re-run).

\set on_error_stop on

ALTER ROLE ira_aml_migrator PASSWORD :'migrator_password';
ALTER ROLE ira_aml_app      PASSWORD :'app_password';

\echo 'staging-init: role passwords provisioned (values out-of-band)'

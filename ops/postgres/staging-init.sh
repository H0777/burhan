#!/usr/bin/env bash
# ops/postgres/staging-init.sh (H04)
#
# Docker postgres entrypoint initializer for the staging stack. Runs ONCE, on
# the FIRST init of an empty data directory, as the bootstrap superuser, before
# alembic ever touches the database.
#
# It reuses ops/postgres/init-roles.sql VERBATIM (the R11 role model: app role
# NOSUPERUSER NOBYPASSRLS + separate migrator) and then applies the staging
# role passwords via ops/postgres/staging-init.sql. Secrets are passed as psql
# variables from the deployment environment — never committed to the repo.
set -euo pipefail

: "${STAGING_MIGRATOR_PASSWORD:?STAGING_MIGRATOR_PASSWORD must be provided (infra/staging/.env)}"
: "${STAGING_APP_PASSWORD:?STAGING_APP_PASSWORD must be provided (infra/staging/.env)}"
: "${POSTGRES_DB:?POSTGRES_DB must be set by the postgres image}"

echo "staging-init.sh: provisioning roles for database ${POSTGRES_DB}"

# 1) Roles, ownership, grants (verbatim R11 file; requires db_name variable).
psql -v ON_ERROR_STOP=1 \
    -d "$POSTGRES_DB" \
    -v db_name="$POSTGRES_DB" \
    -f /ops/postgres/init-roles.sql

# 2) Role passwords (out-of-band values, psql variables only).
psql -v ON_ERROR_STOP=1 \
    -d "$POSTGRES_DB" \
    -v migrator_password="$STAGING_MIGRATOR_PASSWORD" \
    -v app_password="$STAGING_APP_PASSWORD" \
    -f /ops/postgres/staging-init.sql

echo "staging-init.sh: done"

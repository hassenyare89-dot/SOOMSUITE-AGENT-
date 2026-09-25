#!/bin/sh
# Runs once on first container start (superuser). Creates the schema owner and the Temporal
# database/user. Service roles are created by migrations (NOLOGIN) and given passwords by
# scripts/provision_db_users.py in the `migrate` job.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<SQL
CREATE ROLE platform_owner LOGIN CREATEROLE PASSWORD '${DB_OWNER_PASSWORD}';
ALTER DATABASE ${POSTGRES_DB} OWNER TO platform_owner;
ALTER SCHEMA public OWNER TO platform_owner;
CREATE EXTENSION IF NOT EXISTS vector;
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS btree_gist;
CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE ROLE temporal LOGIN CREATEDB PASSWORD '${TEMPORAL_DB_PASSWORD}';
SQL

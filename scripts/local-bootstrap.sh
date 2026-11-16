#!/usr/bin/env bash
# First-run bootstrap for a fresh cluster (no migration dumps on this machine).
#
# Idempotent: creates the `barad` role and `barad_platform` database if they are
# missing and writes the readiness marker the postgres healthcheck requires, so
# `platform-api` (depends_on: service_healthy) can start. The password is read
# from .env and passed through the container environment, never a command line.
#
#   bash scripts/local-bootstrap.sh
set -Eeuo pipefail

cd "$(dirname "$0")/.."
set -a; source .env; set +a

readonly COMPOSE=(docker compose -f compose.yaml -f compose.local.yaml)
readonly PG=barad-dur-postgres-1
readonly MARKER=/var/lib/postgresql/.migration-restore-complete

log() { printf 'bootstrap: %s\n' "$*"; }
die() { printf 'bootstrap: FATAL: %s\n' "$*" >&2; exit 1; }

[ -n "${barad_db_password:-}" ] || die 'barad_db_password is empty in .env'

# The migration-backup volume is declared `external`; Compose refuses to start
# without it existing, even though this cluster never reads it.
docker volume create barad-dur_migration-backup >/dev/null

log 'starting postgres'
"${COMPOSE[@]}" up -d postgres

log 'waiting for the cluster to accept connections'
for _ in $(seq 1 60); do
	docker exec "$PG" pg_isready -h 127.0.0.1 -U dtrack -d dtrack >/dev/null 2>&1 && break
	sleep 2
done
docker exec "$PG" pg_isready -h 127.0.0.1 -U dtrack -d dtrack >/dev/null ||
	die 'postgres did not become ready'

log 'ensuring role "barad" and database "barad_platform"'
docker exec -i -e BARAD_DB_PASSWORD="$barad_db_password" "$PG" \
	psql --username dtrack --dbname dtrack -v ON_ERROR_STOP=1 >/dev/null <<'SQL'
\getenv barad_password BARAD_DB_PASSWORD
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', 'barad', :'barad_password')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'barad')
\gexec
ALTER ROLE barad WITH LOGIN PASSWORD :'barad_password';
SELECT 'CREATE DATABASE barad_platform OWNER barad'
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'barad_platform')
\gexec
SQL

# The healthcheck is `test -f <marker> && pg_isready`: without the marker the
# service never reports healthy and platform-api waits forever.
docker exec -u postgres "$PG" touch "$MARKER"

log 'cluster ready'
docker exec "$PG" psql --username dtrack --dbname dtrack -Atc \
	"select rolname from pg_roles where rolname='barad'"
docker exec "$PG" psql --username dtrack --dbname dtrack -Atc \
	"select datname from pg_database where datname='barad_platform'"

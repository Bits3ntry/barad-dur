#!/usr/bin/env bash
# First-initialization restore for the unified `postgres` service.
#
# The official PostgreSQL entrypoint runs every file in
# /docker-entrypoint-initdb.d exactly once, on an empty data directory, after
# initdb has created the cluster and after POSTGRES_DB/POSTGRES_USER (dtrack)
# exist. This script is therefore the only place where the pre-unification data
# can enter the new volume.
#
# Contract, in order:
#   1. Fail closed unless both verified dumps are present and readable.
#   2. Create the DefectDojo role/database alongside the existing dtrack ones,
#      so the two applications keep separate databases and separate roles.
#   3. Restore each dump into its own database and hand every restored object to
#      the application role that owns that database.
#   4. Write the readiness marker the service healthcheck requires, so a
#      partially restored cluster can never report healthy on a later restart.
#
# Secrets arrive through the environment and are read inside psql with \getenv;
# they are never echoed and never placed on a command line.

set -Eeuo pipefail

readonly BACKUP_DIR=/migration-backup
readonly DT_DUMP=${BACKUP_DIR}/dtrack.dump
readonly DOJO_DUMP=${BACKUP_DIR}/defectdojo.dump
readonly DT_ROLE=${POSTGRES_USER:-dtrack}
readonly DT_DB=${POSTGRES_DB:-dtrack}
readonly DOJO_ROLE=defectdojo
readonly DOJO_DB=defectdojo
readonly MARKER=/var/lib/postgresql/.migration-restore-complete

log() { printf 'init-restore: %s\n' "$*"; }
die() {
	printf 'init-restore: FATAL: %s\n' "$*" >&2
	exit 1
}

is_custom_archive() { [ "$(head -c 5 "$1")" = 'PGDMP' ]; }

# ── 1. Fail closed, before anything is created ──────────────────────────────
[ -n "${DD_DB_PASSWORD:-}" ] ||
	die 'DD_DB_PASSWORD is empty; refusing to create the DefectDojo role'

for dump in "$DT_DUMP" "$DOJO_DUMP"; do
	[ -f "$dump" ] ||
		die "missing $dump: populate the migration-backup volume before the first start"
	[ -s "$dump" ] ||
		die "empty $dump: refusing to initialize from an incomplete backup"
	if is_custom_archive "$dump"; then
		pg_restore --list "$dump" >/dev/null ||
			die "unreadable pg_dump archive $dump: refusing to initialize from a damaged backup"
		log "$dump: pg_dump archive, $(wc -c <"$dump") bytes"
	else
		log "$dump: plain SQL dump, $(wc -c <"$dump") bytes"
	fi
done

# ── 2. One role and one database per application ────────────────────────────
# `dtrack` already exists because POSTGRES_USER=dtrack. DefectDojo keeps its own
# role so neither application can read or write the other's database.
log "ensuring role and database \"$DOJO_ROLE\" (separate from \"$DT_ROLE\")"
psql --username "$POSTGRES_USER" --dbname postgres -v ON_ERROR_STOP=1 <<'SQL'
\getenv dojo_password DD_DB_PASSWORD
SELECT format('CREATE ROLE %I LOGIN PASSWORD %L', 'defectdojo', :'dojo_password')
 WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'defectdojo')
\gexec
ALTER ROLE defectdojo WITH LOGIN PASSWORD :'dojo_password';
SELECT 'CREATE DATABASE defectdojo OWNER defectdojo'
 WHERE NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = 'defectdojo')
\gexec
SQL

# ── 3. Restore each dump into its own database ──────────────────────────────
# Restoring as the superuser keeps extensions and server settings restorable.
# Grants are not replayed: a dump that references roles absent here cannot break
# the restore, and the single owner needs no extra grants.

# Hand every object the restore created to the application role.
#
# The dumps are replayed with --no-owner, so everything that entered the cluster
# belongs to the bootstrap superuser. The transfer must follow dependency order,
# because PostgreSQL rejects some ownership changes in the wrong order:
#
#   * ALTER TABLE ... OWNER TO moves a table's indexes and its serial/identity
#     sequences with it. A sequence linked to a table column must never be
#     altered on its own: PostgreSQL answers "cannot change owner of sequence
#     ... is linked to table ...". That failure aborted the first migration
#     attempt, after both restores, before the readiness marker existed.
#   * Only sequences that no table column owns are altered individually, and
#     only after the tables.
#   * Views, materialized views, foreign tables, standalone types and routines
#     follow for the same "leave nothing behind" reason.
#   * Extension members are skipped: they belong to their extension, not to the
#     application.
#
# The whole transfer is one transaction and it ends with a self-check, so a
# partial transfer rolls back instead of leaving a half-owned database behind.
transfer_ownership() {
	local db=$1 owner=$2

	if [ "$owner" = "$POSTGRES_USER" ]; then
		log "\"$db\" is already owned by \"$owner\"; no ownership transfer needed"
		return 0
	fi

	log "transferring ownership of every restored object in \"$db\" to \"$owner\""
	psql --username "$POSTGRES_USER" --dbname "$db" \
		--single-transaction -v ON_ERROR_STOP=1 -v owner="$owner" <<'SQL'
SELECT set_config('migration.owner', :'owner', false);

-- Schemas created by the dump. `public` is owned by pg_database_owner, so it is
-- not matched here: the role that owns the database already owns it.
SELECT format('ALTER SCHEMA %I OWNER TO %I',
              n.nspname, current_setting('migration.owner'))
  FROM pg_namespace n
 WHERE pg_get_userbyid(n.nspowner) = current_user
   AND n.nspname !~ '^pg_'
   AND n.nspname <> 'information_schema'
\gexec

-- Relations, ordered so a table-linked sequence is never altered on its own:
--   1. tables and partitions (they carry their indexes and owned sequences)
--   2. standalone sequences (no pg_depend row linking them to a table column)
--   3. views and materialized views
--   4. foreign tables
SELECT format('ALTER %s %I.%I OWNER TO %I',
              CASE c.relkind
                WHEN 'S' THEN 'SEQUENCE'
                WHEN 'v' THEN 'VIEW'
                WHEN 'm' THEN 'MATERIALIZED VIEW'
                WHEN 'f' THEN 'FOREIGN TABLE'
                ELSE 'TABLE'
              END,
              n.nspname, c.relname, current_setting('migration.owner'))
  FROM pg_class c
  JOIN pg_namespace n ON n.oid = c.relnamespace
 WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
   AND pg_get_userbyid(c.relowner) = current_user
   AND n.nspname !~ '^pg_'
   AND n.nspname <> 'information_schema'
   -- A sequence owned by a table column is moved by its table, never here.
   AND (c.relkind <> 'S'
        OR NOT EXISTS (
              SELECT 1
                FROM pg_depend d
               WHERE d.classid = 'pg_class'::regclass
                 AND d.objid = c.oid
                 AND d.refclassid = 'pg_class'::regclass
                 AND d.refobjsubid > 0
                 AND d.deptype IN ('a', 'i')))
   AND NOT EXISTS (
         SELECT 1
           FROM pg_depend d
          WHERE d.classid = 'pg_class'::regclass
            AND d.objid = c.oid
            AND d.deptype = 'e')
 ORDER BY CASE c.relkind
            WHEN 'r' THEN 1 WHEN 'p' THEN 1
            WHEN 'S' THEN 2
            WHEN 'v' THEN 3 WHEN 'm' THEN 3
            ELSE 4
          END,
          n.nspname, c.relname
\gexec

-- Domains first: PostgreSQL spells their owner change ALTER DOMAIN.
SELECT format('ALTER DOMAIN %I.%I OWNER TO %I',
              n.nspname, t.typname, current_setting('migration.owner'))
  FROM pg_type t
  JOIN pg_namespace n ON n.oid = t.typnamespace
 WHERE pg_get_userbyid(t.typowner) = current_user
   AND t.typtype = 'd'
   AND n.nspname !~ '^pg_'
   AND n.nspname <> 'information_schema'
   AND NOT EXISTS (
         SELECT 1
           FROM pg_depend d
          WHERE d.classid = 'pg_type'::regclass
            AND d.objid = t.oid
            AND d.deptype = 'e')
\gexec

-- Standalone composite, enum and range types. A table row type follows its
-- table and is excluded here.
SELECT format('ALTER TYPE %I.%I OWNER TO %I',
              n.nspname, t.typname, current_setting('migration.owner'))
  FROM pg_type t
  JOIN pg_namespace n ON n.oid = t.typnamespace
  LEFT JOIN pg_class c ON c.oid = t.typrelid
 WHERE pg_get_userbyid(t.typowner) = current_user
   AND t.typtype IN ('c', 'e', 'r', 'm')
   AND n.nspname !~ '^pg_'
   AND n.nspname <> 'information_schema'
   AND (t.typrelid = 0 OR c.relkind = 'c')
   AND NOT EXISTS (
         SELECT 1
           FROM pg_depend d
          WHERE d.classid = 'pg_type'::regclass
            AND d.objid = t.oid
            AND d.deptype = 'e')
\gexec

-- Routines: functions, procedures and window functions.
SELECT format('ALTER %s %I.%I(%s) OWNER TO %I',
              CASE p.prokind WHEN 'p' THEN 'PROCEDURE' ELSE 'FUNCTION' END,
              n.nspname, p.proname,
              pg_get_function_identity_arguments(p.oid),
              current_setting('migration.owner'))
  FROM pg_proc p
  JOIN pg_namespace n ON n.oid = p.pronamespace
 WHERE pg_get_userbyid(p.proowner) = current_user
   AND p.prokind IN ('f', 'p', 'w')
   AND n.nspname !~ '^pg_'
   AND n.nspname <> 'information_schema'
   AND NOT EXISTS (
         SELECT 1
           FROM pg_depend d
          WHERE d.classid = 'pg_proc'::regclass
            AND d.objid = p.oid
            AND d.deptype = 'e')
\gexec

-- Self-check: the classes above must own nothing on behalf of the bootstrap
-- role any more. Anything left rolls the transaction back, so the readiness
-- marker is never written on a half-owned database.
DO $check$
DECLARE
	leftover text;
BEGIN
	SELECT string_agg(DISTINCT object_class, ', ') INTO leftover
	  FROM (
	        SELECT 'relations' AS object_class
	          FROM pg_class c
	          JOIN pg_namespace n ON n.oid = c.relnamespace
	         WHERE c.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
	           AND pg_get_userbyid(c.relowner) = current_user
	           AND n.nspname !~ '^pg_'
	           AND n.nspname <> 'information_schema'
	           AND NOT EXISTS (
	                 SELECT 1 FROM pg_depend d
	                  WHERE d.classid = 'pg_class'::regclass
	                    AND d.objid = c.oid
	                    AND d.deptype = 'e')
	        UNION ALL
	        SELECT 'types'
	          FROM pg_type t
	          JOIN pg_namespace n ON n.oid = t.typnamespace
	          LEFT JOIN pg_class c ON c.oid = t.typrelid
	         WHERE pg_get_userbyid(t.typowner) = current_user
	           AND t.typtype IN ('c', 'd', 'e', 'r', 'm')
	           AND n.nspname !~ '^pg_'
	           AND n.nspname <> 'information_schema'
	           AND (t.typrelid = 0 OR c.relkind = 'c')
	           AND NOT EXISTS (
	                 SELECT 1 FROM pg_depend d
	                  WHERE d.classid = 'pg_type'::regclass
	                    AND d.objid = t.oid
	                    AND d.deptype = 'e')
	        UNION ALL
	        SELECT 'routines'
	          FROM pg_proc p
	          JOIN pg_namespace n ON n.oid = p.pronamespace
	         WHERE pg_get_userbyid(p.proowner) = current_user
	           AND p.prokind IN ('f', 'p', 'w')
	           AND n.nspname !~ '^pg_'
	           AND n.nspname <> 'information_schema'
	           AND NOT EXISTS (
	                 SELECT 1 FROM pg_depend d
	                  WHERE d.classid = 'pg_proc'::regclass
	                    AND d.objid = p.oid
	                    AND d.deptype = 'e')
	        UNION ALL
	        SELECT 'schemas'
	          FROM pg_namespace n
	         WHERE pg_get_userbyid(n.nspowner) = current_user
	           AND n.nspname !~ '^pg_'
	           AND n.nspname <> 'information_schema'
	       ) remaining;
	IF leftover IS NOT NULL THEN
		RAISE EXCEPTION 'ownership transfer to "%" is incomplete: % still owned by %',
			current_setting('migration.owner'), leftover, current_user;
	END IF;
END
$check$;
SQL
}

restore_dump() {
	local dump=$1 db=$2 owner=$3

	log "restoring $dump into \"$db\""
	if is_custom_archive "$dump"; then
		pg_restore --dbname "$db" --username "$POSTGRES_USER" \
			--no-owner --no-privileges --single-transaction "$dump"
	else
		psql --username "$POSTGRES_USER" --dbname "$db" -v ON_ERROR_STOP=1 \
			--single-transaction --file "$dump"
	fi

	transfer_ownership "$db" "$owner"
	log "restored \"$db\" into \"$owner\""
}

restore_dump "$DT_DUMP" "$DT_DB" "$DT_ROLE"
restore_dump "$DOJO_DUMP" "$DOJO_DB" "$DOJO_ROLE"

# ── 4. Readiness marker ────────────────────────────────────────────────────
# The service healthcheck requires this file. It is written into the data
# volume only after both restores succeed, so a first start that fails closed
# stays unhealthy instead of coming back as a healthy, empty installation.
: >"$MARKER"
log "migration complete: both databases restored; wrote $MARKER"

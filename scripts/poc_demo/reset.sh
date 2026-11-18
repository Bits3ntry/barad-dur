#!/usr/bin/env bash
# Reset the demo estate: wipe everything the POC creates, keep the identity.
#
#   bash scripts/poc_demo/reset.sh            # backup, then wipe
#   bash scripts/poc_demo/reset.sh --no-backup
#
# What survives: the organization, the owner user and their sessions, the API
# keys (the console and the CLI need them), platform settings and AI providers,
# and the intel feeds (KEV/EPSS/trivy-db), which are reference data and take
# minutes to download again.
#
# What goes: projects, components, builds, SBOMs, assets, observations, findings,
# cycles, grants, scope, deployments, scans, jobs, workers, AI runs and chat.
set -Eeuo pipefail

cd "$(dirname "$0")/../.."
set -a; source .env; set +a

readonly PG=(docker exec -i -e "PGPASSWORD=$barad_db_password"
             barad-dur-postgres-1 psql -U barad -d barad_platform -v ON_ERROR_STOP=1)
readonly SQL="scripts/poc_demo/reset.sql"

backup=1
[[ "${1:-}" == "--no-backup" ]] && backup=0

if (( backup )); then
  mkdir -p .barad/backups
  stamp=$(date +%Y%m%d-%H%M%S)
  out=".barad/backups/poc-$stamp.sql.gz"
  docker exec -e PGPASSWORD="$barad_db_password" barad-dur-postgres-1 \
    pg_dump -U barad -d barad_platform --no-owner --no-acl | gzip > "$out"
  printf 'backup: %s (%s)\n' "$out" "$(du -h "$out" | cut -f1)"
fi

echo '--- before'
"${PG[@]}" -At -c "select 'projects', count(*) from projects
                   union all select 'components', count(*) from components
                   union all select 'assets', count(*) from assets
                   union all select 'findings', count(*) from findings
                   union all select 'cycles', count(*) from cycles;"

"${PG[@]}" < "$SQL"

echo '--- after'
"${PG[@]}" -At -c "select 'projects', count(*) from projects
                   union all select 'components', count(*) from components
                   union all select 'assets', count(*) from assets
                   union all select 'findings', count(*) from findings
                   union all select 'cycles', count(*) from cycles
                   union all select 'grants', count(*) from scan_grants
                   union all select 'jobs', count(*) from scan_jobs
                   union all select 'observations', count(*) from observations;"

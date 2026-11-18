#!/usr/bin/env bash
# Rebuild and recreate ONLY the platform API, then prove it came back.
#   bash scripts/poc_demo/redeploy_api.sh
set -Eeuo pipefail
cd "$(dirname "$0")/../.."
set -a; source .env; set +a

docker build -q -t barad-dur-platform-api ./backend
docker compose up -d --no-deps --no-build --force-recreate platform-api >/dev/null

for _ in $(seq 1 60); do
  code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8090/healthz || true)
  [[ "$code" == "200" ]] && break
  sleep 2
done
printf 'healthz: %s\n' "$code"
docker exec -e PGPASSWORD="$barad_db_password" barad-dur-postgres-1 \
  psql -U barad -d barad_platform -At -c "select 'alembic', version_num from alembic_version;"

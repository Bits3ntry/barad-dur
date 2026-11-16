#!/usr/bin/env bash
# Deploy the asset/grants flow: console bundle + API image, then prove both landed.
set -euo pipefail
cd /Volumes/980PRO/Workspace/Councilbox/CYB/Barad-d-r

echo "── console bundle"
npm run build --prefix frontend
rsync -a --delete frontend/dist/ console_html/

echo "── api image"
docker build -q -t barad-dur-platform-api ./backend

echo "── recreate"
docker compose up -d --no-deps --no-build --force-recreate platform-api

for i in $(seq 1 40); do
  if curl -fsS http://127.0.0.1:8090/healthz >/dev/null 2>&1; then
    echo "api healthy after ${i}s"
    break
  fi
  sleep 1
done

curl -fsS http://127.0.0.1:8090/healthz; echo
set -a; . ./.env; set +a
docker exec -e PGPASSWORD="$barad_db_password" barad-dur-postgres-1 psql -U barad -d barad_platform \
  -c "select version_num from alembic_version;" \
  -c "select column_name, data_type from information_schema.columns where table_name='scan_grants' and column_name in ('level','requested_by','approved_by','rejection_reason','asset_id','source') order by column_name;"

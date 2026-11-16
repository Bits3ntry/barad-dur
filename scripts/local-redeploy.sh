#!/usr/bin/env bash
# Redeploy the two images a code change can touch, then prove both came back.
#
#   backend/  → barad-dur-platform-api (serves the console too)
#   ../shauron → shauron-worker:recon (the fat worker; entrypoint `shauron`)
#
# No migration runs here: `barad-platform serve` applies alembic on boot, so a
# schema change is only visible once the container is recreated and healthy.
set -Eeuo pipefail

cd "$(dirname "$0")/.."
ROOT=$(pwd)
set -a; source .env; set +a
readonly COMPOSE=(docker compose -f compose.yaml -f compose.local.yaml)
readonly API="http://127.0.0.1:${PLATFORM_API_PORT:-8090}"

echo "── building the API image"
docker build -q -t barad-dur-platform-api "$ROOT/backend" >/dev/null

echo "── building the worker image"
docker build -q -f "$ROOT/docker/Dockerfile.worker" -t shauron-worker:recon "$ROOT/../shauron" >/dev/null

echo "── recreating platform-api and shauron-worker"
"${COMPOSE[@]}" up -d --no-deps --no-build --force-recreate platform-api shauron-worker

echo "── waiting for /healthz"
for _ in $(seq 1 60); do
	curl -fsS "$API/healthz" >/dev/null 2>&1 && break
	sleep 2
done
curl -fsS "$API/healthz"; echo
"${COMPOSE[@]}" ps --format 'table {{.Service}}\t{{.Status}}' | head -6

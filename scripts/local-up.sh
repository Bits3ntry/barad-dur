#!/usr/bin/env bash
# Bring up the console-facing core: API (built from backend/) + nginx serving
# console_html/. Worker, scaler and field-runtime are separate on purpose: they
# need an API key that only exists after the first bootstrap, and their images
# (shauron-worker:recon from shauron-scan:redteam) are not built on this machine.
#
#   bash scripts/local-up.sh
set -Eeuo pipefail

cd "$(dirname "$0")/.."
set -a; source .env; set +a

readonly COMPOSE=(docker compose -f compose.yaml -f compose.local.yaml)
readonly API="http://127.0.0.1:${PLATFORM_API_PORT:-8090}"
readonly CONSOLE="http://127.0.0.1:${CONSOLE_PORT:-8092}"

log() { printf 'up: %s\n' "$*"; }

log 'building and starting platform-api + console'
"${COMPOSE[@]}" up -d --build platform-api console

log "waiting for ${API}/healthz"
for _ in $(seq 1 80); do
	if curl -fsS "$API/healthz" >/dev/null 2>&1; then break; fi
	sleep 3
done

if ! curl -fsS "$API/healthz"; then
	log 'API did not answer; last 40 log lines:'
	docker logs --tail 40 barad-dur-platform-api-1 || true
	exit 1
fi
printf '\n'

log "console: $(curl -s -o /dev/null -w '%{http_code}' "$CONSOLE/") on $CONSOLE"
log "api:     $(curl -s -o /dev/null -w '%{http_code}' "$API/api/v1/health") on $API"
"${COMPOSE[@]}" ps --format 'table {{.Service}}\t{{.Status}}\t{{.Ports}}'

#!/usr/bin/env bash
# Bring the fat worker service up in Compose and prove it registered.
#
# The image carries nmap, whatweb, httpx, naabu and the shauron source of
# ../shauron, and SHAURON_TOOL_RUNTIME=local makes the runner execute those
# binaries in-process — no docker socket inside the worker.
set -Eeuo pipefail

cd "$(dirname "$0")/.."
set -a; source .env; set +a

readonly COMPOSE=(docker compose -f compose.yaml -f compose.local.yaml)
readonly API="http://127.0.0.1:${PLATFORM_API_PORT:-8090}"

"${COMPOSE[@]}" up -d --no-deps --force-recreate shauron-worker
echo "── waiting for the worker to register"
for _ in $(seq 1 30); do
	rows=$(curl -fsS -H "X-API-Key: $SHAURON_BARAD_KEY" "$API/api/v1/orchestration/workers" || echo '{}')
	count=$(printf '%s' "$rows" | python3 -c "import json,sys;d=json.load(sys.stdin);print(len(d.get('data') or []))" 2>/dev/null || echo 0)
	[ "$count" -gt 0 ] && break
	sleep 2
done

printf '%s' "$rows" | python3 -c "
import json,sys
d=json.load(sys.stdin)
for w in d.get('data') or []:
    print(f\"  {w.get('name'):24} {w.get('status'):8} caps={','.join(w.get('capabilities') or [])}\")
print('  total:', len(d.get('data') or []))"
echo "── last log lines"
"${COMPOSE[@]}" logs --tail 12 shauron-worker 2>&1 | tail -12

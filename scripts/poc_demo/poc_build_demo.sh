#!/usr/bin/env bash
# Build the demo estate from scratch: reset → seed → scans → recon.
#
#   bash scripts/poc_demo/poc_build_demo.sh
#
# This is the "morning of the demo" command. It destroys the estate it created
# last time and rebuilds it in about four minutes, so a rehearsal that left the
# data half-broken costs one command, not an afternoon.
#
# The API must already be running and built from this tree (bash
# scripts/poc_demo/redeploy_api.sh if the backend changed).
set -Eeuo pipefail
cd "$(dirname "$0")/../.."
set -a; source .env; set +a

readonly PY="./.venv/bin/python"
readonly STATE="${POC_DIR:-${HOME}/HUB/Workspace/Councilbox/CYB/poc-juice-shop}/state.json"

step() { printf '\n\033[1m▸ %s\033[0m\n' "$*"; }

step "0/5 · API"
code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8090/healthz || true)
[[ "$code" == "200" ]] || { echo "platform-api is not answering (/healthz $code)"; exit 1; }
echo "healthz 200"

step "1/5 · reset (backup + wipe)"
bash scripts/poc_demo/reset.sh | tail -12

step "2/5 · seed (proyecto, componentes, despliegues, alcance, grant, ciclo externo)"
"$PY" scripts/poc_demo/seed_platform.py | tail -20

step "3/5 · código (SBOM + CVEs + runtime + misconfig + SAST)"
bash scripts/poc_demo/run_scans.sh

step "4/5 · superficie (recon profundo desde el worker)"
bash scripts/poc_demo/run_recon.sh | tail -25

step "5/5 · resumen"
docker exec -e PGPASSWORD="$barad_db_password" barad-dur-postgres-1 \
  psql -U barad -d barad_platform -c "
    select kind, severity, count(*) from findings group by 1,2 order by 1,2;" 

"$PY" - "$STATE" <<'PY'
import json, sys
state = json.load(open(sys.argv[1]))
print("project   ", state["project"])
print("asset     ", state["asset"], state.get("asset_id"))
print("cycle     ", state.get("external_cycle"))
print("grant     ", state.get("grant_id"))
PY

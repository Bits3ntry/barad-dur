#!/usr/bin/env bash
# Launch the deep recon the demo shows, and watch it run.
#
#   bash scripts/poc_demo/run_recon.sh            # web.redteam on juice-shop.demo
#   bash scripts/poc_demo/run_recon.sh recon.simple
#
# This is the same call the console makes from Assets → Scan (plane=cloud): the
# platform enqueues a run and the worker claims it. The script is here so the
# demo can be rehearsed without clicking, and so a failed run has a log.
set -Eeuo pipefail
cd "$(dirname "$0")/../.."
set -a; source .env; set +a

readonly PROFILE="${1:-web.redteam}"
readonly TARGET="${2:-juice-shop.demo}"
readonly API="${POC_API:-http://127.0.0.1:8090}"

run=$("$(command -v curl)" -s -X POST -H "X-API-Key: $SHAURON_BARAD_KEY" \
  -H 'Content-Type: application/json' \
  -d "{\"profile\":\"$PROFILE\",\"targets\":[{\"type\":\"domain\",\"value\":\"$TARGET\"}],\"plane\":\"cloud\",\"engagement\":\"POC\"}" \
  "$API/api/v1/surface/runs")
id=$(printf '%s' "$run" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d.get("run_id") or (d.get("data") or {}).get("id") or "")')
if [[ -z "$id" ]]; then
  printf 'launch refused: %s\n' "$run"; exit 1
fi
printf 'run %s · %s · %s\n' "$id" "$PROFILE" "$TARGET"
printf 'console: %s/#surface::%s\n\n' "${CONSOLE_URL:-http://127.0.0.1:8092}" "$id"

for _ in $(seq 1 120); do
  body=$(curl -s -H "X-API-Key: $SHAURON_BARAD_KEY" "$API/api/v1/surface/runs/$id")
  printf '%s' "$body" | python3 -c '
import json, sys
doc = json.load(sys.stdin)
doc = doc.get("data") or doc
run = doc.get("run") or {}
steps = doc.get("steps") or []
ok = sum(1 for s in steps if s.get("status") == "ok")
bad = sum(1 for s in steps if s.get("status") == "failed")
dropped = sum(1 for s in steps if s.get("status") == "dropped")
print("  " + str(run.get("status")) + " · " + str(len(steps)) + " steps · ok " + str(ok)
      + " · failed " + str(bad) + " · dropped " + str(dropped))
if run.get("status") in {"finished", "failed"}:
    for s in steps:
        print("    " + str(s.get("stage")) + "/" + str(s.get("tool")) + ": "
              + str(s.get("status")) + " " + str(s.get("coverage"))
              + " " + str(s.get("items_out")) + " out"
              + (" — " + str(s.get("error"))[:70] if s.get("error") else ""))
'
  status=$(printf '%s' "$body" | python3 -c 'import json,sys; d=json.load(sys.stdin); d=d.get("data") or d; r=d.get("run") or d; print(r.get("status"))')
  [[ "$status" == "finished" || "$status" == "failed" ]] && break
  sleep 5
done
printf '\nrun: %s/#surface::%s\n' "${CONSOLE_URL:-http://127.0.0.1:8092}" "$id"

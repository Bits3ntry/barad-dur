#!/bin/sh
# Demonstrate the acceptance scenarios locally from a clean scratch copy of
# examples/node. Every run uses the real runner and a real Trivy (the pinned
# container by default, a local binary when BARAD_TRIVY_RUNNER=local).
set -eu

repo_root=$(cd "$(dirname "$0")/../.." && pwd -P)
runner="$repo_root/bin/barad-security"
python="$repo_root/.venv/bin/python"
work=${WORKDIR:-$(mktemp -d)}
demo="$work/ovac-backend"

: "${BARAD_TRIVY_RUNNER:=docker}"
export BARAD_TRIVY_RUNNER

command -v git >/dev/null || { echo "git is required" >&2; exit 2; }
[ -x "$runner" ] || { echo "runner not found at $runner" >&2; exit 2; }
[ -x "$python" ] || python=python3

echo "== preparing $demo"
rm -rf "$demo"
mkdir -p "$demo"
(cd "$repo_root/examples/node" && tar cf - .) | (cd "$demo" && tar xf -)
rm -rf "$demo/.barad-dur"
(
  cd "$demo"
  git init -q
  git config user.email demo@barad.local
  git config user.name "BARAD demo"
  git add -A
  git commit -qm "initial 8.8.0"
)

go() {
  label=$1
  shift
  echo
  echo "== $label"
  ( cd "$demo" && "$runner" run --repository "$demo" --json "$@" > "$work/manifest.json" ) || {
    status=$?
    echo "run exited with $status"
    ( cd "$demo" && "$python" -c "import json,sys;print(json.dumps(json.load(open(sys.argv[1])),indent=2)[:1200])" "$work/manifest.json" 2>/dev/null || true )
    return $status
  }
  "$python" - "$work/manifest.json" "$demo" <<'PY'
import json, sys
from pathlib import Path

manifest = json.load(open(sys.argv[1]))
print(f"  event      : {manifest['event']}  version={manifest['application_version']}")
print(f"  changed    : {manifest['changes']['files_changed']}")
print(f"  trivy      : {manifest['steps'].get('trivy', {}).get('status')} "
      f"counts={manifest['security'].get('counts', {}).get('total')} vulns")
sbom = manifest['steps'].get('sbom')
print(f"  sbom       : {sbom['status'] if sbom else 'SKIPPED'}  reason={manifest['decisions']['sbom_reason']}")
state = (manifest.get('publications') or {}).get('_state', {})
print(f"  publication: attempted={state.get('published_any')} failed={state.get('failed')}")
print(f"  result     : {manifest['result']['status']} scan_ok={manifest['result']['scan_successful']}")
run_dir = Path(sys.argv[2]) / '.barad-dur' / 'security' / 'runs' / manifest['run_id']
files = sorted(path.name for path in run_dir.iterdir()) if run_dir.is_dir() else []
print(f"  evidence   : {run_dir.name} -> {', '.join(files)}")
PY
}

go "scenario 1a: first run builds the inventory" --event push --base-ref HEAD
printf 'export const health = () => ({ ok: true });\n' > "$demo/src/index.ts"
(cd "$demo" && git commit -qam "code only")
go "scenario 1b: code-only change keeps the inventory" --event push --base-ref HEAD^

"$python" - "$demo" <<'PY'
import json
from pathlib import Path
path = Path(__import__("sys").argv[1]) / "package-lock.json"
document = json.loads(path.read_text())
document["packages"]["node_modules/axios"]["version"] = "1.7.0"
path.write_text(json.dumps(document, indent=2) + "\n")
PY
(cd "$demo" && git commit -qam "bump axios 1.7.0")
go "scenario 2: dependency change regenerates the SBOM" --event pr --base-ref HEAD^

"$python" - "$demo" <<'PY'
import json
from pathlib import Path
path = Path(__import__("sys").argv[1]) / "package.json"
document = json.loads(path.read_text())
document["version"] = "8.9.0"
path.write_text(json.dumps(document, indent=2) + "\n")
PY
(cd "$demo" && git commit -qam "release 8.9.0")
go "scenario 2b: version bump is its own trigger" --event push --base-ref HEAD^

go "scenario 3: release produces the definitive inventory" --event release --version 8.9.0 --base-ref HEAD^

echo
echo "== scenario 4: BARAD-DUR unreachable keeps evidence and queues a sync"
( cd "$demo" && BARAD_DUR_ENABLED=true BARAD_DUR_URL=http://127.0.0.1:9 \
    BARAD_DUR_TOKEN=no-such-token "$runner" run --repository "$demo" \
    --event release --version 8.9.0 --base-ref HEAD^ --json > "$work/manifest-barad.json" ) || true
"$python" - "$work/manifest-barad.json" <<'PY'
import json, sys
manifest = json.load(open(sys.argv[1]))
step = manifest["steps"]["barad_dur"]
state = manifest.get("publications", {}).get("_state", {})
print(f"  barad_dur  : {step['status']} ({step.get('reason')}) deferred={step.get('detail', {}).get('deferred')}")
print(f"  result     : {manifest['result']['status']} scan_ok={manifest['result']['scan_successful']}")
print(f"  exit policy: analysis kept, publication pending")
PY
echo "  pending queue: $(ls -1 "$demo/.barad-dur/security/pending" 2>/dev/null | tr '\n' ' ')"

echo
echo "== evidence tree"
(cd "$demo" && find .barad-dur/security -type f | sort)
echo
echo "Done. Scratch repository: $demo"

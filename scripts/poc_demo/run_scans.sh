#!/usr/bin/env bash
# Run the code scans the demo replays, exactly as CI would.
#
#   bash scripts/poc_demo/run_scans.sh              # the two production builds
#   bash scripts/poc_demo/run_scans.sh --new        # also 1.2.0 (the "new build")
#   bash scripts/poc_demo/run_scans.sh --new-only   # only the new build
#
# Each repository gets two tickets: `supply-chain` (SBOM + CVEs + runtime +
# misconfig + secrets) and `code` (SAST + secrets). They are separate on purpose —
# the demo shows that a push changes what runs.
#
# The version label is read from the tree (package.json / setup), never invented:
# the CLI takes `--version` here only so the label matches the tag the pipeline
# would have created.
set -Eeuo pipefail

cd "$(dirname "$0")/../.."
readonly REPO_ROOT="$PWD"
set -a; source .env; set +a

readonly DEST="${POC_DIR:-${HOME}/HUB/Workspace/Councilbox/CYB/poc-juice-shop}"
readonly SHAURON="${SHAURON_DIR:-${HOME}/HUB/Workspace/Councilbox/CYB/shauron}"
readonly PY="$REPO_ROOT/.venv/bin/python"
readonly PLATFORM="http://127.0.0.1:8090"
readonly ACTOR="${POC_ACTOR:-bitsentry.tech@gmail.com}"
readonly LOGS="$DEST/logs"

# The trivy DB mirror that answered here; the default mirror.gcr.io timed out.
export TRIVY_DB_REPOSITORY="${TRIVY_DB_REPOSITORY:-ghcr.io/aquasecurity/trivy-db}"

mkdir -p "$LOGS"

mode="production"
case "${1:-}" in
  --new) mode="both" ;;
  --new-only) mode="new" ;;
esac

read -r web_v1 web_v2 api_sha <<<"$(
  "$PY" - "$DEST/repos.json" <<'PY'
import json, sys
state = json.load(open(sys.argv[1]))
print(state["web_v1"]["commit"], state["web_v2"]["commit"], state["api"]["commit"])
PY
)"

# A worktree per scanned tree: the working copy is at 1.2.0, and a scan of 1.0.0
# must read 1.0.0 or the commit label is a lie.
tree_for() {  # tree_for <repo> <sha> <name>
  local repo="$DEST/$1" sha="$2" name="$3"
  local tree="$DEST/.scan/$name"
  mkdir -p "$DEST/.scan"
  if [[ ! -d "$tree" ]]; then
    git -C "$repo" worktree add -q --detach "$tree" "$sha"
  fi
  printf '%s' "$tree"
}

scan() {  # scan <component> <tree> <commit> <version> <action> <label>
  local component="$1" tree="$2" commit="$3" version="$4" action="$5" label="$6"
  local log="$LOGS/${label}.log"
  printf '\n== %s · %s %s (%s)\n' "$component" "$action" "$version" "$commit"
  PYTHONPATH="$SHAURON" "$PY" -m shauron scan \
    --platform "$PLATFORM" --api-key "$SHAURON_BARAD_KEY" \
    --project juice-shop --component "$component" \
    --repository "https://gitea.juice-shop.demo/juice-shop/${component}.git" \
    --path "$tree" --commit "$commit" --branch main \
    --version "$version" --action "$action" --origin ci --actor "$ACTOR" \
    >"$log" 2>&1 || { printf 'FAILED — tail of %s\n' "$log"; tail -20 "$log"; return 1; }
  "$PY" - "$log" <<'PY'
import json, re, sys
text = open(sys.argv[1]).read()
# The outcome is the LAST json document the CLI prints; anything before it is
# progress. Anchoring on the first key is what makes this reliable.
match = re.search(r'\n\{\n  "cancelled"', text)
doc = None
if match:
    try:
        doc = json.loads(text[match.start() + 1:])
    except ValueError:
        doc = None
if doc is None:
    print("  (no json summary)")
    sys.exit()
counts = doc.get("counts") or {}
print("  ok=" + str(doc.get("ok")) + " · " + str(doc.get("duration_s")) + "s · findings "
      + str(counts.get("findings")) + " · drops " + str(len(doc.get("drops") or [])))
for result in doc.get("results") or []:
    state = "ok" if result.get("ok") else "FAILED"
    print("    " + str(result.get("task")) + ": " + state
          + " (" + str(result.get("coverage")) + ") "
          + str((result.get("engine") or {}).get("name") or ""))
PY
}

if [[ "$mode" != "new" ]]; then
  v1_tree=$(tree_for juice-shop-web "$web_v1" web-1.0.0)
  scan juice-shop-web "$v1_tree" "$web_v1" 1.0.0 supply-chain web-1.0.0-supply
  scan juice-shop-web "$v1_tree" "$web_v1" 1.0.0 code web-1.0.0-code

  api_tree=$(tree_for juice-shop-api "$api_sha" api-0.9.0)
  scan juice-shop-api "$api_tree" "$api_sha" 0.9.0 supply-chain api-0.9.0-supply
  scan juice-shop-api "$api_tree" "$api_sha" 0.9.0 code api-0.9.0-code
fi

if [[ "$mode" != "production" ]]; then
  v2_tree=$(tree_for juice-shop-web "$web_v2" web-1.2.0)
  scan juice-shop-web "$v2_tree" "$web_v2" 1.2.0 supply-chain web-1.2.0-supply
  scan juice-shop-web "$v2_tree" "$web_v2" 1.2.0 code web-1.2.0-code
fi

printf '\nlogs: %s\n' "$LOGS"

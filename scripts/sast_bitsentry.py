"""Run opengrep over the Bitsentry repositories and ingest each SARIF run.

Kept as a script (not a one-off shell loop) so the mapping project -> path is
explicit and rerunning it is idempotent: the API dedupes SARIF by recipe.
"""
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.request

ROOT = "/Users/saf/orca/workspaces/Barad-d-r/fork_openctem"
OPENGREP = os.path.expanduser("~/.local/bin/opengrep")
OUT = "/Users/saf/.hermes/cache/scratch/sast"
BASE = "http://127.0.0.1:8090"
REPOS = "/Users/saf/Workspace/Bitsentry"

PATHS = {
    "aurea-frontend": f"{REPOS}/Aurea/aurea-frontend",
    "aurea-backend": f"{REPOS}/Aurea/aurea-backend",
    "aurea-fx-service": f"{REPOS}/Aurea/aurea-fx-service",
    "aurea-document-service": f"{REPOS}/Aurea/aurea-document-service",
    "saria-backend": f"{REPOS}/saria/backend",
    "saria-ios": f"{REPOS}/saria/ios",
    "bitsentry-xyz": f"{REPOS}/bitsentry.xyz",
}
# A repository with 180 MB of media and 1 GB of node_modules makes opengrep burn
# CPU for twenty minutes with nothing to show. Scan the source roots instead.
SCAN_TARGETS = {
    "bitsentry-xyz": ["app", "components", "lib", "hooks"],
}
EXCLUDES = ["node_modules", ".venv", "venv", "dist", "build", "Pods", "DerivedData",
            ".git", "site-packages", "vendor", ".next", "coverage", "public", "content"]


def env_value(key):
    for line in open(os.path.join(ROOT, ".env")):
        line = line.strip()
        if line.startswith(f"{key}="):
            return line.split("=", 1)[1]
    raise SystemExit(f"{key} missing from .env")


API_KEY = env_value("BITSENTRY_API_KEY")


def api(method, path, payload=None, timeout=180):
    data = json.dumps(payload).encode() if payload is not None else None
    request = urllib.request.Request(BASE + path, data=data, method=method)
    request.add_header("X-API-Key", API_KEY)
    request.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, json.loads(response.read() or b"{}")
    except urllib.error.HTTPError as error:
        return error.code, error.read()[:400]


def scan(slug, path, version):
    target = f"{OUT}/{slug}.sarif"
    roots = [f"{path}/{name}" for name in SCAN_TARGETS.get(slug, [])]
    roots = [root for root in roots if os.path.isdir(root)] or [path]
    command = [OPENGREP, "scan", "--config", "auto", "--quiet",
               "--max-target-bytes", "1000000", "--timeout", "60",
               "--sarif", "--output", target] + roots
    for name in EXCLUDES:
        command += ["--exclude", name]
    started = time.time()
    result = subprocess.run(command, capture_output=True, text=True, timeout=1800)
    if result.returncode not in (0, 1) or not os.path.exists(target):
        return {"project": slug, "status": "scan_failed",
                "detail": (result.stderr or result.stdout)[-300:], "seconds": 0}
    run = json.load(open(target))["runs"][0]
    results = len(run.get("results") or [])
    status, body = api("POST", f"/api/v1/sarif?project={slug}&version={version}",
                       {"run": run, "actor": "opengrep"})
    counts = body.get("counts") if isinstance(body, dict) else None
    return {"project": slug, "results": results, "ingest": status,
            "counts": counts, "seconds": round(time.time() - started)}


def main():
    os.makedirs(OUT, exist_ok=True)
    status, portfolio = api("GET", "/api/v1/inventory/portfolio")
    if status != 200:
        raise SystemExit(f"portfolio unavailable: {status}")
    versions = {}
    for row in portfolio["data"]:
        versions.setdefault(row["project"], row["version"])  # newest first

    report = []
    for slug, path in PATHS.items():
        if slug not in versions:
            report.append({"project": slug, "status": "no_version"})
            continue
        if not os.path.isdir(path):
            report.append({"project": slug, "status": "missing_repo", "path": path})
            continue
        print(f"scanning {slug} …", flush=True)
        report.append(scan(slug, path, versions[slug]))
        print(json.dumps(report[-1]), flush=True)

    json.dump(report, open(f"{OUT}/report.json", "w"), indent=2)
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    sys.exit(main())

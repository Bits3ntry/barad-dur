#!/usr/bin/env python3
"""Read-only smoke over every feature area — the fast gate before a QA pass.

    python scripts/qa_smoke.py --url http://127.0.0.1:8099 --key bdr_...

It walks one representative endpoint per area and asserts three things: HTTP 200,
the response is JSON, and the promised top-level key exists. Nothing is written:
a smoke run is safe against any stack, including one a tester is poking at.

Exit code 0 = every check passed; 1 = at least one failed (the table says which).
"""
import argparse
import json
import sys
import urllib.error
import urllib.request

# (area, path, key that must exist in the body, needs)
# needs: None = always checkable · "dataset" = needs an imported project ·
#        "session" = needs a signed-in user, not an API key
CHECKS = [
    ("platform", "/healthz", "status"),
    ("auth", "/api/v1/auth/me", "data"),
    ("organization", "/api/v1/org", "data"),
    ("projects", "/api/v1/projects", "data"),
    ("dashboard", "/api/v1/dashboard/summary", "data"),
    ("dashboard v0", "/api/v1/dashboard/v0", "data"),
    ("dashboard portfolio", "/api/v1/dashboard/projects", "data"),
    ("dashboard exposure flow", "/api/v1/dashboard/exposure-flow", "data"),
    ("findings", "/api/v1/findings", "total"),
    ("vulnerabilities", "/api/v1/vulnerabilities", "data"),
    ("vulnerabilities meta", "/api/v1/vulnerabilities/meta/summary", "data"),
    ("assets", "/api/v1/assets", "total"),
    ("needs attention", "/api/v1/assets/needs-attention", "data"),
    ("inventory groups", "/api/v1/inventory/groups", "data"),
    ("inventory portfolio", "/api/v1/inventory/portfolio", "data"),
    ("inventory profile", "/api/v1/inventory/profile?project=aurea&version=v3", "data", "dataset"),
    ("activity", "/api/v1/activity", "data"),
    ("audit trail", "/api/v1/audit", "data"),
    ("scope targets", "/api/v1/scope/targets", "data"),
    ("scope exclusions", "/api/v1/scope/exclusions", "data"),
    ("scope resolved", "/api/v1/scope/resolved", "data"),
    ("components", "/api/v1/components", "data"),
    ("components impact", "/api/v1/components/impact?purl=pkg%3Apypi%2Fdjango%403.2.0", "data", "dataset"),
    ("artifacts", "/api/v1/artifacts", "data"),
    ("analysis runs", "/api/v1/analysis/runs", "data"),
    ("attack surface changes", "/api/v1/attack-surface/changes", "data"),
    ("attack surface web", "/api/v1/attack-surface/web-endpoints", "data"),
    ("attack surface lookalikes", "/api/v1/attack-surface/lookalikes", "data"),
    ("attack surface review", "/api/v1/attack-surface/review", "data"),
    ("attack surface summary", "/api/v1/attack-surface/summary", "data"),
    ("exposures", "/api/v1/exposures", "data"),
    ("cycles", "/api/v1/cycles", "data"),
    ("priority rules", "/api/v1/priority-rules", "data"),
    ("sla policies", "/api/v1/sla/policies", "data"),
    ("business impact", "/api/v1/business-impact", "data"),
    ("my work", "/api/v1/my-work?actor=qa%40bitsentry.xyz", "data"),
    ("remediation tasks", "/api/v1/remediation/tasks", "data"),
    ("code pull requests", "/api/v1/code/pull-requests", "data"),
    ("code baselines", "/api/v1/code/baselines", "data"),
    ("ci pipelines", "/api/v1/ci/pipelines", "data"),
    ("ci runs", "/api/v1/ci/runs", "data"),
    ("gates", "/api/v1/gate-policies", "data"),
    ("licenses", "/api/v1/license-inventory?project=aurea", "data", "dataset"),
    ("pentests", "/api/v1/pentest/engagements", "data"),
    ("regression", "/api/v1/regression/suites", "data"),
    ("jira links", "/api/v1/jira/links", "data"),
    ("notifications", "/api/v1/notifications/notifications", "data"),
    ("notification channels", "/api/v1/notifications/channels", "data"),
    ("deliveries", "/api/v1/notifications/deliveries", "data"),
    ("preferences", "/api/v1/notifications/preferences", "data"),
    ("members", "/api/v1/members", "data"),
    ("users", "/api/v1/auth/users", "data"),
    ("grants", "/api/v1/authorization/grants", "data"),
    ("capabilities", "/api/v1/authorization/capabilities", "data"),
    ("schedules", "/api/v1/schedules", "data"),
    ("orchestration jobs", "/api/v1/orchestration/jobs", "data"),
    ("scanners", "/api/v1/orchestration/scanners", "data"),
    ("workers", "/api/v1/orchestration/workers", "data"),
    ("suppressions", "/api/v1/suppressions", "data"),
    ("vex", "/api/v1/vex", "data"),
    ("repositories", "/api/v1/repositories", "data"),
    ("services", "/api/v1/services", "data"),
    ("deployments", "/api/v1/deployments", "data"),
    ("mfa status", "/api/v1/auth/mfa", "data", "session"),
    ("oidc status", "/api/v1/auth/oidc/status", "data"),
]


def get(base: str, path: str, key: str) -> tuple[int, dict | str]:
    request = urllib.request.Request(base + path, headers={"X-API-Key": key})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            body = response.read().decode() or "{}"
            try:
                return response.status, json.loads(body)
            except json.JSONDecodeError:
                return response.status, body[:120]
    except urllib.error.HTTPError as exc:
        return exc.code, (exc.read()[:200].decode(errors="replace") or "")
    except urllib.error.URLError as exc:
        return 0, f"unreachable: {exc.reason}"


def _has_dataset(base: str, key: str) -> bool:
    status, body = get(base, "/api/v1/projects", key)
    return status == 200 and isinstance(body, dict) and bool(body.get("data"))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8099")
    parser.add_argument("--key", required=True)
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    args = parser.parse_args()
    base = args.url.rstrip("/")

    dataset = _has_dataset(base, args.key)
    results, failures, skipped = [], 0, 0
    for entry in CHECKS:
        area, path, expected = entry[0], entry[1], entry[2]
        needs = entry[3] if len(entry) > 3 else None
        if needs == "dataset" and not dataset:
            skipped += 1
            results.append({"area": area, "path": path, "status": None, "ok": True,
                            "skipped": "needs an imported project"})
            continue
        if needs == "session":
            skipped += 1
            results.append({"area": area, "path": path, "status": None, "ok": True,
                            "skipped": "needs a signed-in user, not an API key"})
            continue
        status, body = get(base, path, args.key)
        ok = status == 200 and isinstance(body, dict) and expected in body
        failure = None
        if not ok:
            failures += 1
            if status != 200:
                failure = f"HTTP {status}"
            elif not isinstance(body, dict):
                failure = f"not JSON: {body}"
            else:
                failure = f"missing '{expected}' in {sorted(body)[:5]}"
        results.append({"area": area, "path": path, "status": status,
                        "ok": ok, "failure": failure})

    if args.json:
        print(json.dumps({"checks": len(results), "failed": failures,
                          "skipped": skipped, "results": results}, indent=2))
    else:
        width = max(len(r["area"]) for r in results)
        for row in results:
            mark = "fail" if not row["ok"] else ("skip" if row.get("skipped") else "ok  ")
            print(f"{mark} {row['area']:<{width}}  {row['path']}"
                  + (f"   ← {row['failure']}" if not row["ok"]
                     else (f"   ({row['skipped']})" if row.get("skipped") else "")))
        print(f"\n{len(results) - failures - skipped}/{len(results) - skipped} checks passed"
              f" · {skipped} skipped")
    return 0 if failures == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())

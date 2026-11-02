#!/usr/bin/env python3
"""Barad-dûr v0 acceptance demo — reproducible, isolated, no live stack.

Walks the whole §14 flow on a throwaway SQLite database:

    Bitsentry → AUREA → backend v3 / v4 → domain → deployment → SBOM →
    findings → SAST (base/head + diff) → inventory group → cycle → review → close

Usage:
    python scripts/demo_v0.py                 # run the walk and print it
    python scripts/demo_v0.py --serve         # run it, then serve API + built console
    python scripts/demo_v0.py --serve --port 8099

The demo never touches the compose deployment: it sets PLATFORM_DATABASE_URL to a
temporary SQLite file before importing the app. Fixtures are labelled `demo` and
the script prints every id it creates, so a browser session can be checked
against the same records.
"""
import argparse
import json
import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend" / "src"))

STATE = {}


def _banner(title: str) -> None:
    print(f"\n== {title} ==")


def _check(condition, message, details=None):
    if not condition:
        raise SystemExit(f"FAILED: {message}\n  {details if details is not None else ''}")
    print(f"  ok  {message}")


def build_stack(db_path: str):
    os.environ["PLATFORM_DATABASE_URL"] = f"sqlite:///{db_path}"
    from backend.app import models
    from backend.app.auth import create_key
    from backend.app.db import session_factory
    from backend.app.main import create_app

    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="bitsentry", name="Bitsentry (demo)")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "demo")
    session.commit()
    org_id = org.id
    session.close()
    return app, {"X-API-Key": key}, org_id, key


def walk(client, headers, org_id):
    """Run the acceptance flow through the API. Returns the ids it created."""
    from backend.app import models
    from backend.app.db import session_factory

    now = datetime.now(timezone.utc)

    _banner("1 · scope rule *.bitsentry.xyz (a rule, not a host)")
    rule = client.post("/api/v1/scope/targets", json={
        "target_type": "domain", "value": "*.bitsentry.xyz",
        "reason": "demo: company domains", "owner": "ana@bitsentry.xyz",
        "actor": "demo"}, headers=headers).json()["data"]
    _check(rule["is_pattern"] and rule["asset"] is None,
           "the pattern created no host")
    assets = client.get("/api/v1/assets", headers=headers).json()
    _check(assets["total"] == 0, "inventory is still empty after the rule",
           assets)
    decision = client.post("/api/v1/scope/check", json={
        "value": "api-aurea.bitsentry.xyz", "target_type": "domain",
        "capability": "passive_discovery"}, headers=headers).json()["data"]
    _check(decision["allowed"] is True, "the rule covers a concrete subdomain")
    apex = client.post("/api/v1/scope/check", json={
        "value": "bitsentry.xyz", "target_type": "domain",
        "capability": "passive_discovery"}, headers=headers).json()["data"]
    _check(apex["allowed"] is False, "the apex stays a separate authorization")

    _banner("2 · concrete asset, project AUREA, application components")
    asset = client.post("/api/v1/scope/targets", json={
        "target_type": "domain", "value": "api-aurea.bitsentry.xyz",
        "reason": "demo: product API", "owner": "ana@bitsentry.xyz",
        "actor": "demo"}, headers=headers).json()["data"]["asset"]
    _check(asset["source"] == "scope", "the asset was linked with provenance scope")
    session = session_factory()()
    project = models.Project(org_id=org_id, name="AUREA (demo)", slug="aurea")
    session.add(project)
    session.flush()
    backend_component = models.ApplicationComponent(
        org_id=org_id, project_id=project.id, kind="backend", name="backend",
        slug="backend")
    frontend_component = models.ApplicationComponent(
        org_id=org_id, project_id=project.id, kind="frontend", name="frontend",
        slug="frontend")
    session.add_all([backend_component, frontend_component])
    session.commit()
    project_id = project.id
    backend_id = backend_component.id
    session.close()
    print("  note: application components are seeded directly; they have no API yet")

    _banner("3 · backend v3: SBOM + artifact + deployment")
    def sbom(version, component_version="3.2.0", digest=None, artifact=None):
        document = {
            "bomFormat": "CycloneDX", "specVersion": "1.5",
            "metadata": {"component": {"name": "aurea", "version": version}},
            "components": [
                {"name": "django", "version": component_version,
                 "purl": f"pkg:pypi/django@{component_version}",
                 "licenses": [{"license": {"id": "BSD-3-Clause"}}]},
                {"name": "requests", "version": "2.31.0",
                 "purl": "pkg:pypi/requests@2.31.0"},
            ],
        }
        params = f"/api/v1/sbom?project=aurea&version={version}&source=ci"
        if digest:
            params += f"&artifact_digest={digest}&artifact_name={artifact}"
        response = client.post(params, content=json.dumps(document).encode(),
                               headers={**headers,
                                        "Content-Type": "application/octet-stream"})
        assert response.status_code in (200, 201), response.text
        return response.json()

    first = sbom("v3", digest="sha256:v3-demo", artifact="aurea-backend-v3")
    artifact_v3 = first["artifact"]
    _check(artifact_v3["digest"] == "sha256:v3-demo",
           "the SBOM named its artifact (digest linked)")
    deployment = client.post("/api/v1/deployments", json={
        "name": "aurea-backend", "environment": "production",
        "artifact_id": artifact_v3["id"], "application_component_id": backend_id,
        "status": "active", "deployed_at": "2026-11-01T09:00:00+00:00",
        "actor": "demo"}, headers=headers).json()["data"]
    client.post(f"/api/v1/assets/{asset['id']}/links", json={
        "entity_type": "deployment", "entity_id": deployment["id"],
        "relation": "serves", "added_by": "demo"}, headers=headers)
    artifact = client.get(f"/api/v1/artifacts/{artifact_v3['id']}",
                          headers=headers).json()["data"]
    _check(artifact["in_production"] is True,
           "production is read from the deployment, not a version flag")
    _check(artifact["sbom_present"] is True, "the artifact reports its SBOM")

    _banner("4 · findings: manual IDOR (no CVE) + an imported secret")
    finding = client.post("/api/v1/findings", json={
        "project": "aurea", "kind": "code-weakness",
        "title": "IDOR on invoice export", "severity": "HIGH",
        "path": "app/api/invoices.py", "line": 42, "cwe": "CWE-639",
        "impact": "one tenant reads another tenant's invoices",
        "recommendation": "authorize by tenant before serializing",
        "reproduction": "GET /invoices/123 with another tenant session",
        "assignee": "ana@bitsentry.xyz", "actor": "demo"}, headers=headers).json()["data"]
    detail = client.get(f"/api/v1/findings/{finding['id']}",
                        headers=headers).json()["data"]
    _check(detail["cve_id"] is None, "the IDOR has no invented CVE")
    ingested = client.post(
        "/api/v1/findings/ingest?project=aurea&version=v3&source=web", json={
            "schema": "barad-findings-v1", "tool": "trivy",
            "findings": [{"kind": "secret", "title": "AWS key in bundle",
                          "severity": "CRITICAL", "tool": "trivy",
                          "path": "public/app.js", "line": 3,
                          "detail": "redacted before upload"}]},
        headers=headers)
    _check(ingested.status_code == 200, "a normalized finding import landed",
           ingested.text)

    _banner("5 · SAST analysis: base, then head with code and diff")
    sarif = {
        "tool": {"driver": {"name": "OpenGrep", "version": "1.33.1",
                            "rules": [{"id": "py.sqli",
                                       "shortDescription": {"text": "SQL injection"},
                                       "properties": {"cwe": "CWE-89"}}]}},
        "results": [{"ruleId": "py.sqli", "level": "error",
                     "message": {"text": "query built from request"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": "app/api/reports.py"},
                         "region": {"startLine": 12}}}]}],
    }
    source = "\n".join(f"line {i}" for i in range(1, 41))
    diff_text = """--- a/app/api/reports.py
+++ b/app/api/reports.py
@@ -11,5 +11,6 @@ def export(request):
 context
-old
+cursor.execute(sql % name)
 context
 context
 context
"""
    base = client.post("/api/v1/analysis/import", json={
        "project": "aurea", "version": "v3", "format": "sarif",
        "report": sarif, "coverage": "full", "revision": "base123",
        "files": [{"path": "app/api/reports.py", "content": source}],
        "actor": "demo"}, headers=headers).json()["data"]
    head = client.post("/api/v1/analysis/import", json={
        "project": "aurea", "version": "v3", "format": "sarif",
        "report": sarif, "coverage": "full", "revision": "head456",
        "base_run_id": base["id"], "diff": diff_text,
        "files": [{"path": "app/api/reports.py", "content": source}],
        "actor": "demo"}, headers=headers).json()["data"]
    _check(head["counters"]["persistent"] == 1,
           "the same rule+path is persistent against a comparable base")
    _check(head["counters"]["on_modified_line"] == 1,
           "the finding sits on a changed line (not 'introduced' by itself)")
    opened = client.get(f"/api/v1/analysis/runs/{head['id']}/file",
                        params={"path": "app/api/reports.py"},
                        headers=headers).json()["data"]
    _check(opened["available"] and opened["findings"][0]["cwe"] == "CWE-89",
           "the viewer serves the code and the rule metadata")

    _banner("6 · group, then a cycle over it with a frozen reference")
    group = client.post("/api/v1/inventory/groups", json={
        "name": "Production", "description": "demo production estate",
        "tags": ["prod"], "actor": "demo"}, headers=headers).json()["data"]
    client.post(f"/api/v1/inventory/groups/{group['id']}/assets", json={
        "asset_ids": [asset["id"]], "actor": "demo"}, headers=headers)
    cycle = client.post("/api/v1/cycles", json={
        "name": "Q4 AUREA demo", "description": "demo cycle",
        "owner": "ana@bitsentry.xyz",
        "charter": {"objectives": ["validate AUREA"],
                    "success_criteria": ["IDOR fixed or accepted"]},
        "selection": {"groups": ["Production"], "projects": ["aurea"]},
        "actor": "demo"}, headers=headers).json()["data"]
    preview = client.post(f"/api/v1/cycles/{cycle['id']}/preview",
                          headers=headers).json()["data"]
    _check(preview["assets"] >= 1, "preview resolves the group's assets")
    activated = client.post(f"/api/v1/cycles/{cycle['id']}/activate?actor=demo",
                            headers=headers).json()
    _check(activated["data"]["state"] == "active", "activation froze the reference")
    linked = client.post(f"/api/v1/cycles/{cycle['id']}/link-findings", json={
        "auto": True, "actor": "demo"}, headers=headers).json()["data"]
    _check(linked["linked"] >= 2, "findings inside the frozen scope linked")

    _banner("7 · observations → changes → exposure decision")
    for ports in (["80", "443"], ["80", "443", "8080"]):
        observed = client.post("/api/v1/observations", json={
            "observations": [{
                "asset": {"id": asset["id"]}, "kind": "host", "coverage": "full",
                "source": "demo-import",
                "value": {"ports": ports, "addresses": ["203.0.113.10"],
                          "technology": ["nginx"]}}],
            "actor": "demo"}, headers=headers).json()["data"]
    _check(observed["counters"]["changes"] == 1, "the newly open port is a change")
    exposure = client.get("/api/v1/exposures?state=open",
                          headers=headers).json()["data"][0]
    accepted = client.post(f"/api/v1/exposures/{exposure['id']}/decide", json={
        "action": "accept", "reason": "demo: firewalled to the office",
        "valid_until": (now + timedelta(days=30)).isoformat(),
        "actor": "ana"}, headers=headers).json()["data"]
    _check(accepted["state"] == "accepted", "the condition is under management")

    _banner("8 · v4: a new artifact in staging does not fix production")
    second = sbom("v4", component_version="4.2.0", digest="sha256:v4-demo",
                  artifact="aurea-backend-v4")
    staging = client.post("/api/v1/deployments", json={
        "name": "aurea-backend-staging", "environment": "staging",
        "artifact_id": second["artifact"]["id"],
        "application_component_id": backend_id, "status": "active",
        "actor": "demo"}, headers=headers).json()["data"]
    v4 = client.get(f"/api/v1/artifacts/{second['artifact']['id']}",
                    headers=headers).json()["data"]
    v3 = client.get(f"/api/v1/artifacts/{artifact_v3['id']}",
                    headers=headers).json()["data"]
    _check(v4["in_production"] is False and v3["in_production"] is True,
           "v4 exists but production still runs v3")

    _banner("9 · review and close the cycle")
    reviewed = client.post(f"/api/v1/cycles/{cycle['id']}/review", json={
        "results": "IDOR triaged; one open port accepted for 30 days",
        "criteria": [{"name": "IDOR fixed or accepted", "verdict": "met"},
                     {"name": "no critical open", "verdict": "not_met"}],
        "learnings": "import the SBOM before the first scan",
        "actor": "ana"}, headers=headers)
    _check(reviewed.status_code == 200, "review recorded", reviewed.text)
    closed = client.post(f"/api/v1/cycles/{cycle['id']}/close?actor=ana",
                         headers=headers).json()["data"]
    _check(closed["state"] == "closed", "cycle closed")
    history = client.get(f"/api/v1/cycles/{cycle['id']}",
                         headers=headers).json()["data"]
    _check(len(history["review"]["criteria"]) == 2,
           "history kept after closing")

    _banner("10 · isolation: the same ids are invisible from another organization")
    session = session_factory()()
    from backend.app.auth import create_key
    other = models.Organization(slug="demo-other", name="Other (demo)")
    session.add(other)
    session.flush()
    other_key = create_key(session, other.id, "demo-other")
    session.commit()
    session.close()
    other_headers = {"X-API-Key": other_key}
    _check(client.get(f"/api/v1/cycles/{cycle['id']}",
                      headers=other_headers).status_code == 404,
           "another organization cannot read the cycle by id")
    _check(client.get("/api/v1/findings", headers=other_headers).json()["total"] == 0,
           "another organization sees no findings")

    STATE.update({
        "org_id": org_id, "project_id": project_id,
        "asset": asset["value"], "artifact_v3": artifact_v3["id"],
        "artifact_v4": second["artifact"]["id"], "cycle": cycle["id"],
        "deployment_prod": deployment["id"], "deployment_staging": staging["id"],
        "finding": finding["id"], "exposure": exposure["id"],
    })
    _banner("done")
    print(json.dumps(STATE, indent=2))


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--serve", action="store_true")
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--db", default=None)
    args = parser.parse_args()

    db_path = args.db or str(Path(tempfile.mkdtemp(prefix="barad-demo-")) / "demo.db")
    app, headers, org_id, key = build_stack(db_path)
    from fastapi.testclient import TestClient
    client = TestClient(app)
    walk(client, headers, org_id)

    if not args.serve:
        print(f"\ndatabase: {db_path}")
        print("run with --serve to browse the same records")
        return 0

    dist = ROOT / "frontend" / "dist"
    if not dist.is_dir():
        print("frontend/dist missing: run `npm run build --prefix frontend` first")
        return 2
    from fastapi.staticfiles import StaticFiles
    app.mount("/", StaticFiles(directory=str(dist), html=True), name="console")
    state_path = Path(tempfile.gettempdir()) / "barad_demo_state.json"
    state_path.write_text(json.dumps({"api_key": key, "url": f"http://127.0.0.1:{args.port}",
                                      "db": db_path, **STATE}, indent=2))
    print(f"\nconsole: http://127.0.0.1:{args.port}/")
    print(f"state:   {state_path}")
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=args.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

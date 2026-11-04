"""Declarative inventory: projects, components, code, deployments, probes.

The contract under test is the one the screen promises: a team records what it
has without any scan, the version can be typed by hand or read from a /health
endpoint, and cataloguing an asset grants nothing.
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402

BOOTSTRAP = "boot-secret"


class HealthHandler(BaseHTTPRequestHandler):
    payload = {"version": "1.7.4", "status": "ok"}
    tokens = []
    fail = False

    def do_GET(self):  # noqa: N802
        HealthHandler.tokens.append(self.headers.get("Authorization"))
        if HealthHandler.fail:
            self.send_response(503)
            self.end_headers()
            self.wfile.write(b'{"error":"unhealthy"}')
            return
        body = json.dumps(HealthHandler.payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        raise AssertionError("the version probe must never write")

    def log_message(self, *args):
        pass


@pytest.fixture()
def health_server():
    HealthHandler.payload = {"version": "1.7.4", "status": "ok"}
    HealthHandler.tokens = []
    HealthHandler.fail = False
    server = HTTPServer(("127.0.0.1", 0), HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}/health"
    server.shutdown()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/inv.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", BOOTSTRAP)
    for name in ("GITHUB_TOKEN", "GITLAB_TOKEN", "GITEA_TOKEN",
                 "JIRA_BASE_URL", "JIRA_EMAIL", "JIRA_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "inv")
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), {"X-API-Key": key}


def _project(client, headers, name="Aurea", **extra):
    payload = {"name": name, "actor": "console", **extra}
    return client.post("/api/v1/projects", json=payload, headers=headers)


def _component(client, headers, ref, name="Backend", kind="backend"):
    return client.post(f"/api/v1/projects/{ref}/components",
                       json={"name": name, "kind": kind, "actor": "console"},
                       headers=headers)


def _deployment(client, headers, ref, component_id, environment="PRO",
                version="1.7.4", **extra):
    return client.post(f"/api/v1/projects/{ref}/deployments", json={
        "component_id": component_id, "environment": environment,
        "version_label": version, "actor": "console", **extra}, headers=headers)


def test_project_component_code_and_deployment_flow(client):
    http, headers = client
    created = _project(http, headers, group="Bitsentry")
    assert created.status_code == 200, created.text
    slug = created.json()["data"]["slug"]
    assert slug == "aurea"

    duplicate = _project(http, headers)
    assert duplicate.status_code == 409

    component = _component(http, headers, slug)
    assert component.status_code == 200, component.text
    component_id = component.json()["data"]["id"]
    again = _component(http, headers, slug)
    assert again.status_code == 409

    repo = http.post(f"/api/v1/projects/{slug}/repositories", json={
        "remote_url": "https://gitea.bitsentry.xyz/bitsentry/aurea-api.git",
        "component_id": component_id, "actor": "console"}, headers=headers)
    assert repo.status_code == 200, repo.text
    repository = repo.json()["data"]
    # The link response is the project↔repository edge; the repository row is
    # what the inventory reads.
    assert repository["project_id"] or repository["repository_id"]

    deployment = _deployment(http, headers, slug, component_id,
                             exposure="public", requires_auth=True)
    assert deployment.status_code == 200, deployment.text
    body = deployment.json()["data"]
    assert body["environment"] == "PRO"
    assert body["version_label"] == "1.7.4"
    assert body["source"] == "manual"
    assert body["exposure"] == "public"
    assert body["requires_auth"] is True

    clash = _deployment(http, headers, slug, component_id)
    assert clash.status_code == 409

    dev = _deployment(http, headers, slug, component_id, environment="DEV",
                      version=None)
    assert dev.status_code == 200
    assert dev.json()["data"]["version_label"] is None

    inventory = http.get(f"/api/v1/projects/{slug}/inventory", headers=headers)
    assert inventory.status_code == 200, inventory.text
    data = inventory.json()["data"]
    assert data["project"]["name"] == "Aurea"
    assert data["project"]["group"] == "Bitsentry"
    assert [row["name"] for row in data["components"]] == ["Backend"]
    backend = data["components"][0]
    assert backend["versions"] == ["1.7.4"]
    assert len(backend["repositories"]) == 1
    assert backend["repositories"][0]["remote_url"].endswith("aurea-api.git")
    assert {row["environment"] for row in data["deployments"]} == {"DEV", "PRO"}
    assert data["project"]["counts"]["components"] == 1
    assert data["project"]["counts"]["deployments"] == 2
    assert data["project"]["counts"]["environments"] == ["DEV", "PRO"]

    renamed = http.patch(f"/api/v1/projects/{slug}", json={
        "name": "AUREA", "group": "Bitsentry", "actor": "console"}, headers=headers)
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["data"]["name"] == "AUREA"
    assert renamed.json()["data"]["slug"] == slug


def test_version_probe_reads_health_and_never_writes(client, health_server):
    http, headers = client
    slug = _project(http, headers).json()["data"]["slug"]
    component_id = _component(http, headers, slug).json()["data"]["id"]
    deployment_id = _deployment(http, headers, slug, component_id,
                                version=None).json()["data"]["id"]

    configured = http.put(f"/api/v1/deployments/{deployment_id}/health-probe",
                          json={"url": health_server, "token": "probe-secret",
                                "actor": "console"}, headers=headers)
    assert configured.status_code == 200, configured.text
    probe = configured.json()["data"]
    assert probe["token_set"] is True
    assert "probe-secret" not in configured.text

    checked = http.post(f"/api/v1/deployments/{deployment_id}/health/check",
                        headers=headers)
    assert checked.status_code == 200, checked.text
    body = checked.json()["data"]
    assert body["version"] == "1.7.4"
    assert body["status"] == "ok"
    assert body["error"] is None
    assert body["deployment"]["source"] == "health"
    assert body["deployment"]["last_check_status"] == "ok"
    # The probe authenticated with the stored token (sealed at rest).
    assert HealthHandler.tokens[-1] == "Bearer probe-secret"

    # A failing endpoint keeps the last known version and says why.
    HealthHandler.fail = True
    failed = http.post(f"/api/v1/deployments/{deployment_id}/health/check",
                       headers=headers)
    assert failed.status_code == 200
    outcome = failed.json()["data"]
    assert outcome["error"].startswith("http_503")
    assert outcome["deployment"]["last_check_status"] == "failed"
    assert outcome["deployment"]["version_label"] == "1.7.4"


def test_probe_tick_runs_only_what_is_due(client, health_server):
    """`interval_minutes` has to mean something: the tick runs a due probe once.

    The same rules as a manual check — no grant, a failed probe keeps the last
    version — plus the one the schedule adds: `0` is manual-only, and a second
    tick inside the same window must not run the probe again.
    """
    http, headers = client
    slug = _project(http, headers).json()["data"]["slug"]
    component_id = _component(http, headers, slug).json()["data"]["id"]
    deployment_id = _deployment(http, headers, slug, component_id,
                                version=None).json()["data"]["id"]

    configured = http.put(f"/api/v1/deployments/{deployment_id}/health-probe",
                          json={"url": health_server, "interval_minutes": 60,
                                "actor": "console"}, headers=headers)
    assert configured.status_code == 200, configured.text
    # No run yet: the probe is due immediately, not "in an hour".
    assert configured.json()["data"]["next_due_at"] is not None

    first = http.post("/api/v1/probes/tick", json={}, headers=headers)
    assert first.status_code == 200, first.text
    body = first.json()
    assert body["ran"] == 1
    assert body["data"][0]["result"] == "ok"
    assert body["data"][0]["version"] == "1.7.4"
    assert body["data"][0]["next_due_at"] is not None

    # Inside the window: nothing runs, and it is not reported as skipped work.
    second = http.post("/api/v1/probes/tick", json={}, headers=headers)
    assert second.status_code == 200
    assert second.json()["ran"] == 0

    # Rewind the clock instead of waiting an hour.
    session = session_factory()()
    probe = session.query(models.HealthProbe).one()
    probe.last_run_at = models.utcnow() - __import__("datetime").timedelta(minutes=61)
    session.commit()
    session.close()

    third = http.post("/api/v1/probes/tick", json={}, headers=headers)
    assert third.json()["ran"] == 1

    # Manual-only: interval 0 never enters the tick.
    http.put(f"/api/v1/deployments/{deployment_id}/health-probe",
             json={"url": health_server, "interval_minutes": 0}, headers=headers)
    session = session_factory()()
    probe = session.query(models.HealthProbe).one()
    probe.last_run_at = None
    session.commit()
    session.close()
    manual = http.post("/api/v1/probes/tick", json={}, headers=headers)
    assert manual.json()["ran"] == 0
    assert http.put(f"/api/v1/deployments/{deployment_id}/health-probe",
                    json={"url": health_server, "interval_minutes": 60},
                    headers=headers).json()["data"]["next_due_at"] is not None

    # A failing endpoint advances the clock too: no tight retry loop, and the
    # version it could not confirm stays untouched.
    HealthHandler.fail = True
    try:
        http.post("/api/v1/probes/tick", json={}, headers=headers)
        session = session_factory()()
        probe = session.query(models.HealthProbe).one()
        deployment = session.get(models.Deployment, deployment_id)
        assert probe.last_error.startswith("http_503")
        assert deployment.last_check_status == "failed"
        session.close()
    finally:
        HealthHandler.fail = False


def test_probe_and_version_are_validated(client):
    http, headers = client
    slug = _project(http, headers).json()["data"]["slug"]
    component_id = _component(http, headers, slug).json()["data"]["id"]
    deployment_id = _deployment(http, headers, slug, component_id).json()["data"]["id"]

    missing = http.post(f"/api/v1/deployments/{deployment_id}/health/check",
                        headers=headers)
    assert missing.status_code == 404
    bad_url = http.put(f"/api/v1/deployments/{deployment_id}/health-probe",
                       json={"url": "ftp://x"}, headers=headers)
    assert bad_url.status_code == 422
    bad_exposure = http.patch(f"/api/v1/deployments/{deployment_id}",
                              json={"exposure": "wide-open"}, headers=headers)
    assert bad_exposure.status_code == 422
    updated = http.patch(f"/api/v1/deployments/{deployment_id}",
                         json={"version_label": "1.8.0-rc1"}, headers=headers)
    assert updated.status_code == 200
    assert updated.json()["data"]["version_label"] == "1.8.0-rc1"
    assert updated.json()["data"]["source"] == "manual"


def test_project_profile_and_slug_override(client):
    http, headers = client
    created = _project(http, headers, name="Aurea Retail", slug="aurea-retail",
                       description="Customer app and its APIs.",
                       owner="ana@example.dev", group="Bitsentry")
    assert created.status_code == 200, created.text
    body = created.json()["data"]
    assert body["slug"] == "aurea-retail"
    assert body["description"] == "Customer app and its APIs."
    assert body["owner"] == "ana@example.dev"

    listed = http.get("/api/v1/projects", headers=headers).json()["data"]
    assert listed[0]["owner"] == "ana@example.dev"
    assert listed[0]["description"].startswith("Customer app")

    inventory = http.get("/api/v1/projects/aurea-retail/inventory", headers=headers)
    assert inventory.status_code == 200
    assert inventory.json()["data"]["project"]["owner"] == "ana@example.dev"

    # The identifier is validated and unique; the display name is free.
    assert _project(http, headers, name="Other", slug="Not A Slug").status_code == 422
    assert _project(http, headers, name="Other", slug="aurea-retail").status_code == 409

    edited = http.patch("/api/v1/projects/aurea-retail", json={
        "owner": "ops@example.dev", "description": "  ", "actor": "console"},
        headers=headers)
    assert edited.status_code == 200, edited.text
    assert edited.json()["data"]["owner"] == "ops@example.dev"
    assert edited.json()["data"]["description"] is None


def test_project_assets_are_declared_with_or_without_a_component(client):
    http, headers = client
    _project(http, headers, name="WordPress site", slug="wp-site")
    _project(http, headers, name="Aurea", slug="aurea")
    component = http.post("/api/v1/projects/aurea/components",
                          json={"name": "Backend", "kind": "backend",
                                "actor": "console"}, headers=headers)
    assert component.status_code == 200, component.text
    component_id = component.json()["data"]["id"]

    # A domain with no component: a WordPress site has no code in the inventory.
    bare = http.post("/api/v1/projects/wp-site/assets",
                     json={"type": "domain", "value": "Blog.Example.com ",
                           "actor": "console"}, headers=headers)
    assert bare.status_code == 200, bare.text
    assert bare.json()["data"]["value"] == "blog.example.com"
    assert bare.json()["data"]["component"] is None

    linked = http.post("/api/v1/projects/aurea/assets",
                       json={"type": "domain", "value": "api.example.com",
                             "component_id": component_id, "actor": "console"},
                       headers=headers)
    assert linked.status_code == 200, linked.text
    assert linked.json()["data"]["component"] == "Backend"

    inventory = http.get("/api/v1/projects/aurea/inventory", headers=headers).json()["data"]
    assert [(a["value"], a["component"]) for a in inventory["assets"]] == \
        [("api.example.com", "Backend")]

    # The same domain cannot be claimed twice by different projects.
    conflict = http.post("/api/v1/projects/wp-site/assets",
                         json={"type": "domain", "value": "api.example.com",
                               "actor": "console"}, headers=headers)
    assert conflict.status_code == 409

    assert http.post("/api/v1/projects/aurea/assets",
                     json={"type": "dns-record", "value": "x", "actor": "console"},
                     headers=headers).status_code == 422
    assert http.post("/api/v1/projects/aurea/assets",
                     json={"type": "domain", "value": "https://api.example.com",
                           "actor": "console"}, headers=headers).status_code == 422


def test_a_domain_can_belong_to_an_environment(client):
    http, headers = client
    _project(http, headers, name="Aurea", slug="aurea")
    component = http.post("/api/v1/projects/aurea/components",
                          json={"name": "Backend", "kind": "backend",
                                "actor": "console"}, headers=headers).json()["data"]
    other = http.post("/api/v1/projects/aurea/components",
                      json={"name": "Web", "kind": "web",
                            "actor": "console"}, headers=headers).json()["data"]
    pro = http.post("/api/v1/projects/aurea/deployments",
                    json={"component_id": component["id"], "environment": "PRO",
                          "version_label": "1.7.4", "actor": "console"},
                    headers=headers)
    assert pro.status_code == 200, pro.text
    pro_id = pro.json()["data"]["id"]

    asset = http.post("/api/v1/projects/aurea/assets",
                      json={"type": "domain", "value": "api.example.com",
                            "deployment_id": pro_id, "actor": "console"},
                      headers=headers)
    assert asset.status_code == 200, asset.text
    body = asset.json()["data"]
    assert body["deployment"]["environment"] == "PRO"
    # The environment already knows its component; the asset inherits it.
    assert body["component"] == "Backend"

    inventory = http.get("/api/v1/projects/aurea/inventory", headers=headers).json()["data"]
    deployment = next(row for row in inventory["deployments"] if row["id"] == pro_id)
    assert deployment["domains"] == ["api.example.com"]
    assert inventory["assets"][0]["deployment"]["environment"] == "PRO"

    # A domain cannot claim an environment of a different component.
    clash = http.post("/api/v1/projects/aurea/assets",
                      json={"type": "domain", "value": "web.example.com",
                            "component_id": other["id"], "deployment_id": pro_id,
                            "actor": "console"}, headers=headers)
    assert clash.status_code == 422


def test_environment_rename_respects_the_component(client):
    http, headers = client
    _project(http, headers, name="Aurea", slug="aurea")
    component = http.post("/api/v1/projects/aurea/components",
                          json={"name": "Backend", "kind": "backend",
                                "actor": "console"}, headers=headers).json()["data"]
    ids = {}
    for environment in ("DEV", "PRO"):
        response = http.post("/api/v1/projects/aurea/deployments",
                             json={"component_id": component["id"],
                                   "environment": environment, "actor": "console"},
                             headers=headers)
        ids[environment] = response.json()["data"]["id"]

    clash = http.patch(f"/api/v1/deployments/{ids['DEV']}",
                       json={"environment": "PRO", "actor": "console"}, headers=headers)
    assert clash.status_code == 409, clash.text

    renamed = http.patch(f"/api/v1/deployments/{ids['DEV']}",
                         json={"environment": "STAGING", "version_label": "1.7.2",
                               "exposure": "internal", "requires_auth": True,
                               "actor": "console"}, headers=headers)
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["data"]["environment"] == "STAGING"
    assert renamed.json()["data"]["exposure"] == "internal"
    assert renamed.json()["data"]["requires_auth"] is True


def test_declared_versions_become_project_versions(client):
    """The label a deployment declares is the row an SBOM attaches to."""
    http, headers = client
    _project(http, headers, name="Aurea", slug="aurea")
    component = http.post("/api/v1/projects/aurea/components",
                          json={"name": "Backend", "kind": "backend",
                                "actor": "console"}, headers=headers).json()["data"]
    deployment = http.post("/api/v1/projects/aurea/deployments",
                           json={"component_id": component["id"],
                                 "environment": "PRO", "version_label": "1.7.4",
                                 "actor": "console"}, headers=headers).json()["data"]
    assert deployment["sbom"]["project_version_id"], "declaring a version must create it"
    assert deployment["sbom"]["sbom_imports"] == 0

    inventory = http.get("/api/v1/projects/aurea/inventory", headers=headers).json()["data"]
    assert "1.7.4" in inventory["project"]["versions"]
    assert inventory["deployments"][0]["sbom"]["version"] == "1.7.4"

    http.patch(f"/api/v1/deployments/{deployment['id']}",
               json={"version_label": "1.7.5", "actor": "console"}, headers=headers)
    versions = http.get("/api/v1/projects/aurea/inventory",
                        headers=headers).json()["data"]["project"]["versions"]
    assert {"1.7.4", "1.7.5"} <= set(versions)

    # Two environments can declare different versions of the same component.
    http.post("/api/v1/projects/aurea/deployments",
              json={"component_id": component["id"], "environment": "PRE",
                    "version_label": "1.8.0-rc1", "actor": "console"}, headers=headers)
    rows = http.get("/api/v1/projects/aurea/inventory", headers=headers).json()["data"]
    declared = {(row["environment"], row["version_label"]) for row in rows["deployments"]}
    assert declared == {("PRO", "1.7.5"), ("PRE", "1.8.0-rc1")}


def test_a_version_can_exist_before_any_deployment(client):
    """Naming a build is not deploying it, and the version belongs to a component."""
    http, headers = client
    _project(http, headers, name="Aurea", slug="aurea")
    component = http.post("/api/v1/projects/aurea/components",
                          json={"name": "Backend", "kind": "backend",
                                "actor": "console"}, headers=headers).json()["data"]
    created = http.post("/api/v1/projects/aurea/versions",
                        json={"version": "1.8", "component_id": component["id"],
                              "actor": "console"}, headers=headers)
    assert created.status_code == 200, created.text
    assert created.json()["data"]["component"] == "Backend"
    assert created.json()["data"]["deployments"] == []

    duplicate = http.post("/api/v1/projects/aurea/versions",
                          json={"version": "1.8", "component_id": component["id"],
                                "actor": "console"}, headers=headers)
    assert duplicate.status_code == 409

    inventory = http.get("/api/v1/projects/aurea/inventory", headers=headers).json()["data"]
    version = next(row for row in inventory["versions"] if row["version"] == "1.8")
    assert version["component"] == "Backend"
    assert version["deployments"] == []

    deployed = http.post("/api/v1/projects/aurea/deployments",
                         json={"component_id": component["id"], "environment": "PRO",
                               "version_id": version["id"], "actor": "console"},
                         headers=headers)
    assert deployed.status_code == 200, deployed.text
    assert deployed.json()["data"]["version_id"] == version["id"]
    assert deployed.json()["data"]["sbom"]["version"] == "1.8"

    inventory = http.get("/api/v1/projects/aurea/inventory", headers=headers).json()["data"]
    version = next(row for row in inventory["versions"] if row["version"] == "1.8")
    assert version["deployments"][0]["environment"] == "PRO"
    assert inventory["deployments"][0]["version_id"] == version["id"]


def test_two_components_can_share_a_version_label(client):
    """The backend's 1.8 and the web's 1.8 are different versions."""
    http, headers = client
    _project(http, headers, name="Aurea", slug="aurea")
    backend = http.post("/api/v1/projects/aurea/components",
                        json={"name": "Backend", "kind": "backend",
                              "actor": "console"}, headers=headers).json()["data"]
    web = http.post("/api/v1/projects/aurea/components",
                    json={"name": "Web", "kind": "web", "actor": "console"},
                    headers=headers).json()["data"]
    for component in (backend, web):
        created = http.post("/api/v1/projects/aurea/versions",
                            json={"version": "1.8", "component_id": component["id"],
                                  "actor": "console"}, headers=headers)
        assert created.status_code == 200, created.text

    inventory = http.get("/api/v1/projects/aurea/inventory", headers=headers).json()["data"]
    scopes = {(row["version"], row["component"]) for row in inventory["versions"]}
    assert ("1.8", "Backend") in scopes and ("1.8", "Web") in scopes

    # A product-wide release of the same label coexists with both.
    product = http.post("/api/v1/projects/aurea/versions",
                        json={"version": "1.8", "actor": "console"}, headers=headers)
    assert product.status_code == 200, product.text
    assert product.json()["data"]["component"] is None


def test_renaming_a_version_keeps_its_deployments(client):
    http, headers = client
    _project(http, headers, name="Aurea", slug="aurea")
    component = http.post("/api/v1/projects/aurea/components",
                          json={"name": "Backend", "kind": "backend",
                                "actor": "console"}, headers=headers).json()["data"]
    version = http.post("/api/v1/projects/aurea/versions",
                        json={"version": "1.8", "component_id": component["id"],
                              "actor": "console"}, headers=headers).json()["data"]
    deployment = http.post("/api/v1/projects/aurea/deployments",
                           json={"component_id": component["id"], "environment": "PRO",
                                 "version_id": version["id"], "actor": "console"},
                           headers=headers).json()["data"]

    renamed = http.patch(
        f"/api/v1/projects/aurea/versions/1.8?component_id={component['id']}",
        json={"version": "1.8.1"}, headers=headers)
    assert renamed.status_code == 200, renamed.text
    inventory = http.get("/api/v1/projects/aurea/inventory", headers=headers).json()["data"]
    row = next(item for item in inventory["deployments"]
               if item["id"] == deployment["id"])
    assert row["version_label"] == "1.8.1"
    assert row["version_id"] == version["id"]


def test_sbom_belongs_to_the_component_version(client):
    """The same label in two components is two documents, not one."""
    http, headers = client
    _project(http, headers, name="Aurea", slug="aurea")
    for name, kind in (("aurea-backend", "backend"), ("aurea-web", "web")):
        http.post("/api/v1/projects/aurea/components",
                  json={"name": name, "kind": kind, "actor": "console"}, headers=headers)

    payload = {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
        "metadata": {"component": {"type": "application", "name": "aurea",
                                   "version": "1.7.4"}},
        "components": [{"type": "library", "name": "fastapi", "version": "0.115.0",
                        "purl": "pkg:pypi/fastapi@0.115.0"}],
    }
    uploaded = http.post(
        "/api/v1/sbom?project=aurea&version=1.7.4&component=aurea-backend&source=api",
        content=json.dumps(payload).encode(),
        headers={**headers, "Content-Type": "application/octet-stream"})
    assert uploaded.status_code in (200, 201), uploaded.text

    inventory = http.get("/api/v1/projects/aurea/inventory", headers=headers).json()["data"]
    imports = {row["component"]: row["sbom_imports"] for row in inventory["versions"]}
    assert imports == {"aurea-backend": 1}
    # The web's 1.7.4 does not exist until someone declares it: no twin row.
    assert [row for row in inventory["versions"] if row["component"] == "aurea-web"] == []

    missing = http.post(
        "/api/v1/sbom?project=aurea&version=1.7.4&component=nope&source=api",
        content=json.dumps(payload).encode(),
        headers={**headers, "Content-Type": "application/octet-stream"})
    assert missing.status_code == 422, missing.text


def test_unknown_project_answers_404(client):
    http, headers = client
    assert http.get("/api/v1/projects/nope/inventory", headers=headers).status_code == 404
    assert http.post("/api/v1/projects/nope/components",
                     json={"name": "Backend"}, headers=headers).status_code == 404


def test_cataloguing_an_asset_files_it_without_granting_scope(client):
    http, headers = client
    slug = _project(http, headers).json()["data"]["slug"]
    asset = http.post("/api/v1/assets", json={
        "type": "domain", "value": "api.aurea.example",
        "source": "discovery", "actor": "console"}, headers=headers)
    assert asset.status_code == 200, asset.text
    asset_id = asset.json()["data"]["id"]

    pending = http.get("/api/v1/inventory/unassigned", headers=headers)
    assert pending.status_code == 200
    assert [row["value"] for row in pending.json()["data"]] == ["api.aurea.example"]
    assert pending.json()["projects"][0]["slug"] == slug

    catalogued = http.post(f"/api/v1/assets/{asset_id}/catalog",
                           json={"project": slug, "actor": "console"},
                           headers=headers)
    assert catalogued.status_code == 200, catalogued.text
    assert catalogued.json()["data"]["classification_status"] == "owned"

    after = http.get("/api/v1/inventory/unassigned", headers=headers).json()["data"]
    assert after == []
    inventory = http.get(f"/api/v1/projects/{slug}/inventory",
                         headers=headers).json()["data"]
    assert [row["value"] for row in inventory["assets"]] == ["api.aurea.example"]
    # Cataloguing is ownership, not authorization: no grant was created.
    session = session_factory()()
    assert session.query(models.ScanGrant).count() == 0
    session.close()


def test_saved_credentials_beat_the_environment(client, monkeypatch):
    from backend.app import integrations, jira_client, secrets as secret_store

    http, headers = client
    session = session_factory()()
    org = session.query(models.Organization).one()

    monkeypatch.setenv("JIRA_BASE_URL", "https://env.atlassian.net")
    monkeypatch.setenv("JIRA_EMAIL", "env@example.dev")
    monkeypatch.setenv("JIRA_TOKEN", "env-token")
    assert jira_client.config_for(session, org.id) == (
        "https://env.atlassian.net", "env@example.dev", "env-token")

    session.add(models.IntegrationConnection(
        org_id=org.id, kind="tickets", provider="jira",
        base_url="https://bitsentry.atlassian.net", account="ana@example.dev",
        secret_cipher=secret_store.seal(session, "saved-token"),
        config=json.dumps({"project_key": "SEC"}), access="read",
        created_at=models.utcnow()))
    session.commit()
    assert jira_client.config_for(session, org.id) == (
        "https://bitsentry.atlassian.net", "ana@example.dev", "saved-token")
    assert integrations.for_tickets(session, org.id)["config"]["project_key"] == "SEC"
    session.close()


def test_scm_credentials_are_used_for_gitea_status(client, monkeypatch):
    from backend.app import scm_client

    http, headers = client
    seen = {}

    class FakeResponse:
        status = 201

        def read(self):
            return b'{"id": 7}'

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

    def fake_urlopen(request, timeout=None):
        seen["url"] = request.full_url
        seen["method"] = request.get_method()
        seen["auth"] = request.get_header("Authorization")
        seen["body"] = request.data
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    creds = {"provider": "gitea", "base_url": "https://gitea.example",
             "token": "gitea-token"}
    result = scm_client.post_gitea_commit_status(
        "bitsentry/aurea-api", "abc123", "success", "gate pass", creds=creds)
    assert result == {"id": 7}
    assert seen["url"] == "https://gitea.example/api/v1/repos/bitsentry/aurea-api/statuses/abc123"
    assert seen["method"] == "POST"
    assert seen["auth"] == "token gitea-token"
    assert json.loads(seen["body"])["state"] == "success"


def _grant(http, headers, principal, targets, capabilities=("passive_discovery",),
           issued_by=None, hours=4):
    return http.post("/api/v1/authorization/grants", json={
        "principal": principal,
        "capabilities": list(capabilities),
        "targets": [{"type": "domain", "value": value} for value in targets],
        "issued_by": issued_by or f"{principal}-issuer",
        "justification": "verification flow test",
        "hours": hours,
    }, headers=headers)


def _verification(http, headers, ref="aurea", principal="console"):
    body = http.get(f"/api/v1/projects/{ref}/verification"
                    f"?principal={principal}", headers=headers)
    assert body.status_code == 200, body.text
    return body.json()["data"]


def test_verification_keeps_permission_and_observation_apart(client):
    """Permission is a grant; observation is a snapshot. Neither implies the
    other, and neither requires the host to be inside the declared scope."""
    http, headers = client
    _project(http, headers)
    component = _component(http, headers, "aurea").json()["data"]
    _deployment(http, headers, "aurea", component["id"])
    created = http.post("/api/v1/projects/aurea/assets",
                        json={"type": "domain", "value": "api.aurea.example",
                              "actor": "console"}, headers=headers)
    assert created.status_code == 200, created.text

    body = _verification(http, headers)
    row = body["assets"][0]
    assert row["permissions"]["passive_discovery"]["allowed"] is False
    assert row["permissions"]["passive_discovery"]["excluded"] is False
    assert row["observation"] is None
    assert body["summary"]["assets"] == 1
    assert body["summary"]["authorized"] == 0
    assert body["summary"]["never_observed"] == 1
    assert body["summary"]["deployments"] == 1
    assert "scope" not in row, "scope is a different ledger and has its own screen"

    # A grant issued to another principal is invisible to this reader.
    assert _grant(http, headers, "someone-else",
                  ["api.aurea.example"]).status_code == 200
    assert _verification(http, headers)["assets"][0]["permissions"][
        "passive_discovery"]["allowed"] is False

    # The grant for the collector's principal is what flips the decision — and it
    # does so without any scope target existing for this host: permission to run
    # a test is not membership of the automated sweep.
    assert _grant(http, headers, "console",
                  ["api.aurea.example"]).status_code == 200
    row = _verification(http, headers)["assets"][0]
    assert row["permissions"]["passive_discovery"]["allowed"] is True
    assert row["permissions"]["passive_discovery"]["grant"]["id"]
    assert row["permissions"]["active_verification"]["allowed"] is False
    assert row["observation"] is None, "a grant is not an observation"
    session = session_factory()()
    try:
        assert session.query(models.ScopeTarget).count() == 0
    finally:
        session.close()

    # An observation is the newest snapshot, with its timestamp.
    session = session_factory()()
    try:
        asset = session.query(models.Asset).filter_by(
            value="api.aurea.example").one()
        session.add(models.AssetSnapshot(
            org_id=asset.org_id, asset_id=asset.id, source="dns-collector",
            data=json.dumps({"dns": {"ipv4": ["203.0.113.10"], "ipv6": []}})))
        session.commit()
    finally:
        session.close()
    row = _verification(http, headers)["assets"][0]
    assert row["observation"]["ipv4"] == 1
    assert row["observation"]["age_days"] == 0
    assert row["observation"]["observed_at"]
    assert _verification(http, headers)["summary"]["observed"] == 1


def test_an_exclusion_wins_over_a_grant(client):
    """The one scope-side rule that changes a permission is an exclusion."""
    http, headers = client
    _project(http, headers)
    for value in ("web.aurea.example", "secret.aurea.example"):
        http.post("/api/v1/projects/aurea/assets",
                  json={"type": "domain", "value": value, "actor": "console"},
                  headers=headers)
    assert _grant(http, headers, "console",
                  ["web.aurea.example", "secret.aurea.example"]).status_code == 200
    excluded = http.post("/api/v1/scope/exclusions", json={
        "target_type": "domain", "value": "secret.aurea.example",
        "reason": "not ours", "actor": "console"}, headers=headers)
    assert excluded.status_code == 200, excluded.text

    rows = {row["value"]: row for row in _verification(http, headers)["assets"]}
    assert rows["web.aurea.example"]["permissions"]["passive_discovery"]["allowed"] is True
    denied = rows["secret.aurea.example"]["permissions"]["passive_discovery"]
    assert denied["allowed"] is False
    assert "exclusion" in denied["reason"]
    assert denied["excluded"] is True
    assert _verification(http, headers)["summary"]["excluded"] == 1


def test_verification_uses_the_asset_environment_for_narrowed_grants(client):
    """A grant narrowed to an environment only applies to assets served from it."""
    http, headers = client
    _project(http, headers)
    component = _component(http, headers, "aurea").json()["data"]
    deployment = _deployment(http, headers, "aurea", component["id"],
                             environment="production").json()["data"]
    linked = http.post("/api/v1/projects/aurea/assets", json={
        "type": "domain", "value": "api.aurea.example",
        "deployment_id": deployment["id"], "actor": "console"}, headers=headers)
    assert linked.status_code == 200, linked.text
    loose = http.post("/api/v1/projects/aurea/assets", json={
        "type": "domain", "value": "docs.aurea.example",
        "actor": "console"}, headers=headers)
    assert loose.status_code == 200, loose.text

    targets = [{"type": "domain", "value": "api.aurea.example"},
               {"type": "domain", "value": "docs.aurea.example"}]
    staging = http.post("/api/v1/authorization/grants", json={
        "principal": "console", "capabilities": ["passive_discovery"],
        "targets": targets, "issued_by": "console-operator",
        "justification": "environment narrowing", "hours": 4,
        "environment": "staging"}, headers=headers)
    assert staging.status_code == 200, staging.text

    rows = {row["value"]: row for row in _verification(http, headers)["assets"]}
    denied = rows["api.aurea.example"]["permissions"]["passive_discovery"]
    assert denied["allowed"] is False
    assert rows["api.aurea.example"]["environment"] == "production"
    # The unlinked asset declares no environment, so the narrowed grant cannot
    # match it — and the reason says that instead of a silent "no grant".
    unlinked = rows["docs.aurea.example"]["permissions"]["passive_discovery"]
    assert unlinked["allowed"] is False
    assert "environment" in unlinked["reason"]

    production = http.post("/api/v1/authorization/grants", json={
        "principal": "console", "capabilities": ["passive_discovery"],
        "targets": targets, "issued_by": "console-operator",
        "justification": "production, this window", "hours": 4,
        "environment": "production"}, headers=headers)
    assert production.status_code == 200, production.text

    rows = {row["value"]: row for row in _verification(http, headers)["assets"]}
    allowed = rows["api.aurea.example"]["permissions"]["passive_discovery"]
    assert allowed["allowed"] is True
    assert allowed["grant"]["environment"] == "production"
    assert allowed["grant"]["valid_until"]
    # The asset that belongs to no environment cannot satisfy the narrowing.
    assert rows["docs.aurea.example"]["permissions"]["passive_discovery"]["allowed"] is False


def test_a_declared_asset_can_be_corrected(client):
    """A typo in a declared value must be fixable without deleting the asset and
    losing its links, snapshots and history."""
    http, headers = client
    _project(http, headers)
    created = http.post("/api/v1/projects/aurea/assets", json={
        "type": "domain", "value": "api.aurea.exmaple", "actor": "console"},
        headers=headers).json()["data"]

    fixed = http.patch(f"/api/v1/assets/{created['id']}",
                       json={"value": "api.aurea.example", "actor": "console"},
                       headers=headers)
    assert fixed.status_code == 200, fixed.text
    assert fixed.json()["data"]["value"] == "api.aurea.example"

    # A domain is a hostname, not a URL.
    bad = http.patch(f"/api/v1/assets/{created['id']}",
                     json={"value": "https://api.aurea.example"},
                     headers=headers)
    assert bad.status_code == 422

    # Two assets cannot share type+value.
    http.post("/api/v1/projects/aurea/assets", json={
        "type": "domain", "value": "web.aurea.example", "actor": "console"},
        headers=headers)
    clash = http.patch(f"/api/v1/assets/{created['id']}",
                       json={"value": "web.aurea.example"}, headers=headers)
    assert clash.status_code == 409

    values = [row["value"] for row in _verification(http, headers)["assets"]]
    assert values == ["api.aurea.example", "web.aurea.example"]


def test_an_exclusion_can_be_undone_and_still_leaves_a_record(client):
    """Undoing an exclusion disables the control, it does not erase the decision."""
    http, headers = client
    _project(http, headers)
    http.post("/api/v1/projects/aurea/assets", json={
        "type": "domain", "value": "api.aurea.example", "actor": "console"},
        headers=headers)
    assert _grant(http, headers, "console", ["api.aurea.example"]).status_code == 200

    added = http.post("/api/v1/scope/exclusions", json={
        "target_type": "domain", "value": "api.aurea.example",
        "reason": "production payment endpoint", "actor": "console"}, headers=headers)
    assert added.status_code == 200, added.text
    exclusion_id = added.json()["data"]["id"]
    row = _verification(http, headers)["assets"][0]
    assert row["permissions"]["passive_discovery"]["excluded"] is True
    assert row["permissions"]["passive_discovery"]["exclusion"]["id"] == exclusion_id

    off = http.patch(f"/api/v1/scope/exclusions/{exclusion_id}",
                     json={"status": "disabled", "actor": "console"}, headers=headers)
    assert off.status_code == 200, off.text
    row = _verification(http, headers)["assets"][0]
    assert row["permissions"]["passive_discovery"]["excluded"] is False
    assert row["permissions"]["passive_discovery"]["allowed"] is True
    assert _verification(http, headers)["summary"]["excluded"] == 0

    # The row survives, and declaring it again re-arms it.
    session = session_factory()()
    try:
        assert session.query(models.ScopeExclusion).count() == 1
    finally:
        session.close()
    again = http.post("/api/v1/scope/exclusions", json={
        "target_type": "domain", "value": "api.aurea.example",
        "reason": "production payment endpoint", "actor": "console"}, headers=headers)
    assert again.status_code == 200, again.text
    assert again.json()["restored"] is True
    assert _verification(http, headers)["assets"][0]["permissions"][
        "passive_discovery"]["excluded"] is True


def test_verification_is_scoped_to_the_project(client):
    """A foreign project reference is a 404, never another project's inventory."""
    http, headers = client
    _project(http, headers, name="Aurea")
    _project(http, headers, name="Other")
    missing = http.get("/api/v1/projects/nope/verification", headers=headers)
    assert missing.status_code == 404

    other = http.get("/api/v1/projects/other/verification", headers=headers)
    assert other.status_code == 200
    assert other.json()["data"]["assets"] == []

"""BL-010 acceptance: typed N:M relationships without duplication.

Covers: shared repository across projects, shared asset across projects
(links, never copies), orphan assets without any project/repository,
temporal unlink (removed_at, history kept), finding context links, and the
invariant that the same SBOM on two projects still dedupes components.
"""
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/bl10.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "bl10")
    project_a = models.Project(org_id=org.id, slug="alpha", name="alpha")
    project_b = models.Project(org_id=org.id, slug="beta", name="beta")
    session.add_all([project_a, project_b])
    session.flush()
    session.add_all([
        models.ProjectVersion(project_id=project_a.id, version="1.0"),
        models.ProjectVersion(project_id=project_b.id, version="1.0"),
    ])
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), key


def _client_objs(client):
    test_client, key = client
    return test_client, {"X-API-Key": key}


def test_repository_nm_shared_across_projects(client):
    test_client, headers = _client_objs(client)
    projects = test_client.get("/api/v1/projects", headers=headers).json()["data"]
    alpha, beta = projects[0], projects[1]
    first = test_client.post(f"/api/v1/projects/{alpha['id']}/repositories", json={
        "remote_url": "git@github.com:councilbox/saria.git", "actor": "gate"},
        headers=headers).json()
    assert first.get("already_linked") is not True
    repo_id = first["data"]["repository_id"]
    # Same repository linked to alpha again → idempotent, no duplicate link.
    again = test_client.post(f"/api/v1/projects/{alpha['id']}/repositories", json={
        "remote_url": "git@github.com:councilbox/saria.git", "actor": "gate"},
        headers=headers).json()
    assert again["already_linked"] is True
    # Same repository linked to beta → new relation row, SAME one repository.
    second = test_client.post(f"/api/v1/projects/{beta['id']}/repositories", json={
        "repository_id": repo_id, "relation": "scans", "actor": "gate"},
        headers=headers).json()
    assert second["data"]["repository_id"] == repo_id
    repositories = test_client.get("/api/v1/repositories", headers=headers).json()
    assert repositories["total"] == 1
    assert repositories["data"][0]["remote_url"] == "git@github.com:councilbox/saria.git"


def test_assets_are_shared_through_links_not_copies(client):
    test_client, headers = _client_objs(client)
    asset = test_client.post("/api/v1/assets", json={
        "type": "domain", "value": "api.councilbox.com", "actor": "gate"},
        headers=headers).json()["data"]
    projects = test_client.get("/api/v1/projects", headers=headers).json()["data"]
    alpha, beta = projects[0], projects[1]
    first = test_client.post(f"/api/v1/assets/{asset['id']}/links", json={
        "entity_type": "project", "entity_id": alpha["id"], "relation": "serves",
        "actor": "gate"}, headers=headers)
    second = test_client.post(f"/api/v1/assets/{asset['id']}/links", json={
        "entity_type": "project", "entity_id": beta["id"], "relation": "serves",
        "actor": "gate"}, headers=headers)
    assert first.status_code == 200 and second.status_code == 200
    # Both links point at the ONE asset; the polymorphic entity side differs.
    assert {first.json()["data"]["entity_id"], second.json()["data"]["entity_id"]} \
        == {alpha["id"], beta["id"]}
    # Two N:M links, ONE asset row (no duplication).
    asset_links = test_client.get(f"/api/v1/assets/{asset['id']}/links",
                                  headers=headers).json()
    assert asset_links["total"] == 2
    assets = test_client.get("/api/v1/assets", headers=headers).json()
    assert assets["total"] == 1
    # Re-linking with the same triple is idempotent.
    dup = test_client.post(f"/api/v1/assets/{asset['id']}/links", json={
        "entity_type": "project", "entity_id": alpha["id"], "relation": "serves"},
        headers=headers).json()
    assert dup["already_linked"] is True


def test_orphan_asset_lives_without_links(client):
    test_client, headers = _client_objs(client)
    assets = test_client.get("/api/v1/assets", headers=headers).json()
    assert assets["total"] == 0
    orphan = test_client.post("/api/v1/assets", json={
        "type": "ip", "value": "198.51.100.9", "detail": "CT-only discovery"},
        headers=headers).json()["data"]
    links = test_client.get(f"/api/v1/assets/{orphan['id']}/links",
                            headers=headers).json()
    assert links["total"] == 0  # exists, unlinked, first-class


def test_unlink_is_temporal_and_audited(client):
    test_client, headers = _client_objs(client)
    asset = test_client.post("/api/v1/assets", json={
        "type": "domain", "value": "stage.councilbox.com"}, headers=headers).json()["data"]
    project = test_client.get("/api/v1/projects", headers=headers).json()["data"][0]
    link = test_client.post(f"/api/v1/assets/{asset['id']}/links", json={
        "entity_type": "project", "entity_id": project["id"], "actor": "santiago"},
        headers=headers).json()["data"]
    gone = test_client.delete(
        f"/api/v1/assets/{asset['id']}/links/{link['id']}?actor=santiago",
        headers=headers).json()
    assert gone.get("already_removed") is not True
    after = test_client.get(f"/api/v1/assets/{asset['id']}/links",
                            headers=headers).json()
    assert after["total"] == 0
    # Deleting again is idempotent, not an error.
    repeat = test_client.delete(
        f"/api/v1/assets/{asset['id']}/links/{link['id']}",
        headers=headers).json()
    assert repeat["already_removed"] is True
    # The audit trail kept BOTH sides of the lifecycle.
    audit = test_client.get("/api/v1/audit", headers=headers).json()
    actions = [row["action"] for row in audit["data"]]
    assert actions.count("asset.linked") == 1
    assert actions.count("asset.unlinked") == 1
    assert audit["chain_ok"] is True


def test_finding_context_links(client):
    test_client, headers = _client_objs(client)
    svc = test_client.post("/api/v1/services", json={
        "name": "saria-api", "runtime": "fastapi", "actor": "gate"},
        headers=headers).json()["data"]
    dep = test_client.post("/api/v1/deployments", json={
        "name": "saria-api@eu", "environment": "production",
        "service_id": svc["id"], "actor": "gate"}, headers=headers).json()["data"]
    # Seed one finding through the normal ingest path.
    ingest = test_client.post("/api/v1/findings/ingest?project=alpha&version=1.0", json={
        "schema": "barad-findings-v1", "tool": "trivy",
        "findings": [{"kind": "secret", "title": "AWS key", "severity": "HIGH",
                      "rule_id": "aws-access-key-id", "path": "settings.py"}]},
        headers=headers)
    assert ingest.status_code == 200, ingest.text
    finding = test_client.get("/api/v1/findings", headers=headers).json()["data"][0]
    ctx_one = test_client.post(f"/api/v1/findings/{finding['id']}/contexts", json={
        "entity_type": "service", "entity_id": svc["id"], "actor": "gate"},
        headers=headers)
    ctx_two = test_client.post(f"/api/v1/findings/{finding['id']}/contexts", json={
        "entity_type": "deployment", "entity_id": dep["id"], "actor": "gate"},
        headers=headers)
    assert ctx_one.status_code == 200 and ctx_two.status_code == 200
    listed = test_client.get(f"/api/v1/findings/{finding['id']}/contexts",
                             headers=headers).json()
    assert listed["total"] == 2
    assert {row["entity_type"] for row in listed["data"]} == {"service", "deployment"}
    # Unknown org entity is rejected, wrong type rejected.
    bad = test_client.post(f"/api/v1/findings/{finding['id']}/contexts", json={
        "entity_type": "galaxy", "entity_id": svc["id"]}, headers=headers)
    assert bad.status_code == 422
    missing = test_client.post(f"/api/v1/findings/{finding['id']}/contexts", json={
        "entity_type": "service", "entity_id": "nope"}, headers=headers)
    assert missing.status_code == 404


def test_sbom_sharing_two_projects_does_not_duplicate_vulns(client):
    """Requirement 8: one component shared across projects stays one row in
    the catalog when both projects ingest it; findings stay per project."""
    test_client, headers = _client_objs(client)
    import json as _json
    payload = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "serialNumber": "urn:uuid:6b6e1d2f-1111-4000-8000-000000000001",
        "metadata": {"component": {"type": "application", "name": "shared-app"}},
        "components": [
            {"type": "library", "name": "requests", "version": "2.32.3",
             "purl": "pkg:pypi/requests@2.32.3"},
        ],
        "dependencies": [],
    }
    body = _json.dumps(payload).encode()

    projects = test_client.get("/api/v1/projects", headers=headers).json()["data"]
    r1 = test_client.post(f"/api/v1/sbom?project={projects[0]['slug']}&version=1.0",
                          content=body, headers={'X-API-Key': headers['X-API-Key'],
                                                 'Content-Type': 'application/octet-stream'})
    r2 = test_client.post(f"/api/v1/sbom?project={projects[1]['slug']}&version=1.0",
                          content=body, headers={'X-API-Key': headers['X-API-Key'],
                                                 'Content-Type': 'application/octet-stream'})
    assert r1.status_code in (200, 201) and r2.status_code in (200, 201)
    components_alpha = test_client.get(
        f"/api/v1/components?project={projects[0]['slug']}&version=1.0",
        headers=headers).json()
    components_beta = test_client.get(
        f"/api/v1/components?project={projects[1]['slug']}&version=1.0",
        headers=headers).json()
    assert components_alpha["total"] == components_beta["total"] == 1
    # Both views point at the same component identity (name/version/purl).
    assert components_alpha["data"][0]["identity_key"] == components_beta["data"][0]["identity_key"]
    assert components_alpha["data"][0]["purl"] == "pkg:pypi/requests@2.32.3"

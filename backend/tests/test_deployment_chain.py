"""`GET /api/v1/deployment/chain` — the facts, with no opinion (D74, D79).

The test that matters is the last one: the payload must not contain a severity, a
score, `affected` or `kev` **anywhere**. That is the difference between a fact
endpoint every screen can share and a second scoring model nobody can review.
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

FORBIDDEN_KEYS = {"severity", "score", "risk", "affected", "kev", "epss",
                  "priority", "cvss"}


@pytest.fixture()
def seeded(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/chain.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "chain")

    project = models.Project(org_id=org.id, name="Aurea", slug="aurea")
    session.add(project)
    session.flush()

    component = models.Component(
        org_id=org.id, identity_key="pkg:npm/lodash@4.17.15",
        purl="pkg:npm/lodash@4.17.15", name="lodash", version="4.17.15",
        license="MIT", manifest_path="package-lock.json")
    session.add(component)
    session.flush()

    version = models.ProjectVersion(project_id=project.id,
                                    component_id=component.id, version="1.8.0")
    session.add(version)
    session.flush()
    session.add(models.VersionComponent(project_version_id=version.id,
                                        component_id=component.id,
                                        is_direct=True,
                                        manifest_path="package-lock.json"))
    session.add(models.SbomImport(project_version_id=version.id,
                                  content_sha256="a" * 64, source="ci",
                                  filename="bom.json", components_received=120))

    pro = models.Deployment(org_id=org.id, name="aurea-api", environment="PRO",
                            version_id=version.id, version_label="1.8.0",
                            exposure="public", requires_auth=True,
                            status="active", source="manual")
    dev = models.Deployment(org_id=org.id, name="aurea-api", environment="DEV",
                            application_component_id=component.id,
                            version_label="1.8.0", exposure="internal",
                            requires_auth=False, status="active", source="manual")
    session.add_all([pro, dev])
    session.flush()

    asset = models.Asset(org_id=org.id, type="domain", value="app.aurea.test",
                         source="manual", classification_status="classified",
                         project_id=project.id)
    lonely = models.Asset(org_id=org.id, type="domain", value="old.aurea.test",
                          source="manual", classification_status="unclassified",
                          project_id=project.id)
    session.add_all([asset, lonely])
    session.flush()
    session.add(models.AssetLink(org_id=org.id, asset_id=asset.id,
                                 entity_type="deployment", entity_id=pro.id,
                                 relation="serves"))
    session.add(models.Observation(org_id=org.id, asset_id=asset.id, kind="technology",
                                   subject="app.aurea.test",
                                   value={"name": "nginx", "version": "1.25"},
                                   source="collector", coverage="full"))

    vulnerability = models.Vulnerability(source_id="CVE-2021-23337", source="osv",
                                         cve_id="CVE-2021-23337",
                                         title="Command injection in lodash",
                                         severity="HIGH")
    session.add(vulnerability)
    session.flush()
    session.add(models.Finding(org_id=org.id, project_id=project.id, kind="vulnerability",
                               fingerprint="fp-1", source="osv", severity="HIGH",
                               component_id=component.id,
                               vulnerability_id=vulnerability.id,
                               status="open", last_seen_version_id=version.id))
    session.commit()

    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}


def _walk_keys(value):
    if isinstance(value, dict):
        for key, inner in value.items():
            yield key
            yield from _walk_keys(inner)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys(item)


def test_chain_walks_build_deployment_asset_observation(seeded):
    http, headers = seeded
    response = http.get("/api/v1/deployment/chain",
                        params={"purl": "pkg:npm/lodash"},
                        headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()

    assert body["edges"]["components"][0]["name"] == "lodash"
    assert body["edges"]["builds"][0]["version"] == "1.8.0"
    assert body["edges"]["builds"][0]["confidence"] == "sbom"
    deployments = {row["environment"]: row for row in body["edges"]["deployments"]}
    assert set(deployments) == {"PRO", "DEV"}
    assert deployments["PRO"]["matched_by"] == "version_id"
    # The DEV row has no version_id: it is a declaration, and the chain says so.
    assert deployments["DEV"]["matched_by"] == "label"
    assert deployments["DEV"]["confidence"] == "declared"
    # The deployment's asset comes from the link; the second one is owned by the
    # project and is reported as inventory, not as this deployment's surface.
    values = [row["value"] for row in body["edges"]["assets"]]
    assert values == ["app.aurea.test", "old.aurea.test"]
    linked = next(row for row in body["edges"]["assets"]
                  if row["value"] == "app.aurea.test")
    assert linked["relations"][0]["entity_type"] == "deployment"
    assert body["edges"]["observations"][0]["kind"] == "technology"
    assert body["edges"]["findings"][0]["kind"] == "vulnerability"
    # Two assets are owned by the project; the unclassified one is reported.
    assert any("unclassified" in note for note in body["completeness"]["unknown_edges"])


def test_chain_names_the_edge_it_could_not_establish(seeded):
    http, headers = seeded
    response = http.get("/api/v1/deployment/chain",
                        params={"component": "nope"}, headers=headers)
    assert response.status_code == 404
    assert "no component" in response.json()["detail"]

    body = http.get("/api/v1/deployment/chain",
                    params={"asset": "old.aurea.test"}, headers=headers).json()
    assert body["edges"]["observations"] == []
    assert body["completeness"]["has_observation"] is False
    assert any("no observation" in note for note in body["completeness"]["unknown_edges"])


def test_chain_requires_a_query(seeded):
    http, headers = seeded
    response = http.get("/api/v1/deployment/chain", headers=headers)
    assert response.status_code == 422


def test_chain_carries_no_opinion_field(seeded):
    http, headers = seeded
    body = http.get("/api/v1/deployment/chain", params={"purl": "pkg:npm/lodash"},
                    headers=headers).json()
    leaked = FORBIDDEN_KEYS & set(_walk_keys(body))
    assert not leaked, f"chain must stay a description of the estate, found {leaked}"
    # And the finding edge points at the row instead of scoring it.
    finding = body["edges"]["findings"][0]
    assert set(finding) == {"id", "kind", "status", "component_id",
                           "vulnerability_id", "first_seen_at", "last_seen_at"}


def test_a_project_without_builds_answers_200_instead_of_404(seeded):
    """A lab target served straight from the host has no repositories, so no component
    links to it. That is an answer — "nothing is built from this project" — and it used to
    arrive as a 404, which the assistant reported as a gap in the estate instead of its
    own status code."""
    http, headers = seeded
    db = session_factory()()
    org = db.query(models.Organization).first()
    row = models.Project(org_id=org.id, name="Empty Lab", slug="empty-lab")
    db.add(row)
    db.commit()

    response = http.get("/api/v1/deployment/chain", params={"project": row.id},
                        headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body["edges"]["builds"] == []
    assert any("no component or build" in note
               for note in body["completeness"]["unknown_edges"])

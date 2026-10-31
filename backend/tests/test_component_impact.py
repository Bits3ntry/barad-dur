"""Cross-project component impact."""
import json
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


def _sbom(component="requests", version="2.31.0", purl="pkg:pypi/requests@2.31.0"):
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "metadata": {"component": {"type": "application", "name": "app"}},
        "components": [{"type": "library", "name": component, "version": version,
                        "purl": purl,
                        "licenses": [{"license": {"id": "Apache-2.0"}}]}],
    }


@pytest.fixture()
def impact_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/impact.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "impact")
    other_key = create_key(session, other.id, "impact2")
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key})


def _ingest(test_client, headers, project, version):
    return test_client.post(f"/api/v1/sbom?project={project}&version={version}",
                            content=json.dumps(_sbom()).encode(),
                            headers={**headers,
                                     "Content-Type": "application/octet-stream"})


def test_impact_spans_projects_and_counts_findings(impact_client):
    test_client, headers, _other = impact_client
    _ingest(test_client, headers, "billing", "1.0")
    _ingest(test_client, headers, "reporting", "2.0")

    components = test_client.get("/api/v1/components?project=billing&version=1.0",
                                 headers=headers).json()["data"]
    component = next(row for row in components if row["name"] == "requests")

    session = session_factory()()
    version_row = (session.query(models.ProjectVersion)
                   .join(models.Project, models.ProjectVersion.project_id == models.Project.id)
                   .filter(models.Project.slug == "billing").one())
    session.add(models.Finding(
        org_id=component and version_row.project_id and
        session.get(models.Project, version_row.project_id).org_id,
        project_id=version_row.project_id, component_id=component["id"],
        kind="dependency", source="osv", fingerprint="impact-1",
        title="requests vulnerable", severity="HIGH", status="open",
        last_seen_version_id=version_row.id))
    session.commit()

    impact = test_client.get("/api/v1/components/impact", params={
        "purl": "pkg:pypi/requests@2.31.0"}, headers=headers).json()["data"]
    assert impact["projects_using"] == 2
    projects = {usage["project"] for usage in impact["usages"]}
    assert projects == {"billing", "reporting"}
    billing = next(u for u in impact["usages"] if u["project"] == "billing")
    assert billing["findings"] == 1 and billing["open_findings"] == 1
    assert billing["by_severity"]["HIGH"] == 1
    reporting = next(u for u in impact["usages"] if u["project"] == "reporting")
    assert reporting["findings"] == 0
    assert impact["open_findings"] == 1
    # the project with open findings sorts first
    assert impact["usages"][0]["project"] == "billing"


def test_impact_identity_resolution_and_errors(impact_client):
    test_client, headers, _other = impact_client
    _ingest(test_client, headers, "billing", "1.0")
    by_name = test_client.get("/api/v1/components/impact",
                              params={"name": "requests"}, headers=headers)
    assert by_name.status_code == 200
    missing = test_client.get("/api/v1/components/impact",
                              params={"name": "nope"}, headers=headers)
    assert missing.status_code == 404
    no_key = test_client.get("/api/v1/components/impact", headers=headers)
    assert no_key.status_code == 400
    # a second version of the same name must be reported as ambiguous
    _ingest(test_client, headers, "billing", "2.0")
    test_client.post("/api/v1/sbom?project=billing&version=2.0",
                     content=json.dumps(_sbom(version="2.32.0",
                                              purl="pkg:pypi/requests@2.32.0")).encode(),
                     headers={**headers, "Content-Type": "application/octet-stream"})
    ambiguous = test_client.get("/api/v1/components/impact",
                                params={"name": "requests"}, headers=headers)
    assert ambiguous.status_code == 409
    assert "ambiguous" in ambiguous.json()["detail"]


def test_impact_is_tenant_scoped(impact_client):
    test_client, headers, other_headers = impact_client
    _ingest(test_client, headers, "billing", "1.0")
    foreign = test_client.get("/api/v1/components/impact",
                              params={"purl": "pkg:pypi/requests@2.31.0"},
                              headers=other_headers)
    assert foreign.status_code == 404  # not visible outside its org

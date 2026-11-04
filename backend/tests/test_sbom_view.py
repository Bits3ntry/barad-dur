"""The BOM as a screen: an index of every version that has one, and one version.

The contract the Supply chain section depends on: a BOM is reachable without
entering its project, the index counts what each version ships, and the version
view lists the findings per component instead of a rollup the reader has to
reconstruct.
"""
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


def _sbom(components):
    return {"bomFormat": "CycloneDX", "specVersion": "1.5",
            "metadata": {"component": {"type": "application", "name": "app"}},
            "components": [{"type": "library", "name": name, "version": version,
                            "purl": f"pkg:pypi/{name}@{version}"}
                           for name, version in components]}


@pytest.fixture()
def bom_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/bom.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "bom")
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), {"X-API-Key": key}, org


def _ingest(test_client, headers, components, project="payments", version="1.0"):
    response = test_client.post(f"/api/v1/sbom?project={project}&version={version}",
                                content=json.dumps(_sbom(components)).encode(),
                                headers={**headers,
                                         "Content-Type": "application/octet-stream"})
    assert response.status_code in (200, 201), response.text
    return response.json()


def _seed_finding(session, org_id, project_slug, version, component_name,
                  cve="CVE-2021-44228", severity="CRITICAL", kev=True):
    """One vulnerability finding attached to a component of that version."""
    project = session.query(models.Project).filter_by(slug=project_slug).one()
    project_version = (session.query(models.ProjectVersion)
                       .filter_by(project_id=project.id, version=version).one())
    component = (session.query(models.Component)
                 .filter_by(org_id=org_id, name=component_name).one())
    advisory = models.Vulnerability(source_id=cve, source="osv", cve_id=cve,
                                    title=f"{cve} in {component_name}",
                                    severity=severity,
                                    url=f"https://osv.dev/{cve}")
    session.add(advisory)
    if kev:
        session.add(models.KevEntry(cve_id=cve, title="Known exploited",
                                    source="cisa"))
    session.flush()
    session.add(models.Finding(
        org_id=org_id, project_id=project.id, kind="vulnerability",
        fingerprint=f"fp-{cve}-{component.id}", source="osv", title=advisory.title,
        severity=severity, component_id=component.id,
        vulnerability_id=advisory.id, status="open", tool="osv",
        last_seen_version_id=project_version.id,
        first_seen_at=models.utcnow(), last_seen_at=models.utcnow()))
    session.commit()


def test_bom_index_lists_versions_with_a_bom(bom_client):
    test_client, headers, org = bom_client
    _ingest(test_client, headers, [("requests", "2.31.0"), ("log4j-core", "2.14.1")])

    index = test_client.get("/api/v1/sbom/index", headers=headers)
    assert index.status_code == 200, index.text
    body = index.json()
    assert body["totals"]["boms"] == 1
    row = body["data"][0]
    assert row["project"]["slug"] == "payments"
    assert row["version"] == "1.0"
    assert row["components"] == 2
    assert row["is_latest"] is True
    assert row["last_import_at"]
    # Nothing analysed yet: the counts are zero, not missing.
    assert row["findings"] == {"total": 0, "kev": 0,
                               "by_severity": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0,
                                               "LOW": 0, "UNKNOWN": 0}}


def test_bom_version_lists_findings_per_component(bom_client):
    test_client, headers, org = bom_client
    _ingest(test_client, headers, [("requests", "2.31.0"), ("log4j-core", "2.14.1")])
    session = session_factory()()
    _seed_finding(session, org.id, "payments", "1.0", "log4j-core")
    session.close()

    view = test_client.get("/api/v1/sbom/version",
                           params={"project": "payments", "version": "1.0"},
                           headers=headers)
    assert view.status_code == 200, view.text
    data = view.json()["data"]
    assert data["components"] == 2
    assert data["findings"]["by_severity"]["CRITICAL"] == 1
    assert data["findings"]["kev"] == 1
    assert len(data["vulnerabilities"]) == 1
    row = data["vulnerabilities"][0]
    assert row["component"] == "log4j-core"
    assert row["component_version"] == "2.14.1"
    assert row["vulnerability"] == "CVE-2021-44228"
    assert row["severity"] == "CRITICAL"
    assert row["kev"] is True
    assert row["analyzer"] == "osv"
    assert row["suppressed"] is False
    assert row["attributed_on"]

    # The index now reflects the analysis: a version's counts are not a snapshot.
    index = test_client.get("/api/v1/sbom/index", headers=headers).json()
    assert index["data"][0]["findings"]["total"] == 1
    assert index["totals"]["kev"] == 1


def test_bom_version_is_404_for_a_version_that_does_not_exist(bom_client):
    test_client, headers, _org = bom_client
    _ingest(test_client, headers, [("requests", "2.31.0")])
    missing = test_client.get("/api/v1/sbom/version",
                              params={"project": "payments", "version": "9.9"},
                              headers=headers)
    assert missing.status_code == 404
    no_project = test_client.get("/api/v1/sbom/version",
                                 params={"project": "ghost", "version": "1.0"},
                                 headers=headers)
    assert no_project.status_code == 404

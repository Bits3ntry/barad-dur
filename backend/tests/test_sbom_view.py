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


def test_a_label_shared_by_two_components_is_answered_not_crashed(bom_client):
    """A monorepo ships one label per component, and the endpoint used to raise
    MultipleResultsFound — a 500 on a repository that merely had two components
    on the same release label."""
    test_client, headers, org = bom_client
    _ingest(test_client, headers, [("flask", "3.0.0")], project="aurea", version="main")

    session = session_factory()()
    try:
        project = session.query(models.Project).filter_by(slug="aurea").one()
        component = models.ApplicationComponent(
            org_id=org.id, project_id=project.id, name="Aurea web",
            slug="aurea-web", kind="service")
        session.add(component)
        session.flush()
        session.add(models.ProjectVersion(project_id=project.id, version="main",
                                          component_id=component.id))
        session.commit()
        product_wide = (session.query(models.ProjectVersion)
                        .filter_by(project_id=project.id, version="main",
                                   component_id=None).one())
        product_wide_id = product_wide.id
    finally:
        session.close()

    response = test_client.get("/api/v1/sbom/version",
                               params={"project": "aurea", "version": "main"},
                               headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()["data"]
    # `pick_version`'s documented rule: the product-wide release wins a bare label.
    assert body["version_id"] == product_wide_id
    assert body["components"] == 1

    # With the id the index already returned, the answer is exact.
    exact = test_client.get("/api/v1/sbom/version",
                            params={"project": "aurea", "version": "main",
                                    "version_id": product_wide_id},
                            headers=headers)
    assert exact.status_code == 200, exact.text
    assert exact.json()["data"]["version_id"] == product_wide_id


def test_component_rows_carry_risk_and_the_severity_bar_they_show(bom_client):
    """The components table is "what does this build ship and what does it cost",
    so every row needs an identity, a recomputable risk and its own histogram."""
    test_client, headers, org = bom_client
    _ingest(test_client, headers, [("flask", "3.0.0"), ("urllib3", "2.2.0")], version="2.0")
    session = session_factory()()
    try:
        _seed_finding(session, org.id, "payments", "2.0", "flask",
                      cve="CVE-2024-0001", severity="CRITICAL", kev=True)
    finally:
        session.close()

    body = test_client.get("/api/v1/sbom/version",
                           params={"project": "payments", "version": "2.0"},
                           headers=headers).json()["data"]
    rows = {row["name"]: row for row in body["component_rows"]}
    assert set(rows) == {"flask", "urllib3"}
    assert rows["flask"]["by_severity"]["CRITICAL"] == 1
    assert rows["flask"]["worst"] == "CRITICAL"
    # severity weight 10 × KEV 2 × (1 + 0 EPSS) = 20
    assert rows["flask"]["risk"] == 20.0
    assert rows["urllib3"]["risk"] == 0
    assert rows["flask"]["component_id"] and rows["urllib3"]["component_id"]
    # Risk sorts the table: the package to look at first is the first row.
    assert body["component_rows"][0]["name"] == "flask"


def test_the_package_drawer_answers_with_its_advisories(bom_client):
    test_client, headers, org = bom_client
    _ingest(test_client, headers, [("flask", "3.0.0")], version="2.0")
    session = session_factory()()
    try:
        _seed_finding(session, org.id, "payments", "2.0", "flask",
                      cve="CVE-2024-0002", severity="HIGH", kev=True)
    finally:
        session.close()

    body = test_client.get("/api/v1/sbom/version",
                           params={"project": "payments", "version": "2.0"},
                           headers=headers).json()["data"]
    row = body["component_rows"][0]
    drawer = test_client.get("/api/v1/sbom/component",
                             params={"version_id": body["version_id"],
                                     "component_id": row["component_id"]},
                             headers=headers)
    assert drawer.status_code == 200, drawer.text
    data = drawer.json()["data"]
    assert data["component"]["name"] == "flask"
    assert len(data["versions"]) == 1
    current = data["versions"][0]
    assert current["is_current"] is True
    assert [finding["advisory"] for finding in current["findings"]] == ["CVE-2024-0002"]
    assert current["findings"][0]["severity"] == "HIGH"
    assert current["findings"][0]["kev"] is True
    assert current["risk"] == 12.0  # 6 × KEV 2

def test_the_audit_list_reports_epss_when_the_feed_has_it(bom_client):
    """EPSS is what reorders two findings of the same severity, so the audit list
    carries it per advisory — and a missing score is null, never a zero."""
    test_client, headers, org = bom_client
    _ingest(test_client, headers, [("flask", "3.0.0")], version="2.0")
    session = session_factory()()
    try:
        _seed_finding(session, org.id, "payments", "2.0", "flask",
                      cve="CVE-2024-0003", severity="HIGH", kev=False)
        session.add(models.EpssScore(cve_id="CVE-2024-0003", epss="0.420000",
                                     percentile="0.98000"))
        session.commit()
    finally:
        session.close()

    rows = test_client.get("/api/v1/sbom/version",
                           params={"project": "payments", "version": "2.0"},
                           headers=headers).json()["data"]["vulnerabilities"]
    assert [row["epss"] for row in rows] == [0.42]

def test_ordering_happens_on_the_platform(bom_client):
    """A page that sorts itself only orders the rows that happen to be on it."""
    test_client, headers, org = bom_client
    _ingest(test_client, headers,
            [("zeta", "1.0.0"), ("alpha", "2.0.0"), ("mike", "3.0.0")], version="3.0")
    session = session_factory()()
    try:
        _seed_finding(session, org.id, "payments", "3.0", "mike",
                      cve="CVE-2024-0010", severity="LOW", kev=False)
        _seed_finding(session, org.id, "payments", "3.0", "alpha",
                      cve="CVE-2024-0011", severity="CRITICAL", kev=False)
        session.add(models.EpssScore(cve_id="CVE-2024-0010", epss="0.900000"))
        session.add(models.EpssScore(cve_id="CVE-2024-0011", epss="0.010000"))
        session.commit()
    finally:
        session.close()

    def names(**params):
        query = {"project": "payments", "version": "3.0", **params}
        return [row["name"] for row in test_client.get(
            "/api/v1/sbom/version", params=query, headers=headers
        ).json()["data"]["component_rows"]]

    # Default is risk, so the CRITICAL package leads.
    assert names()[0] == "alpha"
    assert names(component_sort="name", component_dir="asc") == ["alpha", "mike", "zeta"]
    assert names(component_sort="name", component_dir="desc") == ["zeta", "mike", "alpha"]
    # An unknown field falls back to the default order instead of exploding.
    assert names(component_sort="nonsense")[0] == "alpha"

    def advisories(**params):
        query = {"project": "payments", "version": "3.0", **params}
        return [(row["vulnerability"], row["epss"]) for row in test_client.get(
            "/api/v1/sbom/version", params=query, headers=headers
        ).json()["data"]["vulnerabilities"]]

    assert [row[0] for row in advisories()] == ["CVE-2024-0011", "CVE-2024-0010"]
    by_epss = advisories(advisory_sort="epss", advisory_dir="desc")
    assert [row[0] for row in by_epss] == ["CVE-2024-0010", "CVE-2024-0011"]


def test_code_findings_live_beside_the_audit_not_inside_it(bom_client):
    """A leaked key and a SQL-injection warning are source problems: they belong
    to the Code findings tab, and counting them as dependency CVEs made the
    header say 82 when the build shipped 62."""
    test_client, headers, org = bom_client
    _ingest(test_client, headers, [("flask", "3.0.0")], version="4.0")
    session = session_factory()()
    try:
        _seed_finding(session, org.id, "payments", "4.0", "flask",
                      cve="CVE-2024-0020", severity="HIGH", kev=False)
        project = session.query(models.Project).filter_by(slug="payments").one()
        project_version = (session.query(models.ProjectVersion)
                           .filter_by(project_id=project.id, version="4.0").one())
        session.add_all([
            models.Finding(org_id=org.id, project_id=project.id, kind="code-weakness",
                           vector="sast", fingerprint="fp-sast-1", source="scan",
                           title="sqlalchemy.text passes the constructed SQL",
                           severity="MEDIUM", status="open", tool="Opengrep OSS",
                           rule_id="python.sqlalchemy.security.avoid-sqlalchemy-text",
                           path="app/db.py", line=32,
                           last_seen_version_id=project_version.id),
            models.Finding(org_id=org.id, project_id=project.id, kind="secret",
                           vector="credential", fingerprint="fp-secret-1", source="scan",
                           title="generic-api-key has detected secret",
                           severity="CRITICAL", status="open", tool="gitleaks",
                           rule_id="generic-api-key", path="tests/test_api.py", line=9,
                           last_seen_version_id=project_version.id),
        ])
        session.commit()
    finally:
        session.close()

    body = test_client.get("/api/v1/sbom/version",
                           params={"project": "payments", "version": "4.0"},
                           headers=headers).json()["data"]
    # The audit keeps only what the build ships.
    assert body["findings"]["total"] == 1
    assert [row["vulnerability"] for row in body["vulnerabilities"]] == ["CVE-2024-0020"]
    # The source results are counted and listed apart.
    assert body["code"]["total"] == 2
    assert body["code"]["secrets"] == 1
    classes = {row["class"] for row in body["code_findings"]}
    assert classes == {"weakness", "secret"}
    secret = next(row for row in body["code_findings"] if row["class"] == "secret")
    assert secret["path"] == "tests/test_api.py" and secret["line"] == 9
    assert secret["tool"] == "gitleaks"

    # Ordering is the platform's, like every other table.
    by_path = test_client.get("/api/v1/sbom/version",
                              params={"project": "payments", "version": "4.0",
                                      "code_sort": "path", "code_dir": "desc"},
                              headers=headers).json()["data"]["code_findings"]
    assert [row["path"] for row in by_path] == ["tests/test_api.py", "app/db.py"]


def test_source_reports_when_it_has_no_revision_to_read(bom_client):
    """No recorded repository means "I cannot show you the file", not an empty one."""
    test_client, headers, _org = bom_client
    _ingest(test_client, headers, [("flask", "3.0.0")], version="6.0")
    version = test_client.get("/api/v1/sbom/version",
                              params={"project": "payments", "version": "6.0"},
                              headers=headers).json()["data"]
    body = test_client.get("/api/v1/sbom/source",
                           params={"version_id": version["version_id"],
                                   "path": "app/main.py"},
                           headers=headers).json()["data"]
    assert body["found"] is False
    assert "no repository and commit" in body["reason"]

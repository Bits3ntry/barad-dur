"""`GET /api/v1/exposure/verdict` — interpretation over the chain (D3, D78, D80).

The three answers that must not be confused:

* `affected`   — a deployment runs it and nothing refutes it
* `not_affected` — every match was refuted by a rule, with the rule named
* `unknown`    — we cannot tell, and the endpoint names the edge that would settle it

"No finding" is `unknown`, never `not_affected`. That is the whole point.
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
def seeded(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/verdict.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "verdict")

    project = models.Project(org_id=org.id, name="Aurea", slug="aurea")
    session.add(project)
    session.flush()
    component = models.Component(org_id=org.id,
                                 identity_key="pkg:npm/lodash@4.17.15",
                                 purl="pkg:npm/lodash@4.17.15", name="lodash",
                                 version="4.17.15", manifest_path="package-lock.json")
    session.add(component)
    session.flush()
    version = models.ProjectVersion(project_id=project.id,
                                    component_id=component.id, version="1.8.0")
    session.add(version)
    session.flush()
    session.add(models.VersionComponent(project_version_id=version.id,
                                        component_id=component.id, is_direct=True))
    session.add(models.SbomImport(project_version_id=version.id,
                                  content_sha256="b" * 64, source="ci",
                                  components_received=120))
    pro = models.Deployment(org_id=org.id, name="aurea-api", environment="PRO",
                            version_id=version.id, version_label="1.8.0",
                            exposure="public", requires_auth=True,
                            status="active", source="manual")
    retired = models.Deployment(org_id=org.id, name="aurea-old", environment="PRO",
                                version_id=version.id, version_label="1.8.0",
                                exposure="public", requires_auth=True,
                                status="retired", source="manual")
    session.add_all([pro, retired])
    session.flush()

    vulnerability = models.Vulnerability(source_id="CVE-2021-23337", source="osv",
                                         cve_id="CVE-2021-23337",
                                         title="Command injection in lodash",
                                         severity="HIGH")
    session.add(vulnerability)
    session.flush()
    session.add(models.Finding(org_id=org.id, project_id=project.id,
                               kind="vulnerability", fingerprint="fp-1",
                               source="osv", component_id=component.id,
                               vulnerability_id=vulnerability.id, status="open",
                               last_seen_version_id=version.id))
    session.commit()

    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, session


def test_verdict_is_affected_and_says_which_deployment(seeded):
    http, headers, _ = seeded
    response = http.get("/api/v1/exposure/verdict",
                        params={"cve": "CVE-2021-23337", "depth": "rules"},
                        headers=headers)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["verdict"] == "affected"
    states = {row["deployment"]: row["state"] for row in body["deployments"]}
    assert states["aurea-api"] == "applicable"
    # A retired deployment is refuted by its own row, not by absence of data.
    assert states["aurea-old"] == "refuted"
    pro = next(row for row in body["deployments"] if row["deployment"] == "aurea-api")
    assert any("internet-facing" in reason for reason in pro["reasons"])
    assert body["depth"] == "rules"


def test_verdict_stops_at_rules_and_says_so(seeded):
    http, headers, _ = seeded
    body = http.get("/api/v1/exposure/verdict",
                    params={"cve": "CVE-2021-23337", "depth": "full"},
                    headers=headers).json()
    assert body["depth"] == "rules"          # the analyst is F2, not invented here
    assert body["stopped_because"] == "analyst_not_implemented"


def test_verdict_never_reads_exceptions_as_clean(seeded):
    http, headers, _ = seeded
    body = http.get("/api/v1/exposure/verdict",
                    params={"cve": "CVE-9999-00000"}, headers=headers).json()
    assert body["verdict"] == "unknown"
    assert body["stopped_because"] == "no_match"
    assert any("ingest" in note for note in body["missing"])


def test_reference_with_findings_everywhere_refuted_is_not_affected(seeded):
    http, headers, session = seeded
    finding = session.query(models.Finding).one()
    finding.status = "false_positive"
    session.commit()
    body = http.get("/api/v1/exposure/verdict",
                    params={"cve": "CVE-2021-23337"}, headers=headers).json()
    assert body["verdict"] == "not_affected"
    assert any("false_positive" in reason
               for row in body["deployments"] for reason in row["reasons"])


def test_component_without_deployment_is_unknown_not_safe(seeded):
    http, headers, session = seeded
    for row in session.query(models.Deployment).all():
        session.delete(row)
    session.commit()
    body = http.get("/api/v1/exposure/verdict",
                    params={"cve": "CVE-2021-23337"}, headers=headers).json()
    assert body["verdict"] == "unknown"
    assert body["deployments"][0]["state"] == "not_deployed"
    assert any("deployment row" in note for note in body["missing"])


def test_depth_match_reports_that_rules_were_not_run(seeded):
    http, headers, _ = seeded
    body = http.get("/api/v1/exposure/verdict",
                    params={"cve": "CVE-2021-23337", "depth": "match"},
                    headers=headers).json()
    assert body["verdict"] == "unknown"
    assert body["stopped_because"] == "depth_match"
    assert all(row["state"] == "not_evaluated" for row in body["deployments"])

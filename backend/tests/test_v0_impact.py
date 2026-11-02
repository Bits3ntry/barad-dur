"""Business impact: per-application counts, with no invented score."""
import datetime
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
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/impact.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="bitsentry", name="Bitsentry")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "impact")
    other = models.Organization(slug="other", name="Other")
    session.add(other)
    session.flush()
    other_key = create_key(session, other.id, "impact-other")
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), key, other_key, session, org


def _finding(session, org, project, *, priority=None, cve=None, assignee=None,
             sla=None, status="open"):
    now = models.utcnow()
    vulnerability = None
    if cve:
        vulnerability = (session.query(models.Vulnerability)
                         .filter_by(source_id=cve).one_or_none())
        if vulnerability is None:
            vulnerability = models.Vulnerability(source_id=cve, cve_id=cve,
                                                 source="osv")
            session.add(vulnerability)
            session.flush()
    row = models.Finding(
        org_id=org.id, project_id=project.id, kind="vulnerability",
        fingerprint=f"fp-{priority}-{cve}-{assignee}-{status}-{now.timestamp()}",
        source="scanner", title="fixture", severity="HIGH", status=status,
        priority=priority, assignee=assignee, sla_deadline=sla,
        vulnerability_id=vulnerability.id if vulnerability else None,
        first_seen_at=now, last_seen_at=now)
    session.add(row)
    return row


def test_counts_per_application_come_from_real_rows(client):
    test_client, key, other_key, session, org = client
    project = models.Project(org_id=org.id, slug="aurea", name="AUREA")
    session.add(project)
    session.flush()
    component = models.ApplicationComponent(
        org_id=org.id, project_id=project.id, kind="backend", name="backend",
        slug="backend")
    session.add(component)
    session.flush()
    deployment = models.Deployment(
        org_id=org.id, name="aurea-prod", environment="production",
        application_component_id=component.id, status="active")
    staging = models.Deployment(
        org_id=org.id, name="aurea-staging", environment="staging",
        application_component_id=component.id, status="active")
    session.add_all([deployment, staging])
    session.flush()

    asset = models.Asset(org_id=org.id, type="domain",
                         value="api.aurea.test", source="scope")
    session.add(asset)
    session.flush()
    session.add(models.AssetLink(org_id=org.id, asset_id=asset.id,
                                 entity_type="deployment", entity_id=deployment.id))

    late = models.utcnow() - datetime.timedelta(days=2)
    _finding(session, org, project, priority="P0", cve="CVE-2026-0001",
             sla=late)
    _finding(session, org, project, priority="P1")
    _finding(session, org, project, priority=None, assignee="ana@test",
             status="acknowledged")
    _finding(session, org, project, priority="P0", status="resolved")
    session.commit()

    data = test_client.get("/api/v1/business-impact",
                           headers={"X-API-Key": key}).json()
    row = data["data"][0]
    assert row["project"] == "aurea"
    assert row["open_findings"] == 3, "resolved findings are not open work"
    assert row["by_priority"] == {"P0": 1, "P1": 1, "P2": 0, "P3": 0}
    assert row["untriaged"] == 1, "a finding with no rule match is untriaged"
    assert row["sla_breached"] == 1
    assert row["unassigned"] == 2
    assert row["cves"] == 1
    assert row["assets"] == 1
    assert row["production_deployments"] == 1, "staging is not production"
    assert data["totals"]["production_deployments"] == 1
    assert data["model"]["criticality"] == "not modelled"
    assert "no impact score" in data["model"]["note"]


def test_impact_is_isolated_and_reports_coverage(client):
    test_client, key, other_key, session, org = client
    project = models.Project(org_id=org.id, slug="aurea", name="AUREA")
    session.add(project)
    session.flush()
    _finding(session, org, project, priority="P0")
    session.add(models.Asset(org_id=org.id, type="domain",
                             value="orphan.aurea.test", source="import"))
    session.commit()

    mine = test_client.get("/api/v1/business-impact",
                           headers={"X-API-Key": key}).json()
    assert mine["data"][0]["open_findings"] == 1
    assert mine["coverage"]["assets_without_project"] == 1
    assert mine["coverage"]["projects_without_assets"] == 1

    theirs = test_client.get("/api/v1/business-impact",
                             headers={"X-API-Key": other_key}).json()
    assert theirs["data"] == []
    assert theirs["totals"]["open_findings"] == 0
    assert theirs["coverage"]["assets_without_project"] == 0


def test_every_response_states_that_criticality_is_not_modelled(client):
    test_client, key, _other, session, org = client
    empty = test_client.get("/api/v1/business-impact",
                            headers={"X-API-Key": key}).json()
    assert empty["data"] == []
    assert empty["totals"]["projects"] == 0
    assert empty["model"]["criticality"] == "not modelled"

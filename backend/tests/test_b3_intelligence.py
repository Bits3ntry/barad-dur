"""B3 acceptance: CVE reconcile, VEX statements, KEV/EPSS reads."""
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models, vulns  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/b3.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "b3")
    project = models.Project(org_id=org.id, slug="fixture", name="fixture")
    session.add(project)
    session.flush()
    version = models.ProjectVersion(project_id=project.id, version="1.0")
    session.add(version)
    session.flush()
    component = models.Component(
        org_id=org.id, identity_key="pkg:pypi/requests@2.32.3",
        name="requests", version="2.32.3", purl="pkg:pypi/requests@2.32.3",
        created_at=models.utcnow(), updated_at=models.utcnow())
    session.add(component)
    session.flush()
    session.add(models.VersionComponent(project_version_id=version.id,
                                        component_id=component.id))
    # One advisory without CVE, then its alias lands.
    advisory = models.Vulnerability(
        source_id="GHSA-9wx4-h78v-vm56", cve_id=None, title="Leak",
        severity="HIGH", url=None, created_at=models.utcnow())
    session.add(advisory)
    session.flush()
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    session.add(models.Finding(
        org_id=org.id, project_id=project.id, kind="vulnerability",
        fingerprint=vulns.vulnerability_fingerprint(org.id, project.id, component.identity_key,
                                                    advisory.source_id),
        source="osv", title="Leak", severity="HIGH",
        component_id=component.id, vulnerability_id=advisory.id,
        last_seen_version_id=version.id,
        first_seen_at=now, last_seen_at=now, updated_at=now))
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), key, session, org, advisory, component


H = {"X-API-Key": ""}


def test_reconcile_moves_finding_to_cve_fingerprint(client):
    test_client, key, session, org, advisory, component = client
    H["X-API-Key"] = key
    advisory.cve_id = "CVE-2024-35195"
    session.commit()

    moved = test_client.post("/api/v1/intelligence/reconcile", headers=H).json()
    assert moved["data"]["reconciled"] == 1
    rows = test_client.get("/api/v1/findings", headers=H).json()["data"]
    expected = vulns.vulnerability_fingerprint(
        org.id, rows[0]["project_id"], component.identity_key, "CVE-2024-35195")
    assert rows[0]["fingerprint"] == expected
    assert rows[0]["cve_id"] == "CVE-2024-35195"

    again = test_client.post("/api/v1/intelligence/reconcile", headers=H).json()
    assert again["data"]["reconciled"] == 0


def test_reconcile_dedupes_split_findings(client):
    test_client, key, session, org, advisory, component = client
    H["X-API-Key"] = key
    advisory.cve_id = "CVE-2024-35195"
    session.commit()
    # Second finding (advisory fingerprint) created after the alias landed.
    twin = session.query(models.Finding).one()
    split = models.Finding(
        org_id=org.id, project_id=twin.project_id, kind="vulnerability",
        fingerprint=vulns.vulnerability_fingerprint(
            org.id, twin.project_id, component.identity_id if hasattr(component, "identity_id") else component.identity_key,
            "GHSA-9wx4-h78v-vm56-x2"),
        source="osv", title="Leak (split)", severity="HIGH",
        component_id=component.id, vulnerability_id=advisory.id,
        last_seen_version_id=twin.last_seen_version_id,
        first_seen_at=twin.last_seen_at, last_seen_at=twin.last_seen_at,
        updated_at=twin.last_seen_at)
    session.add(split)
    session.commit()

    result = test_client.post("/api/v1/intelligence/reconcile", headers=H).json()
    assert result["data"]["reconciled"] == 2  # both re-keyed, only one row kept
    rows = test_client.get("/api/v1/findings", headers=H).json()["data"]
    assert len(rows) == 1
    expected = vulns.vulnerability_fingerprint(
        org.id, rows[0]["project_id"], component.identity_key, "CVE-2024-35195")
    assert rows[0]["fingerprint"] == expected


def test_vex_statements(client):
    test_client, key, session, _org, _advisory, _component = client
    H["X-API-Key"] = key
    finding_id = test_client.get("/api/v1/findings", headers=H).json()["data"][0]["id"]

    added = test_client.post("/api/v1/vex", json={
        "finding_id": finding_id, "status": "not_affected",
        "statement": "Not exploitable: requests never called from this path.",
        "author": "santiago"}, headers=H)
    assert added.status_code == 200, added.text
    listed = test_client.get("/api/v1/vex", headers=H).json()
    assert listed["total"] == 1
    assert listed["data"][0]["status"] == "not_affected"

    bad = test_client.post("/api/v1/vex", json={
        "finding_id": finding_id, "status": "vibes_ok",
        "statement": "not a status"}, headers=H)
    assert bad.status_code == 422


def test_kev_epss_reads(client, monkeypatch):
    import backend.app.routers.intelligence as intel
    monkeypatch.setattr(intel, "fetch_kev", lambda: [
        {"cve_id": "CVE-2024-35195", "title": "Requests leak", "date_added": "2024-07-01",
         "due_date": "2024-07-22", "source": "cisa"}])
    monkeypatch.setattr(intel, "fetch_epss", lambda: [
        {"cve_id": "CVE-2024-35195", "epss": "0.94", "percentile": "0.99"}])
    test_client, key, session, _org, _advisory, _component = client
    H["X-API-Key"] = key
    # Simulate a prior sync by merging the rows (network stays out of tests).
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc)
    session.merge(models.KevEntry(cve_id="CVE-2024-35195", title="Requests leak",
                                  date_added="2024-07-01", due_date="2024-07-22",
                                  source="cisa", fetched_at=now))
    session.merge(models.EpssScore(cve_id="CVE-2024-35195", epss="0.94",
                                   percentile="0.98", fetched_at=now))
    session.commit()
    kev = test_client.get("/api/v1/intel/kev/CVE-2024-35195", headers=H).json()
    assert kev["known_exploited"] is True
    epss = test_client.get("/api/v1/intel/epss/CVE-2024-35195", headers=H).json()
    assert epss["data"]["epss"] == "0.94"

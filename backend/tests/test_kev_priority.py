"""KEV→priority automation: a configurable rule, not a hard global override."""
import datetime
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
def kev_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/kev.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "kev")
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
    advisory = models.Vulnerability(
        source_id="GHSA-9wx4-h78v-vm56", cve_id="CVE-2024-35195", title="Leak",
        severity="MEDIUM", url=None, created_at=models.utcnow())
    session.add(advisory)
    session.flush()
    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc)
    finding = models.Finding(
        org_id=org.id, project_id=project.id, kind="vulnerability",
        fingerprint=vulns.vulnerability_fingerprint(org.id, project.id,
                                                    component.identity_key,
                                                    advisory.source_id),
        source="osv", title="Leak", severity="MEDIUM",
        component_id=component.id, vulnerability_id=advisory.id,
        last_seen_version_id=version.id,
        first_seen_at=now, last_seen_at=now, updated_at=now)
    session.add(finding)
    session.flush()
    from backend.app import lifecycle
    lifecycle.apply_lifecycle(session, org.id, finding)
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), key, session, finding


def test_kev_rule_promotes_and_reverts_on_rule_delete(kev_client, monkeypatch):
    import backend.app.routers.intelligence as intel
    monkeypatch.setattr(intel, "fetch_kev", lambda: [])
    test_client, key, session, finding = kev_client
    headers = {"X-API-Key": key}

    # Before any rule: MEDIUM falls back to P2.
    listed = test_client.get("/api/v1/findings", headers=headers).json()["data"]
    assert listed[0]["priority"] == "P2"

    # KEV entry lands in the local mirror (sync would fill it, we simulate).
    session.merge(models.KevEntry(cve_id="CVE-2024-35195", title="Requests leak",
                                  date_added="2024-07-01", fetched_at=models.utcnow()))
    session.commit()

    rule = test_client.post("/api/v1/priority-rules", json={
        "position": 1, "match_intel": "kev", "priority": "P0",
        "reason": "org rule: CISA-KEV exploited CVE -> drop everything"}, headers=headers)
    assert rule.status_code == 200, rule.text
    assert rule.json()["reclassified"] == 1
    listed = test_client.get("/api/v1/findings", headers=headers).json()["data"]
    assert listed[0]["priority"] == "P0"
    assert "CISA-KEV" in listed[0]["priority_reason"]

    # Pentest-only governance: delete the rule → next reclass run reverts.
    # (rules are never deleted; a lower-position opposite rule is added.)
    opposite = test_client.post("/api/v1/priority-rules", json={
        "position": 0, "match_kind": "vulnerability", "priority": "P2",
        "reason": "org rule bumped: KEV no longer outranks medium"}, headers=headers)
    assert opposite.json()["reclassified"] == 1
    listed = test_client.get("/api/v1/findings", headers=headers).json()["data"]
    assert listed[0]["priority"] == "P2"


def test_kev_rule_ignores_findings_without_cve_or_kev(kev_client):
    test_client, key, session, find = kev_client
    headers = {"X-API-Key": key}
    test_client.post("/api/v1/findings/ingest?project=fixture&version=1.0", json={
        "schema": "barad-findings-v1", "tool": "trivy",
        "findings": [{"kind": "secret", "title": "AWS key", "severity": "CRITICAL",
                      "rule_id": "aws-access-key-id", "path": "settings.py"}]},
        headers=headers)
    test_client.post("/api/v1/priority-rules", json={
        "position": 5, "match_intel": "kev", "priority": "P0",
        "reason": "org rule: KEV first"}, headers=headers)
    listed = test_client.get("/api/v1/findings", headers=headers).json()["data"]
    rows = {row["kind"]: row for row in listed}
    secret_row = rows["secret"]
    assert secret_row["priority"] == "P0"  # from CRITICAL severity fallback, NOT the KEV rule
    assert "fallback" in secret_row["priority_reason"]
    bad = test_client.post("/api/v1/priority-rules", json={
        "position": 9, "match_intel": "magic", "priority": "P3",
        "reason": "invalid intel criterion"}, headers=headers)
    assert bad.status_code == 422

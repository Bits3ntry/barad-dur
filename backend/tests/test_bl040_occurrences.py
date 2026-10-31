"""BL-040 acceptance: occurrence history per finding."""
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
def occ_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/bl40.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "bl40")
    session.add(models.Project(org_id=org.id, slug="fixture", name="fixture"))
    session.flush()
    session.add(models.ProjectVersion(project_id=session.query(models.Project)
                                      .first().id, version="1.0"))
    session.add(models.ProjectVersion(project_id=session.query(models.Project)
                                      .first().id, version="1.1"))
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key})


def _ingest(test_client, headers, version="1.0", tool="trivy", path="settings.py"):
    payload = {
        "schema": "barad-findings-v1", "tool": tool,
        "findings": [{"kind": "secret", "title": "AWS key", "severity": "HIGH",
                      "rule_id": "aws-access-key-id", "path": path}],
    }
    return test_client.post(
        f"/api/v1/findings/ingest?project=fixture&version={version}",
        json=payload, headers=headers)


def test_two_ingests_one_finding_two_occurrences(occ_client):
    test_client, headers = occ_client
    first = _ingest(test_client, headers)
    assert first.status_code == 200, first.text
    finding = test_client.get("/api/v1/findings", headers=headers).json()["data"][0]
    occ = test_client.get(f"/api/v1/findings/{finding['id']}/occurrences",
                          headers=headers).json()
    assert occ["total"] == 1
    # Second sighting: same finding dedupes; new version context → new row.
    second = _ingest(test_client, headers, version="1.1")
    assert second.status_code == 200
    occ = test_client.get(f"/api/v1/findings/{finding['id']}/occurrences",
                          headers=headers).json()
    assert occ["total"] == 2
    versions = {row["project_version_id"] for row in occ["data"]}
    assert len(versions) == 2


def test_identical_reingest_stays_one_occurrence(occ_client):
    """Idempotent rescan: the same (finding, tool, source, version) sighting
    must not spawn duplicate history rows."""
    test_client, headers = occ_client
    for _ in range(3):
        assert _ingest(test_client, headers).status_code == 200
    finding = test_client.get("/api/v1/findings", headers=headers).json()["data"][0]
    occ = test_client.get(f"/api/v1/findings/{finding['id']}/occurrences",
                          headers=headers).json()
    assert occ["total"] == 1


def test_occurrence_history_survives_suppression_workflow(occ_client):
    test_client, headers = occ_client
    _ingest(test_client, headers)
    finding = test_client.get("/api/v1/findings", headers=headers).json()["data"][0]
    rule = test_client.post("/api/v1/suppressions", json={
        "kind": "secret", "rule_id": "aws-access-key-id",
        "path_pattern": "settings.py", "suppression_type": "accepted_risk",
        "reason": "known pattern in demo fixture",
        "requested_by": "santiago"}, headers=headers)
    assert rule.status_code == 200, rule.text
    occ = test_client.get(f"/api/v1/findings/{finding['id']}/occurrences",
                          headers=headers).json()
    assert occ["total"] == 1  # sightings preserved alongside the lifecycle
    history = test_client.get("/api/v1/audit", headers=headers).json()
    assert history["chain_ok"] is True

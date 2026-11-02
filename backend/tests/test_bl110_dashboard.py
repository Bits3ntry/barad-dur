"""BL-110 acceptance: dashboard aggregates and per-project posture."""
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


@pytest.fixture()
def dash_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/dash.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "dash")
    other_key = create_key(session, other.id, "dash2")
    project = models.Project(org_id=org.id, slug="saria", name="saria")
    session.add(project)
    session.flush()
    session.add(models.ProjectVersion(project_id=project.id, version="1.0"))
    session.add(models.Asset(org_id=org.id, type="domain",
                             value="app.saria.dev", source="manual",
                             discovered_at=models.utcnow(),
                             last_seen_at=models.utcnow()))
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key},
            {"X-API-Key": other_key}, session, project)


def _ingest(test_client, headers, severity="HIGH", rule="r-1"):
    return test_client.post(
        "/api/v1/findings/ingest?project=saria&version=1.0",
        json={"schema": "barad-findings-v1", "tool": "opengrep",
              "findings": [{"kind": "code-weakness", "title": f"issue {rule}",
                            "severity": severity, "rule_id": rule,
                            "path": "app.py"}]}, headers=headers)


def test_summary_counts_are_real(dash_client):
    test_client, headers, _other, _session, _project = dash_client
    _ingest(test_client, headers, severity="HIGH", rule="a")
    _ingest(test_client, headers, severity="CRITICAL", rule="b")
    _ingest(test_client, headers, severity="LOW", rule="c")

    data = test_client.get(
        "/api/v1/dashboard/summary?project=saria&version=1.0",
        headers=headers).json()["data"]
    assert data["findings"]["total"] == 3
    assert data["findings"]["open"] == 3
    assert data["findings"]["by_severity_open"]["HIGH"] == 1
    assert data["findings"]["by_severity_open"]["CRITICAL"] == 1
    assert data["findings"]["by_severity_open"]["LOW"] == 1
    assert data["assets"]["total"] == 1
    assert data["assets"]["discovered_last_7d"] == 1
    assert data["scope"]["project"] == "saria"
    assert data["scope"]["version"] == "1.0"
    assert data["gate"] is not None  # no policy → default threshold verdict


def test_summary_reflects_status_changes(dash_client):
    test_client, headers, _other, _session, _project = dash_client
    _ingest(test_client, headers, severity="HIGH", rule="a")
    finding = test_client.get("/api/v1/findings", headers=headers).json()["data"][0]
    test_client.patch(f"/api/v1/findings/{finding['id']}/status",
                      json={"status": "resolved", "reason": "fixed",
                            "actor": "dev"}, headers=headers)
    data = test_client.get("/api/v1/dashboard/summary?project=saria",
                           headers=headers).json()["data"]
    assert data["findings"]["open"] == 0
    assert data["findings"]["total"] == 1
    assert data["findings"]["resolved_last_7d"] == 1


def test_projects_posture_and_isolation(dash_client):
    test_client, headers, other_headers, _session, _project = dash_client
    _ingest(test_client, headers, severity="CRITICAL", rule="z")
    posture = test_client.get("/api/v1/dashboard/projects",
                              headers=headers).json()["data"]
    assert posture[0]["project"] == "saria"
    assert posture[0]["critical"] == 1
    # Foreign org sees nothing — not even project names.
    foreign = test_client.get("/api/v1/dashboard/projects",
                              headers=other_headers).json()["data"]
    assert foreign == []
    # A project outside the caller's organization answers 404: returning a
    # zeroed summary would still confirm that the project exists.
    foreign_summary = test_client.get(
        "/api/v1/dashboard/summary?project=saria", headers=other_headers)
    assert foreign_summary.status_code == 404

"""B1 acceptance tests: priority classification, SLA deadlines, remediation."""
import datetime
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import incidents, lifecycle, models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/b1.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "b1")
    project = models.Project(org_id=org.id, slug="fixture", name="fixture")
    session.add(project)
    session.flush()
    session.add(models.ProjectVersion(project_id=project.id, version="1.0"))
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), key, session


def _ingest(client, key, findings):
    return client.post(
        "/api/v1/findings/ingest?project=fixture&version=1.0",
        json={"schema": "barad-findings-v1", "tool": "trivy", "findings": findings},
        headers={"X-API-Key": key})


def test_severity_fallback_classification_and_sla(client):
    test_client, key, session = client
    test_client.post("/api/v1/sla/policies",
                     json={"name": "default", "p0_days": 7, "p1_days": 15,
                           "p2_days": 30, "p3_days": 60, "make_default": True},
                     headers={"X-API-Key": key})
    _ingest(test_client, key, [
        {"kind": "secret", "title": "AWS key", "severity": "CRITICAL",
         "rule_id": "aws-access-key-id", "path": "settings.py"},
        {"kind": "misconfiguration", "title": "latest tag", "severity": "MEDIUM",
         "rule_id": "DS-0001", "path": "Dockerfile"},
    ])
    listed = test_client.get("/api/v1/findings", headers={"X-API-Key": key}).json()["data"]
    by_rule = {row["rule_id"]: row for row in listed}
    assert by_rule["aws-access-key-id"]["priority"] == "P0"
    assert "severity CRITICAL fallback" in by_rule["aws-access-key-id"]["priority_reason"]
    assert by_rule["DS-0001"]["priority"] == "P2"
    deadline = datetime.datetime.fromisoformat(by_rule["aws-access-key-id"]["sla_deadline"])
    created = datetime.datetime.fromisoformat(by_rule["aws-access-key-id"]["first_seen_at"])
    assert (deadline.date() - created.date()).days == 7


def test_rules_win_over_fallback_and_reclassify(client):
    test_client, key, session = client
    _ingest(test_client, key, [
        {"kind": "code-weakness", "title": "leak", "severity": "LOW",
         "rule_id": "python-weak", "path": "a.py"}])
    listed = test_client.get("/api/v1/findings", headers={"X-API-Key": key}).json()["data"]
    assert listed[0]["priority"] == "P3"

    rule = test_client.post("/api/v1/priority-rules",
                            json={"position": 1,
                                  "match_kind": "code-weakness",
                                  "priority": "P1",
                                  "reason": "org rule: code weaknesses ship fast"},
                            headers={"X-API-Key": key}).json()
    assert rule["reclassified"] == 1
    listed = test_client.get("/api/v1/findings", headers={"X-API-Key": key}).json()["data"]
    assert listed[0]["priority"] == "P1"
    assert listed[0]["priority_reason"] == "org rule: code weaknesses ship fast"


def test_remediation_single_open_task_contract(client):
    test_client, key, session = client
    _ingest(test_client, key, [
        {"kind": "secret", "title": "AWS key", "severity": "HIGH",
         "rule_id": "aws-access-key-id", "path": "settings.py"}])
    finding_id = test_client.get("/api/v1/findings", headers={"X-API-Key": key}).json()["data"][0]["id"]

    task = test_client.post("/api/v1/remediation/tasks",
                            json={"title": "Rotate leaked credentials", "owner": "santiago"},
                            headers={"X-API-Key": key}).json()["data"]
    link = test_client.post(f"/api/v1/remediation/tasks/{task['id']}/findings",
                            json={"finding_id": finding_id},
                            headers={"X-API-Key": key})
    assert link.status_code == 200
    assert link.json()["data"]["findings"][0]["id"] == finding_id

    other = test_client.post("/api/v1/remediation/tasks",
                             json={"title": "Follow-up"},
                             headers={"X-API-Key": key}).json()["data"]
    second = test_client.post(f"/api/v1/remediation/tasks/{other['id']}/findings",
                              json={"finding_id": finding_id},
                              headers={"X-API-Key": key})
    # OpenCTM contract: a finding belongs to at most one open task.
    assert second.status_code == 409
    assert "already in open task" in second.json()["detail"]

    test_client.patch(f"/api/v1/remediation/tasks/{task['id']}",
                      json={"status": "resolved"}, headers={"X-API-Key": key})
    third = test_client.post(f"/api/v1/remediation/tasks/{other['id']}/findings",
                             json={"finding_id": finding_id},
                             headers={"X-API-Key": key})
    assert third.status_code == 200

    closed = test_client.patch(f"/api/v1/remediation/tasks/{other['id']}",
                               json={"status": "resolved"}, headers={"X-API-Key": key})
    fourth = test_client.post(f"/api/v1/remediation/tasks/{other['id']}/findings",
                              json={"finding_id": finding_id},
                              headers={"X-API-Key": key})
    assert closed.status_code == 200
    assert fourth.status_code == 409

    linked = test_client.get("/api/v1/remediation/tasks", headers={"X-API-Key": key}).json()
    tasks = {row["title"]: row["status"] for row in linked["data"]}
    assert tasks == {"Rotate leaked credentials": "resolved", "Follow-up": "resolved"}


def test_unlink_leaves_history(client):
    test_client, key, session = client
    _ingest(test_client, key, [
        {"kind": "secret", "title": "key", "severity": "HIGH",
         "rule_id": "aws-access-key-id", "path": "settings.py"}])
    finding_id = test_client.get("/api/v1/findings", headers={"X-API-Key": key}).json()["data"][0]["id"]
    task = test_client.post("/api/v1/remediation/tasks", json={"title": "T"},
                            headers={"X-API-Key": key}).json()["data"]
    test_client.post(f"/api/v1/remediation/tasks/{task['id']}/findings",
                     json={"finding_id": finding_id}, headers={"X-API-Key": key})
    gone = test_client.delete(f"/api/v1/remediation/tasks/{task['id']}/findings/{finding_id}",
                              headers={"X-API-Key": key})
    assert gone.status_code == 200
    assert gone.json()["data"]["findings"] == []
    history = session.query(models.RemediationFinding).one()
    assert history.removed_at is not None

"""Named SAST baselines: snapshots are inert until a second person approves."""
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
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/base.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "bl")
    project = models.Project(org_id=org.id, slug="saria", name="saria")
    session.add(project)
    session.flush()
    version = models.ProjectVersion(project_id=project.id, version="1.0")
    repo = models.Repository(org_id=org.id, name="saria",
                             remote_url="https://github.com/acme/saria.git",
                             created_at=models.utcnow())
    session.add_all([version, repo])
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), {"X-API-Key": key}, repo.id


def _sarif(rule, path, line, severity="ERROR"):
    return {"tool": {"driver": {"name": "opengrep", "rules": [
        {"id": rule, "properties": {"security-severity": severity}}]}},
        "results": [{"ruleId": rule, "level": "error",
                     "message": {"text": f"{rule} at {path}"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": path},
                         "region": {"startLine": line}}}]}]}


def _pr(test_client, headers, repo_id, number):
    return test_client.post("/api/v1/code/pull-requests", json={
        "repository_id": repo_id, "number": number, "branch": "feat/x",
        "base_branch": "main", "head_sha": f"sha{number}", "project": "saria",
        "version": "1.0", "actor": "ci"}, headers=headers).json()["data"]


def test_baseline_lifecycle_and_self_approval(client):
    test_client, headers, repo_id = client
    pr = _pr(test_client, headers, repo_id, 31)
    test_client.post(f"/api/v1/code/pull-requests/{pr['id']}/sarif",
                     json={"run": _sarif("py.legacy", "app/old.py", 10),
                           "actor": "ci"}, headers=headers)
    created = test_client.post("/api/v1/code/baselines", json={
        "name": "legacy-2026-10", "repository_id": repo_id,
        "from_pr_id": pr["id"], "actor": "santiago"}, headers=headers)
    assert created.status_code == 201, created.text
    baseline = created.json()["data"]
    assert baseline["status"] == "draft"
    assert baseline["counters"]["entries"] == 1

    self_approval = test_client.post(
        f"/api/v1/code/baselines/{baseline['id']}/approve",
        json={"actor": "santiago"}, headers=headers)
    assert self_approval.status_code == 409
    assert "self-approval" in self_approval.json()["detail"]

    approved = test_client.post(
        f"/api/v1/code/baselines/{baseline['id']}/approve",
        json={"actor": "reviewer"}, headers=headers)
    assert approved.status_code == 200, approved.text
    assert approved.json()["data"]["status"] == "approved"
    assert approved.json()["data"]["approved_by"] == "reviewer"

    again = test_client.post(
        f"/api/v1/code/baselines/{baseline['id']}/approve",
        json={"actor": "third"}, headers=headers)
    assert again.status_code == 409


def test_draft_baseline_does_not_silence_findings(client):
    test_client, headers, repo_id = client
    first = _pr(test_client, headers, repo_id, 32)
    test_client.post(f"/api/v1/code/pull-requests/{first['id']}/sarif",
                     json={"run": _sarif("py.legacy2", "app/old2.py", 12),
                           "actor": "ci"}, headers=headers)
    test_client.post("/api/v1/code/baselines", json={
        "name": "draft-only", "repository_id": repo_id,
        "from_pr_id": first["id"], "actor": "santiago"}, headers=headers)
    second = _pr(test_client, headers, repo_id, 33)
    ingest = test_client.post(f"/api/v1/code/pull-requests/{second['id']}/sarif",
                              json={"run": _sarif("py.new", "app/new.py", 3),
                                    "actor": "ci"}, headers=headers)
    assert ingest.status_code == 200
    # a fresh finding with no approval anywhere is still new
    assert ingest.json()["counters"]["new"] == 1


def test_approved_baseline_marks_findings_as_baselined(client):
    test_client, headers, repo_id = client
    pr1 = _pr(test_client, headers, repo_id, 34)
    test_client.post(f"/api/v1/code/pull-requests/{pr1['id']}/sarif",
                     json={"run": _sarif("py.legacy3", "app/old3.py", 7),
                           "actor": "ci"}, headers=headers)
    baseline = test_client.post("/api/v1/code/baselines", json={
        "name": "approved-scope", "repository_id": repo_id,
        "from_pr_id": pr1["id"], "actor": "santiago"}, headers=headers).json()["data"]
    test_client.post(f"/api/v1/code/baselines/{baseline['id']}/approve",
                     json={"actor": "reviewer"}, headers=headers)

    # a *new* PR introducing the same rule+path is covered by the baseline
    pr2 = _pr(test_client, headers, repo_id, 35)
    covered = test_client.post(
        f"/api/v1/code/pull-requests/{pr2['id']}/sarif",
        json={"run": _sarif("py.legacy3", "app/old3.py", 7), "actor": "ci"},
        headers=headers)
    assert covered.status_code == 200, covered.text
    assert covered.json()["counters"]["baselined"] == 1
    assert covered.json()["counters"]["new"] == 0
    detail = test_client.get(f"/api/v1/code/pull-requests/{pr2['id']}/findings",
                             headers=headers).json()["data"]
    classifications = {entry["classification"]
                       for file_entry in detail["files"]
                       for entry in file_entry["findings"]}
    assert classifications == {"baselined"}

    # a genuinely different rule in the same repo is still new
    pr3 = _pr(test_client, headers, repo_id, 36)
    fresh = test_client.post(f"/api/v1/code/pull-requests/{pr3['id']}/sarif",
                             json={"run": _sarif("py.brand-new", "app/x.py", 1),
                                   "actor": "ci"}, headers=headers)
    assert fresh.json()["counters"]["new"] == 1


def test_duplicate_name_and_foreign_tenant(client):
    test_client, headers, repo_id = client
    payload = {"name": "dup", "repository_id": repo_id, "actor": "santiago"}
    assert test_client.post("/api/v1/code/baselines", json=payload,
                            headers=headers).status_code == 201
    assert test_client.post("/api/v1/code/baselines", json=payload,
                            headers=headers).status_code == 409

    session = session_factory()()
    other = models.Organization(slug="other", name="Other")
    session.add(other)
    session.flush()
    other_key = create_key(session, other.id, "other")
    session.commit()
    listed = test_client.get("/api/v1/code/baselines",
                             headers={"X-API-Key": other_key}).json()["data"]
    assert listed == []

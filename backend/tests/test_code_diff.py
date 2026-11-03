"""Diff viewer: base↔head diffs for PR files, honest about missing baselines."""
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402

BASE_CODE = "def handler(x):\n    return x\n"
HEAD_CODE = ("def handler(x):\n"
             "    y = x + 1\n"
             "    api_key = 'sk-live-DIFFSECRET'\n"
             "    return y\n")

SARIF = {
    "tool": {"driver": {"name": "opengrep", "rules": [
        {"id": "python.injection", "shortDescription": {"text": "injection"}}]}},
    "results": [{"ruleId": "python.injection", "level": "error",
                 "message": {"text": "injection"},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "app/handler.py"},
                     "region": {"startLine": 3}}}]}],
}


@pytest.fixture()
def diff_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/diff.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "diff")
    other_key = create_key(session, other.id, "diff2")
    project = models.Project(org_id=org.id, slug="saria", name="saria")
    session.add(project)
    session.flush()
    session.add(models.ProjectVersion(project_id=project.id, version="1.0"))
    repo = models.Repository(org_id=org.id, name="saria",
                             remote_url="https://github.com/acme/saria",
                             created_at=models.utcnow())
    session.add(repo)
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key},
            repo.id)


def _setup_pr(test_client, headers, repo_id):
    test_client.post("/api/v1/code/files", json={
        "repository_id": repo_id, "ref": "main", "path": "app/handler.py",
        "content": BASE_CODE, "actor": "ci"}, headers=headers)
    test_client.post("/api/v1/code/files", json={
        "repository_id": repo_id, "ref": "feat/x", "path": "app/handler.py",
        "content": HEAD_CODE, "actor": "ci"}, headers=headers)
    pr = test_client.post("/api/v1/code/pull-requests", json={
        "repository_id": repo_id, "number": 7, "title": "add math",
        "branch": "feat/x", "base_branch": "main", "project": "saria",
        "version": "1.0", "actor": "ci"}, headers=headers).json()["data"]
    test_client.post(f"/api/v1/code/pull-requests/{pr['id']}/sarif",
                     json={"run": SARIF, "actor": "ci"}, headers=headers)
    return pr


def test_generic_file_diff(diff_client):
    test_client, headers, _other, repo_id = diff_client
    _setup_pr(test_client, headers, repo_id)
    response = test_client.get("/api/v1/code/diff", params={
        "repository_id": repo_id, "from_ref": "main", "to_ref": "feat/x",
        "path": "app/handler.py"}, headers=headers)
    assert response.status_code == 200, response.text
    data = response.json()["data"]
    assert data["changed"] is True
    added = [row["text"] for row in data["rows"] if row["type"] == "added"]
    assert any("y = x + 1" in line for line in added)
    assert data["added"] >= 2
    # the secret in the added line never reaches the API
    serialized = str(data)
    assert "sk-live-DIFFSECRET" not in serialized
    assert "api_key=[REDACTED]" in serialized

    missing = test_client.get("/api/v1/code/diff", params={
        "repository_id": repo_id, "from_ref": "nope", "to_ref": "feat/x",
        "path": "app/handler.py"}, headers=headers)
    assert missing.status_code == 409
    assert "base snapshot missing" in missing.json()["detail"]


def test_pr_diff_honest_about_missing_base(diff_client):
    test_client, headers, _other, repo_id = diff_client
    pr = _setup_pr(test_client, headers, repo_id)
    diff = test_client.get(f"/api/v1/code/pull-requests/{pr['id']}/diff",
                           headers=headers).json()["data"]
    assert diff["files"][0]["path"] == "app/handler.py"
    assert diff["files"][0]["status"] == "diff"
    assert diff["files"][0]["added"] >= 1

    # delete the base snapshot → the response must say missing_base, not "no changes"
    session = session_factory()()
    base_row = (session.query(models.CodeFile)
                .filter_by(ref="main", path="app/handler.py").one())
    session.delete(base_row)
    session.commit()
    after = test_client.get(f"/api/v1/code/pull-requests/{pr['id']}/diff",
                            headers=headers).json()["data"]
    assert after["files"][0]["status"] == "missing_base"
    assert "rows" not in after["files"][0]


def test_pr_diff_requires_refs_and_isolation(diff_client):
    test_client, headers, other_headers, repo_id = diff_client
    pr = _setup_pr(test_client, headers, repo_id)
    bare = test_client.post("/api/v1/code/pull-requests", json={
        "number": 8, "project": "saria", "version": "1.0",
        "actor": "ci"}, headers=headers).json()["data"]
    test_client.post(f"/api/v1/code/pull-requests/{bare['id']}/sarif",
                     json={"run": SARIF, "actor": "ci"}, headers=headers)
    no_refs = test_client.get(f"/api/v1/code/pull-requests/{bare['id']}/diff",
                              headers=headers).json()["data"]
    assert no_refs["files"][0]["status"] == "missing_refs"

    assert test_client.get(f"/api/v1/code/pull-requests/{pr['id']}/diff",
                           headers=other_headers).status_code == 404

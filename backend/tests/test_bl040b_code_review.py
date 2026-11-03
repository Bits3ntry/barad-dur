"""BL-040b part 2 acceptance: code files, PR classification and context."""
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402

SOURCE = "\n".join([
    "import subprocess",
    "def handler(request):",
    "    cmd = request.GET['cmd']",
    "    api_key = 'sk-live-TOPSECRET'",
    "    return subprocess.check_output(cmd, shell=True)",  # line 5
    "def safe():",
    "    return 1",
])

SARIF = {
    "tool": {"driver": {"name": "opengrep", "rules": [
        {"id": "python.lang.security.audit.subprocess-shell",
         "shortDescription": {"text": "Shell injection"},
         "properties": {"security-severity": "9.1"}}]}},
    "results": [{
        "ruleId": "python.lang.security.audit.subprocess-shell",
        "level": "error",
        "message": {"text": "Untrusted input reaches subprocess with shell=True"},
        "locations": [{"physicalLocation": {
            "artifactLocation": {"uri": "app/handler.py"},
            "region": {"startLine": 5}}}],
    }],
}


@pytest.fixture()
def code_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/code.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "code")
    other_key = create_key(session, other.id, "code2")
    project = models.Project(org_id=org.id, slug="saria", name="saria")
    session.add(project)
    session.flush()
    version = models.ProjectVersion(project_id=project.id, version="1.0")
    repo = models.Repository(org_id=org.id, name="saria",
                             remote_url="https://github.com/acme/saria",
                             created_at=models.utcnow())
    session.add_all([version, repo])
    session.flush()
    session.add(models.ProjectRepository(
        org_id=org.id, project_id=project.id, repository_id=repo.id))
    session.commit()
    from fastapi.testclient import TestClient

    ids = {"repo": repo.id}
    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key},
            ids)


def test_file_push_context_and_redaction(code_client):
    test_client, headers, _other, ids = code_client
    pushed = test_client.post("/api/v1/code/files", json={
        "repository_id": ids["repo"], "ref": "main", "path": "app/handler.py",
        "content": SOURCE, "actor": "ci"}, headers=headers)
    assert pushed.status_code == 200, pushed.text
    assert pushed.json()["created"] is True

    # idempotent re-push of identical content
    again = test_client.post("/api/v1/code/files", json={
        "repository_id": ids["repo"], "ref": "main", "path": "app/handler.py",
        "content": SOURCE, "actor": "ci"}, headers=headers)
    assert again.json()["created"] is False

    read = test_client.get("/api/v1/code/file", params={
        "repository_id": ids["repo"], "path": "app/handler.py", "ref": "main"},
        headers=headers).json()["data"]
    assert "sk-live-TOPSECRET" not in read["content"]
    assert "api_key=[REDACTED]" in read["content"]

    # PR + SARIF → finding, then context around it
    pr = test_client.post("/api/v1/code/pull-requests", json={
        "repository_id": ids["repo"], "number": 42, "title": "add handler",
        "branch": "feat/handler", "base_branch": "main", "head_sha": "abc123",
        "project": "saria", "version": "1.0", "actor": "ci"}, headers=headers)
    assert pr.status_code == 200, pr.text
    pr_id = pr.json()["data"]["id"]

    scan = test_client.post(f"/api/v1/code/pull-requests/{pr_id}/sarif", json={
        "run": SARIF, "actor": "ci"}, headers=headers)
    assert scan.status_code == 200, scan.text
    counters = scan.json()["counters"]
    assert counters["new"] == 1 and counters["existing"] == 0
    assert scan.json()["data"]["gate_verdict"] in {"pass", "fail"}
    assert "NEW" in scan.json()["comment"]

    grouped = test_client.get(f"/api/v1/code/pull-requests/{pr_id}/findings",
                              headers=headers).json()["data"]
    assert grouped["files"][0]["path"] == "app/handler.py"
    finding_id = grouped["files"][0]["findings"][0]["finding_id"]

    context = test_client.get(f"/api/v1/code/findings/{finding_id}/context",
                              params={"radius": 2}, headers=headers).json()["data"]
    assert context["path"] == "app/handler.py"
    numbers = [line["number"] for line in context["lines"]]
    assert 5 in numbers
    body = "\n".join(line["text"] for line in context["lines"])
    assert "sk-live-TOPSECRET" not in body          # redaction in context too
    assert "subprocess.check_output" in body        # the vulnerable line


def test_second_scan_marks_existing(code_client):
    test_client, headers, _other, ids = code_client
    test_client.post("/api/v1/code/files", json={
        "repository_id": ids["repo"], "ref": "main", "path": "app/handler.py",
        "content": SOURCE, "actor": "ci"}, headers=headers)
    pr_id = test_client.post("/api/v1/code/pull-requests", json={
        "repository_id": ids["repo"], "number": 43, "project": "saria",
        "version": "1.0", "actor": "ci"}, headers=headers).json()["data"]["id"]
    first = test_client.post(f"/api/v1/code/pull-requests/{pr_id}/sarif",
                             json={"run": SARIF, "actor": "ci"},
                             headers=headers).json()["counters"]
    assert first["new"] == 1
    second = test_client.post(f"/api/v1/code/pull-requests/{pr_id}/sarif",
                              json={"run": SARIF, "actor": "ci"},
                              headers=headers).json()["counters"]
    assert second["new"] == 0 and second["existing"] == 1


def test_pr_status_and_isolation(code_client):
    test_client, headers, other_headers, ids = code_client
    pr_id = test_client.post("/api/v1/code/pull-requests", json={
        "repository_id": ids["repo"], "number": 44, "project": "saria",
        "version": "1.0", "actor": "ci"}, headers=headers).json()["data"]["id"]
    bad = test_client.post(f"/api/v1/code/pull-requests/{pr_id}/status",
                           json={"status": "vibes", "actor": "x"}, headers=headers)
    assert bad.status_code == 422
    merged = test_client.post(f"/api/v1/code/pull-requests/{pr_id}/status",
                              json={"status": "merged", "actor": "ci"},
                              headers=headers).json()["data"]
    assert merged["status"] == "merged"

    assert test_client.get(f"/api/v1/code/pull-requests/{pr_id}/findings",
                           headers=other_headers).status_code == 404
    assert test_client.get("/api/v1/code/pull-requests",
                           headers=other_headers).json()["total"] == 0
    assert test_client.get("/api/v1/code/file", params={
        "repository_id": ids["repo"], "path": "app/handler.py"},
        headers=other_headers).status_code == 404

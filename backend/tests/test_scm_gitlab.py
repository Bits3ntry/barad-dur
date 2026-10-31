"""GitLab publishing against a real local stub (provider detected from remote)."""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402

STATE = {"statuses": [], "notes": [], "next_id": 0}


class GitLab(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        length = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(length) or b"{}")

    def do_POST(self):
        payload = self._body()
        assert self.headers.get("PRIVATE-TOKEN") == "gl-token"
        if self.path.endswith("/statuses/abc123"):
            STATE["statuses"].append(payload)
            return self._json(201, {"id": len(STATE["statuses"]),
                                    "state": payload["state"]})
        if self.path.endswith("/notes"):
            STATE["next_id"] += 1
            note = {"id": STATE["next_id"], "body": payload["body"]}
            STATE["notes"].append(note)
            return self._json(201, note)
        return self._json(404, {"error": "not found"})

    def do_GET(self):
        if "/notes" in self.path:
            return self._json(200, STATE["notes"])
        return self._json(404, {"error": "not found"})

    def do_PUT(self):
        payload = self._body()
        note_id = int(self.path.rsplit("/", 1)[-1])
        for note in STATE["notes"]:
            if note["id"] == note_id:
                note["body"] = payload["body"]
                return self._json(200, note)
        return self._json(404, {"error": "not found"})


@pytest.fixture(scope="module")
def gitlab_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), GitLab)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}/api/v4"
    server.shutdown()


@pytest.fixture()
def gitlab_client(tmp_path, monkeypatch, gitlab_server):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/gl.db")
    monkeypatch.setenv("GITLAB_API_URL", gitlab_server)
    monkeypatch.setenv("GITLAB_TOKEN", "gl-token")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    STATE["statuses"].clear()
    STATE["notes"].clear()
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "gl")
    project = models.Project(org_id=org.id, slug="saria", name="saria")
    session.add(project)
    session.flush()
    session.add(models.ProjectVersion(project_id=project.id, version="1.0"))
    repo = models.Repository(org_id=org.id, name="saria",
                             remote_url="https://gitlab.example.dev/acme/saria.git",
                             created_at=models.utcnow())
    session.add(repo)
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, repo.id)


SARIF = {"tool": {"driver": {"name": "opengrep", "rules": [
    {"id": "py.bad", "properties": {"security-severity": "8.0"}}]}},
    "results": [{"ruleId": "py.bad", "level": "error",
                 "message": {"text": "bad"},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "app/x.py"},
                     "region": {"startLine": 1}}}]}]}


def test_gitlab_publish_status_and_note(gitlab_client):
    test_client, headers, repo_id = gitlab_client
    pr = test_client.post("/api/v1/code/pull-requests", json={
        "repository_id": repo_id, "number": 5, "branch": "feat/x",
        "base_branch": "main", "head_sha": "abc123", "project": "saria",
        "version": "1.0", "actor": "ci"}, headers=headers).json()["data"]
    test_client.post(f"/api/v1/code/pull-requests/{pr['id']}/sarif",
                     json={"run": SARIF, "actor": "ci"}, headers=headers)

    first = test_client.post(f"/api/v1/code/pull-requests/{pr['id']}/publish",
                             json={"actor": "ci"}, headers=headers)
    assert first.status_code == 200, first.text
    result = first.json()["data"]
    assert result["provider"] == "gitlab"
    assert result["repository"] == "acme/saria"
    # GitLab speaks success/failed, not failure
    assert STATE["statuses"][0]["state"] in {"success", "failed"}
    assert STATE["statuses"][0]["name"] == "barad-dur/security"
    assert len(STATE["notes"]) == 1

    second = test_client.post(f"/api/v1/code/pull-requests/{pr['id']}/publish",
                              json={"actor": "ci"}, headers=headers)
    assert second.status_code == 200
    assert len(STATE["notes"]) == 1  # note updated, not duplicated
    assert len(STATE["statuses"]) == 2  # statuses are append-only


def test_gitlab_requires_its_own_token(gitlab_client, monkeypatch):
    test_client, headers, repo_id = gitlab_client
    pr = test_client.post("/api/v1/code/pull-requests", json={
        "repository_id": repo_id, "number": 6, "branch": "feat/y",
        "base_branch": "main", "head_sha": "deadbeef", "project": "saria",
        "version": "1.0", "actor": "ci"}, headers=headers).json()["data"]
    test_client.post(f"/api/v1/code/pull-requests/{pr['id']}/sarif",
                     json={"run": SARIF, "actor": "ci"}, headers=headers)
    monkeypatch.delenv("GITLAB_TOKEN", raising=False)
    denied = test_client.post(f"/api/v1/code/pull-requests/{pr['id']}/publish",
                              json={"actor": "ci"}, headers=headers)
    assert denied.status_code == 503
    assert "GITLAB_TOKEN" in denied.json()["detail"]


def test_unknown_provider_is_rejected(gitlab_client):
    test_client, headers, _repo_id = gitlab_client
    session = session_factory()()
    org = session.query(models.Organization).first()
    other_repo = models.Repository(org_id=org.id, name="internal",
                                   remote_url="https://gitea.local/acme/app",
                                   created_at=models.utcnow())
    session.add(other_repo)
    session.commit()
    pr = test_client.post("/api/v1/code/pull-requests", json={
        "repository_id": other_repo.id, "number": 7, "branch": "f",
        "base_branch": "main", "head_sha": "cafebabe", "project": "saria",
        "version": "1.0", "actor": "ci"}, headers=headers).json()["data"]
    test_client.post(f"/api/v1/code/pull-requests/{pr['id']}/sarif",
                     json={"run": SARIF, "actor": "ci"}, headers=headers)
    denied = test_client.post(f"/api/v1/code/pull-requests/{pr['id']}/publish",
                              json={"actor": "ci"}, headers=headers)
    assert denied.status_code == 422
    assert "scm_provider_unknown" in denied.json()["detail"]

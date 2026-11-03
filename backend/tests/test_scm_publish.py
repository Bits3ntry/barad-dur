"""SCM publishing against a real local GitHub stub (no mocks)."""
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

STATE = {"statuses": [], "comments": [], "next_id": 100}


class Github(BaseHTTPRequestHandler):
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
        assert self.headers.get("Authorization")
        if self.path.endswith("/statuses/abc123"):
            STATE["statuses"].append(payload)
            return self._json(201, {"id": 1, "state": payload["state"]})
        if "/issues/" in self.path and self.path.endswith("/comments"):
            STATE["next_id"] += 1
            comment = {"id": STATE["next_id"], "body": payload["body"]}
            STATE["comments"].append(comment)
            return self._json(201, comment)
        return self._json(404, {"error": "not found"})

    def do_GET(self):
        if self.path.startswith("/repos/acme/saria/issues/") and "comments" in self.path:
            return self._json(200, STATE["comments"])
        return self._json(404, {"error": "not found"})

    def do_PATCH(self):
        payload = self._body()
        comment_id = int(self.path.rsplit("/", 1)[-1])
        for comment in STATE["comments"]:
            if comment["id"] == comment_id:
                comment["body"] = payload["body"]
                return self._json(200, comment)
        return self._json(404, {"error": "not found"})


@pytest.fixture(scope="module")
def github_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Github)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture()
def publish_client(tmp_path, monkeypatch, github_server):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/pub.db")
    monkeypatch.setenv("GITHUB_API_URL", github_server)
    monkeypatch.setenv("GITHUB_TOKEN", "gh-token")
    STATE["statuses"].clear()
    STATE["comments"].clear()
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "pub")
    other_key = create_key(session, other.id, "pub2")
    project = models.Project(org_id=org.id, slug="saria", name="saria")
    session.add(project)
    session.flush()
    session.add(models.ProjectVersion(project_id=project.id, version="1.0"))
    repo = models.Repository(org_id=org.id, name="saria",
                             remote_url="https://github.com/acme/saria.git",
                             created_at=models.utcnow())
    session.add(repo)
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key},
            repo.id)


SARIF = {"tool": {"driver": {"name": "opengrep", "rules": [
    {"id": "py.hardcoded", "properties": {"security-severity": "9.0"}}]}},
    "results": [{"ruleId": "py.hardcoded", "level": "error",
                 "message": {"text": "hardcoded secret"},
                 "locations": [{"physicalLocation": {
                     "artifactLocation": {"uri": "app/x.py"},
                     "region": {"startLine": 2}}}]}]}


def _pr_with_scan(test_client, headers, repo_id, number=11):
    pr = test_client.post("/api/v1/code/pull-requests", json={
        "repository_id": repo_id, "number": number, "title": "publish me",
        "branch": "feat/p", "base_branch": "main", "head_sha": "abc123",
        "project": "saria", "version": "1.0", "actor": "ci"},
        headers=headers).json()["data"]
    test_client.post(f"/api/v1/code/pull-requests/{pr['id']}/sarif",
                     json={"run": SARIF, "actor": "ci"}, headers=headers)
    return pr


def test_publish_posts_status_and_single_comment(publish_client):
    test_client, headers, _other, repo_id = publish_client
    pr = _pr_with_scan(test_client, headers, repo_id)
    first = test_client.post(f"/api/v1/code/pull-requests/{pr['id']}/publish",
                             json={"actor": "ci"}, headers=headers)
    assert first.status_code == 200, first.text
    assert first.json()["data"]["state"] == "failure"
    assert len(STATE["statuses"]) == 1
    assert STATE["statuses"][0]["context"] == "barad-dur/security"
    assert len(STATE["comments"]) == 1

    # publishing again updates the same comment (idempotent) instead of adding one
    second = test_client.post(f"/api/v1/code/pull-requests/{pr['id']}/publish",
                              json={"actor": "ci"}, headers=headers)
    assert second.status_code == 200
    assert len(STATE["comments"]) == 1
    assert len(STATE["statuses"]) == 2  # statuses are append-only by design


def test_publish_requires_gate_and_configuration(publish_client, monkeypatch):
    test_client, headers, _other, repo_id = publish_client
    pr = test_client.post("/api/v1/code/pull-requests", json={
        "repository_id": repo_id, "number": 12, "branch": "feat/p",
        "base_branch": "main", "head_sha": "abc123", "project": "saria",
        "version": "1.0", "actor": "ci"}, headers=headers).json()["data"]
    no_gate = test_client.post(f"/api/v1/code/pull-requests/{pr['id']}/publish",
                               json={"actor": "ci"}, headers=headers)
    assert no_gate.status_code == 409
    assert "gate verdict" in no_gate.json()["detail"]

    scanned = _pr_with_scan(test_client, headers, repo_id, number=13)
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    unconfigured = test_client.post(
        f"/api/v1/code/pull-requests/{scanned['id']}/publish",
        json={"actor": "ci"}, headers=headers)
    assert unconfigured.status_code == 503
    assert "scm_not_configured" in unconfigured.json()["detail"]


def test_publish_isolation(publish_client):
    test_client, headers, other_headers, repo_id = publish_client
    pr = _pr_with_scan(test_client, headers, repo_id, number=14)
    assert test_client.post(f"/api/v1/code/pull-requests/{pr['id']}/publish",
                            json={"actor": "intruder"},
                            headers=other_headers).status_code == 404

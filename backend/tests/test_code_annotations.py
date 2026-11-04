"""GitHub check runs with inline annotations."""
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

STATE = {"check_runs": [], "statuses": [], "comments": [], "next_id": 0}


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
        if self.path.endswith("/check-runs"):
            STATE["check_runs"].append(payload)
            return self._json(201, {"id": 9})
        if "/statuses/" in self.path:
            STATE["statuses"].append(payload)
            return self._json(201, {"id": 1})
        if self.path.endswith("/comments"):
            STATE["next_id"] += 1
            note = {"id": STATE["next_id"], "body": payload["body"]}
            STATE["comments"].append(note)
            return self._json(201, note)
        return self._json(404, {})

    def do_GET(self):
        if "comments" in self.path:
            return self._json(200, STATE["comments"])
        return self._json(404, {})

    def do_PATCH(self):
        payload = self._body()
        note_id = int(self.path.rsplit("/", 1)[-1])
        for note in STATE["comments"]:
            if note["id"] == note_id:
                note["body"] = payload["body"]
                return self._json(200, note)
        return self._json(404, {})


@pytest.fixture(scope="module")
def gh_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Github)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture()
def annot_client(tmp_path, monkeypatch, gh_server):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/an.db")
    monkeypatch.setenv("GITHUB_API_URL", gh_server)
    monkeypatch.setenv("GITHUB_TOKEN", "gh-token")
    STATE["check_runs"].clear()
    STATE["statuses"].clear()
    STATE["comments"].clear()
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "an")
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

    return TestClient(app), {"X-API-Key": key}, repo.id


def _sarif(rule, path, line, severity):
    return {"tool": {"driver": {"name": "opengrep", "rules": [
        {"id": rule, "properties": {"security-severity": severity}}]}},
        "results": [{"ruleId": rule, "level": "error",
                     "message": {"text": f"{rule} at {path}"},
                     "locations": [{"physicalLocation": {
                         "artifactLocation": {"uri": path},
                         "region": {"startLine": line}}}]}]}


def test_check_run_with_annotations(annot_client):
    test_client, headers, repo_id = annot_client
    pr = test_client.post("/api/v1/code/pull-requests", json={
        "repository_id": repo_id, "number": 21, "branch": "feat/a",
        "base_branch": "main", "head_sha": "cafe1234", "project": "saria",
        "version": "1.0", "actor": "ci"}, headers=headers).json()["data"]
    test_client.post(f"/api/v1/code/pull-requests/{pr['id']}/sarif",
                     json={"run": _sarif("py.critical", "app/a.py", 5, "9.5"),
                           "actor": "ci"}, headers=headers)
    test_client.post(f"/api/v1/code/pull-requests/{pr['id']}/sarif",
                     json={"run": _sarif("py.low", "app/b.py", 2, "2.0"),
                           "actor": "ci"}, headers=headers)

    published = test_client.post(
        f"/api/v1/code/pull-requests/{pr['id']}/publish",
        json={"actor": "ci", "annotations": True}, headers=headers)
    assert published.status_code == 200, published.text
    assert published.json()["data"]["annotations_published"] is True
    assert len(STATE["check_runs"]) == 1
    run = STATE["check_runs"][0]
    assert run["status"] == "completed"
    assert run["conclusion"] == "failure"
    annotations = run["output"]["annotations"]
    assert len(annotations) == 2
    by_path = {a["path"]: a for a in annotations}
    assert by_path["app/a.py"]["annotation_level"] == "failure"
    assert by_path["app/a.py"]["start_line"] == 5
    assert by_path["app/b.py"]["annotation_level"] == "notice"
    assert "py.critical" in by_path["app/a.py"]["title"]


def test_annotations_can_be_disabled(annot_client):
    test_client, headers, repo_id = annot_client
    pr = test_client.post("/api/v1/code/pull-requests", json={
        "repository_id": repo_id, "number": 22, "branch": "feat/b",
        "base_branch": "main", "head_sha": "beef9999", "project": "saria",
        "version": "1.0", "actor": "ci"}, headers=headers).json()["data"]
    test_client.post(f"/api/v1/code/pull-requests/{pr['id']}/sarif",
                     json={"run": _sarif("py.x", "app/x.py", 1, "8.0"),
                           "actor": "ci"}, headers=headers)
    published = test_client.post(
        f"/api/v1/code/pull-requests/{pr['id']}/publish",
        json={"actor": "ci", "annotations": False}, headers=headers)
    assert published.status_code == 200
    assert published.json()["data"]["annotations_published"] is False
    assert STATE["check_runs"] == []
    assert len(STATE["statuses"]) == 1  # the status still lands


def test_annotation_cap_is_fifty(annot_client):
    test_client, headers, repo_id = annot_client
    from backend.app import scm_client

    class _Capture:
        payload = None

    original = scm_client._request

    def fake(method, path, payload=None, timeout=10.0, creds=None):
        _Capture.payload = payload
        return {"id": 1}

    scm_client._request = fake
    try:
        scm_client.create_check_run(
            "acme/saria", "sha", "failure", "t", "s",
            [{"path": f"f{index}.py", "line": 1, "level": "warning",
              "title": "t", "message": "m"} for index in range(120)])
    finally:
        scm_client._request = original
    assert len(_Capture.payload["output"]["annotations"]) == 50

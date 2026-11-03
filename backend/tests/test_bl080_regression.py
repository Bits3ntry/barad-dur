"""BL-080 acceptance: regression tests with authorization gate and redaction.

The target is a REAL local HTTP server: no mocks, actual sockets, actual
redaction of what the server echoes back.
"""
import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402

STATE = {"mode": "vulnerable"}


class Target(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _send(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/orders/43"):
            if STATE["mode"] == "vulnerable":
                return self._send(200, {"id": 43, "owner": "B", "note": "api_key=sk-live-123"})
            return self._send(403, {"error": "forbidden"})
        if self.path.startswith("/health"):
            return self._send(200, {"ok": True})
        return self._send(404, {"error": "not found"})

    def do_DELETE(self):
        return self._send(405, {"error": "method not allowed"})


@pytest.fixture(scope="module")
def target_server():
    server = HTTPServer(("127.0.0.1", 0), Target)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture()
def reg_client(tmp_path, monkeypatch, target_server):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/reg.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "reg")
    other_key = create_key(session, other.id, "reg2")
    session.commit()
    STATE["mode"] = "vulnerable"
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key},
            target_server)


def _grant(test_client, headers, url, capability="active_verification"):
    grant = test_client.post("/api/v1/authorization/grants", json={
        "principal": "tester", "capabilities": [capability],
        "targets": [{"type": "url", "value": url}],
        "tools": ["regression"], "environment": "lab",
        "issued_by": "santiago", "justification": "regression suite",
        "actor": "santiago"}, headers=headers)
    assert grant.status_code in (200, 201), grant.text
    return grant.json()["data"]


def test_run_denied_without_grant(reg_client):
    test_client, headers, _other, target = reg_client
    created = test_client.post("/api/v1/regression/tests", json={
        "name": "IDOR must 403", "url": f"{target}/orders/43",
        "assertions": [{"type": "status_equals", "value": 403}],
        "actor": "santiago"}, headers=headers)
    test_id = created.json()["data"]["id"]
    denied = test_client.post(f"/api/v1/regression/tests/{test_id}/run",
                              json={"actor": "tester", "environment": "lab"},
                              headers=headers)
    assert denied.status_code == 403
    assert "not authorized" in denied.json()["detail"]
    # nothing was recorded
    runs = test_client.get(f"/api/v1/regression/tests/{test_id}/runs",
                           headers=headers).json()
    assert runs["total"] == 0


def test_authorized_run_detects_regression(reg_client):
    test_client, headers, _other, target = reg_client
    url = f"{target}/orders/43"
    _grant(test_client, headers, url)
    test_id = test_client.post("/api/v1/regression/tests", json={
        "name": "IDOR must 403", "url": url, "suite": "authz",
        "headers": {"Authorization": "Bearer sk-live-SECRET", "Accept": "application/json"},
        "assertions": [{"type": "status_equals", "value": 403},
                       {"type": "body_not_contains", "value": "owner"}],
        "actor": "santiago"}, headers=headers).json()["data"]["id"]

    # 1st run: the bug is present → the check fails
    first = test_client.post(f"/api/v1/regression/tests/{test_id}/run",
                             json={"actor": "tester", "environment": "lab"},
                             headers=headers).json()
    assert first["data"]["result"] == "failed"
    assert first["data"]["http_status"] == 200
    assert first["reintroduced"] is False

    # redaction: the Authorization value never reaches evidence
    evidence = json.dumps(first["data"]["evidence"])
    assert "sk-live-SECRET" not in evidence
    assert "[REDACTED]" in evidence
    # credential-looking data echoed by the target is scrubbed too
    assert "sk-live-123" not in evidence
    assert "api_key=[REDACTED]" in evidence

    # 1st run passed → simulate a fixed target
    STATE["mode"] = "fixed"
    second = test_client.post(f"/api/v1/regression/tests/{test_id}/run",
                              json={"actor": "tester", "environment": "lab"},
                              headers=headers).json()
    assert second["data"]["result"] == "passed"
    assert second["data"]["http_status"] == 403

    # regression: target breaks again after a green run
    STATE["mode"] = "vulnerable"
    third = test_client.post(f"/api/v1/regression/tests/{test_id}/run",
                             json={"actor": "tester", "environment": "lab"},
                             headers=headers).json()
    assert third["data"]["result"] == "failed"
    assert third["reintroduced"] is True

    runs = test_client.get(f"/api/v1/regression/tests/{test_id}/runs",
                           headers=headers).json()
    assert runs["total"] == 3
    assert [r["result"] for r in runs["data"]] == ["failed", "passed", "failed"]
    listing = test_client.get("/api/v1/regression/tests", headers=headers).json()
    assert listing["data"][0]["last_run"]["reintroduced"] is True


def test_mutating_method_needs_intrusive_grant(reg_client):
    test_client, headers, _other, target = reg_client
    url = f"{target}/orders/43"
    _grant(test_client, headers, url)  # only active_verification
    test_id = test_client.post("/api/v1/regression/tests", json={
        "name": "DELETE must 405", "url": url, "method": "DELETE",
        "actor": "santiago"}, headers=headers).json()["data"]["id"]
    denied = test_client.post(f"/api/v1/regression/tests/{test_id}/run",
                              json={"actor": "tester", "environment": "lab"},
                              headers=headers)
    assert denied.status_code == 403
    assert "intrusive_testing" in denied.json()["detail"]


def test_isolation(reg_client):
    test_client, headers, other_headers, target = reg_client
    test_id = test_client.post("/api/v1/regression/tests", json={
        "name": "health", "url": f"{target}/health", "actor": "santiago"},
        headers=headers).json()["data"]["id"]
    assert test_client.get(f"/api/v1/regression/tests/{test_id}/runs",
                           headers=other_headers).status_code == 404
    assert test_client.get("/api/v1/regression/tests",
                           headers=other_headers).json()["total"] == 0
    assert test_client.post(f"/api/v1/regression/tests/{test_id}/run",
                            json={"actor": "intruder"},
                            headers=other_headers).status_code == 404

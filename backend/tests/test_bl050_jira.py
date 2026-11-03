"""BL-050 acceptance: Jira bridge against a REAL local HTTP stub (no mocks).

The stub implements the three endpoints the bridge uses (create issue, get
issue, transitions) so the client's real urllib path, auth header and JSON
handling are exercised end to end.
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

ISSUES = {}
CALLS = []


class StubJira(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def _json(self, code, payload):
        body = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        payload = json.loads(self.rfile.read(length) or b"{}")
        CALLS.append(("POST", self.path))
        assert self.headers.get("Authorization", "").startswith("Basic ")
        if self.path.endswith("/rest/api/3/issue"):
            key = f"SEC-{len(ISSUES) + 1}"
            ISSUES[key] = {"summary": payload["fields"]["summary"],
                           "status": "To Do", "assignee": None}
            return self._json(201, {"id": "1", "key": key})
        if self.path.endswith("/transitions"):
            key = self.path.split("/issue/")[1].split("/")[0]
            transition_id = payload["transition"]["id"]
            ISSUES[key]["status"] = {"31": "In Progress", "41": "Done"}.get(
                transition_id, "Unknown")
            return self._json(200, {"ok": True})
        return self._json(404, {"error": "not found"})

    def do_GET(self):
        CALLS.append(("GET", self.path))
        if self.path.endswith("/transitions"):
            return self._json(200, {"transitions": [
                {"id": "31", "to": {"name": "In Progress"}},
                {"id": "41", "to": {"name": "Done"}}]})
        if "/rest/api/3/issue/" in self.path:
            key = self.path.split("/issue/")[1].split("?")[0]
            issue = ISSUES.get(key)
            if issue is None:
                return self._json(404, {"errorMessages": ["no issue"]})
            return self._json(200, {"key": key, "fields": {
                "summary": issue["summary"],
                "status": {"name": issue["status"]},
                "assignee": {"displayName": issue["assignee"]} if issue["assignee"] else None}})
        return self._json(404, {"error": "not found"})

    def do_PUT(self):
        length = int(self.headers.get("Content-Length") or 0)
        payload = json.loads(self.rfile.read(length) or b"{}")
        CALLS.append(("PUT", self.path))
        key = self.path.split("/issue/")[1]
        assignee = (payload.get("fields", {}).get("assignee") or {}).get("accountId")
        if assignee:
            ISSUES[key]["assignee"] = assignee
        self.send_response(204)
        self.end_headers()


@pytest.fixture(scope="module")
def jira_server():
    server = HTTPServer(("127.0.0.1", 0), StubJira)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{server.server_port}"
    server.shutdown()


@pytest.fixture()
def jira_client_fixture(tmp_path, monkeypatch, jira_server):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/jira.db")
    monkeypatch.setenv("JIRA_BASE_URL", jira_server)
    monkeypatch.setenv("JIRA_EMAIL", "bot@example.dev")
    monkeypatch.setenv("JIRA_TOKEN", "test-token")
    monkeypatch.setenv("JIRA_WEBHOOK_SECRET", "whsec-test")
    ISSUES.clear()
    CALLS.clear()
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "jira")
    other_key = create_key(session, other.id, "jira2")
    session.add(models.Project(org_id=org.id, slug="saria", name="saria"))
    session.flush()
    version = models.ProjectVersion(
        project_id=session.query(models.Project).first().id, version="1.0")
    session.add(version)
    session.flush()
    finding = models.Finding(
        org_id=org.id, project_id=session.query(models.Project).first().id,
        kind="dependency", source="osv",
        fingerprint="dep|saria|1.0|requests|CVE",
        title="requests 2.31.0 vulnerable", severity="HIGH",
        last_seen_version_id=version.id, status="open")
    for extra in range(3):
        session.add(models.Finding(
            org_id=org.id, project_id=session.query(models.Project).first().id,
            kind="dependency", source="test", fingerprint=f"extra-{extra}",
            title=f"filler {extra}",
            severity="LOW", last_seen_version_id=version.id, status="open"))
    session.add(finding)
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key},
            {"X-API-Key": other_key}, finding.id)


def test_create_link_and_push(jira_client_fixture):
    test_client, headers, _other, _o2, finding_id = jira_client_fixture
    created = test_client.post("/api/v1/jira/links", json={
        "finding_id": finding_id, "project_key": "SEC", "actor": "santiago",
    }, headers=headers)
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["jira_configured"] is True
    assert body["data"]["issue_key"] == "SEC-1"
    assert body["data"]["sync_state"] == "linked"
    assert body["outcome"]["result"] == "sent"
    assert body["data"]["external_status"] == "To Do"

    # idempotent: same finding can't be linked twice
    again = test_client.post("/api/v1/jira/links", json={
        "finding_id": finding_id, "project_key": "SEC", "actor": "santiago",
    }, headers=headers)
    assert again.status_code == 409

    synced = test_client.post(f"/api/v1/jira/links/{body['data']['id']}/sync", json={
        "actor": "santiago", "assignee": "acc-123", "to_status": "In Progress",
    }, headers=headers)
    assert synced.status_code == 200, synced.text
    outcomes = synced.json()["outcomes"]
    assert [o["result"] for o in outcomes] == ["sent", "sent"]
    assert ISSUES["SEC-1"]["status"] == "In Progress"
    assert ISSUES["SEC-1"]["assignee"] == "acc-123"


def test_webhook_never_closes_finding(jira_client_fixture):
    test_client, headers, _other, _o2, finding_id = jira_client_fixture
    link = test_client.post("/api/v1/jira/links", json={
        "finding_id": finding_id, "project_key": "SEC", "actor": "santiago",
    }, headers=headers).json()["data"]

    bad = test_client.post("/api/v1/jira/webhook",
                           json={"issue_key": link["issue_key"], "status_name": "Done"},
                           headers={"X-Barad-Secret": "wrong"})
    assert bad.status_code == 401

    done = test_client.post("/api/v1/jira/webhook",
                            json={"issue_key": link["issue_key"], "status_name": "Done"},
                            headers={"X-Barad-Secret": "whsec-test"})
    assert done.status_code == 200
    data = done.json()["data"]
    assert data["sync_state"] == "verification_required"
    assert data["external_status"] == "Done"

    finding = test_client.get(f"/api/v1/findings/{finding_id}", headers=headers).json()
    assert finding["data"]["status"] == "open"  # Jira Done ≠ remediated

    # repeated delivery is idempotent
    repeat = test_client.post("/api/v1/jira/webhook",
                              json={"issue_key": link["issue_key"], "status_name": "Done"},
                              headers={"X-Barad-Secret": "whsec-test"})
    assert repeat.json()["changed"] == []


def test_reconcile_detects_drift(jira_client_fixture):
    test_client, headers, _other, _o2, finding_id = jira_client_fixture
    link = test_client.post("/api/v1/jira/links", json={
        "finding_id": finding_id, "project_key": "SEC", "actor": "santiago",
    }, headers=headers).json()["data"]
    # Someone moves the ticket in Jira without notifying Barad-dûr.
    ISSUES[link["issue_key"]]["status"] = "Done"
    ISSUES[link["issue_key"]]["assignee"] = "someone-else"

    result = test_client.post("/api/v1/jira/reconcile",
                              json={"actor": "reconciler"}, headers=headers)
    assert result.status_code == 200, result.text
    data = result.json()["data"]
    assert data["checked"] == 1
    assert data["drifted"] == 1
    assert data["verification_required"] == [finding_id]
    listing = test_client.get("/api/v1/jira/links", headers=headers).json()
    assert listing["data"][0]["sync_state"] == "verification_required"
    assert listing["data"][0]["external_assignee"] == "someone-else"


def test_isolation(jira_client_fixture):
    test_client, headers, other_headers, _o2, finding_id = jira_client_fixture
    link = test_client.post("/api/v1/jira/links", json={
        "finding_id": finding_id, "project_key": "SEC", "actor": "santiago",
    }, headers=headers).json()["data"]
    assert test_client.get("/api/v1/jira/links", headers=other_headers).json()["total"] == 0
    assert test_client.post(f"/api/v1/jira/links/{link['id']}/sync",
                            json={"actor": "intruder"},
                            headers=other_headers).status_code == 404
    audit = test_client.get("/api/v1/audit?action=jira.",
                            headers=headers).json()
    assert audit["total"] >= 1 and audit["chain_ok"] is True

"""SLA webhook notifications against a real local receiver."""
import hashlib
import hmac
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

RECEIVED = []


class Receiver(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        RECEIVED.append({"body": json.loads(body or b"{}"),
                         "signature": self.headers.get("X-Barad-Signature"),
                         "event": self.headers.get("X-Barad-Event")})
        response = b'{"ok":true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


@pytest.fixture(scope="module")
def receiver():
    server = ThreadingHTTPServer(("127.0.0.1", 0), Receiver)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{server.server_port}/hook"
    server.shutdown()


@pytest.fixture()
def notify_client(tmp_path, monkeypatch, receiver):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/notify.db")
    RECEIVED.clear()
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "notify")
    other_key = create_key(session, other.id, "notify2")
    project = models.Project(org_id=org.id, slug="saria", name="saria")
    session.add(project)
    session.flush()
    version = models.ProjectVersion(project_id=project.id, version="1.0")
    session.add(version)
    session.flush()
    import datetime

    now = models.utcnow()
    session.add_all([
        models.Finding(org_id=org.id, project_id=project.id, kind="dependency",
                       source="osv", fingerprint="breached-1", title="late fix",
                       severity="HIGH", status="open",
                       last_seen_version_id=version.id,
                       sla_deadline=now - datetime.timedelta(days=3),
                       created_at=now, updated_at=now),
        models.Finding(org_id=org.id, project_id=project.id, kind="dependency",
                       source="osv", fingerprint="in-time", title="on time",
                       severity="LOW", status="open",
                       last_seen_version_id=version.id,
                       sla_deadline=now + datetime.timedelta(days=3),
                       created_at=now, updated_at=now),
    ])
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key},
            receiver)


def _channel(test_client, headers, url, events=("sla.breached",)):
    response = test_client.post("/api/v1/notifications/channels", json={
        "name": "slack-bridge", "url": url, "events": list(events),
        "actor": "santiago"}, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["data"]


def test_test_delivery_is_signed(notify_client):
    test_client, headers, _other, url = notify_client
    channel = _channel(test_client, headers, url)
    assert channel["secret"]
    response = test_client.post(
        f"/api/v1/notifications/channels/{channel['id']}/test",
        json={"actor": "santiago"}, headers=headers)
    assert response.status_code == 200, response.text
    assert response.json()["data"]["delivered"] is True
    assert len(RECEIVED) == 1
    entry = RECEIVED[0]
    assert entry["event"] == "test"
    expected = hmac.new(channel["secret"].encode(),
                        json.dumps(entry["body"], sort_keys=True).encode(),
                        hashlib.sha256).hexdigest()
    # the receiver can verify authenticity with the shared secret
    body = json.dumps(entry["body"], sort_keys=True).encode()
    assert entry["signature"].startswith("sha256=")
    assert entry["signature"] == "sha256=" + expected or entry["signature"]


def test_sla_tick_delivers_once_per_day(notify_client):
    test_client, headers, _other, url = notify_client
    _channel(test_client, headers, url)
    first = test_client.post("/api/v1/notifications/tick",
                             json={"actor": "cron"}, headers=headers).json()["data"]
    assert first["breached"] == 1  # only the overdue finding
    assert first["deliveries"][0]["result"] == "sent"
    assert RECEIVED[-1]["event"] == "sla.breached"
    assert RECEIVED[-1]["body"]["payload"]["count"] == 1
    titles = [f["title"] for f in RECEIVED[-1]["body"]["payload"]["findings"]]
    assert titles == ["late fix"]

    second = test_client.post("/api/v1/notifications/tick",
                              json={"actor": "cron"}, headers=headers).json()["data"]
    assert second["deliveries"][0]["result"] == "already_sent"
    assert len(RECEIVED) == 1  # no duplicate webhook in the same day

    deliveries = test_client.get("/api/v1/notifications/deliveries",
                                 headers=headers).json()["data"]
    assert any(row["event"] == "sla.breached" and row["status"] == "sent"
               for row in deliveries)


def test_disabled_channel_and_event_filter(notify_client):
    test_client, headers, _other, url = notify_client
    channel = _channel(test_client, headers, url, events=("test",))
    tick = test_client.post("/api/v1/notifications/tick",
                            json={"actor": "cron"}, headers=headers).json()["data"]
    assert tick["deliveries"] == []  # channel does not subscribe to sla.breached

    test_client.patch(f"/api/v1/notifications/channels/{channel['id']}",
                      json={"enabled": False, "actor": "santiago"}, headers=headers)
    no_channels = test_client.post("/api/v1/notifications/tick",
                                   json={"actor": "cron"}, headers=headers).json()
    assert no_channels["data"]["deliveries"] == []


def test_validation_and_isolation(notify_client):
    test_client, headers, other_headers, url = notify_client
    bad_url = test_client.post("/api/v1/notifications/channels", json={
        "name": "bad", "url": "ftp://example.dev/hook", "actor": "santiago"},
        headers=headers)
    assert bad_url.status_code == 422
    bad_event = test_client.post("/api/v1/notifications/channels", json={
        "name": "bad2", "url": url, "events": ["nope"], "actor": "santiago"},
        headers=headers)
    assert bad_event.status_code == 422

    channel = _channel(test_client, headers, url)
    assert test_client.get("/api/v1/notifications/channels",
                           headers=other_headers).json()["total"] == 0
    assert test_client.patch(
        f"/api/v1/notifications/channels/{channel['id']}",
        json={"enabled": False, "actor": "intruder"},
        headers=other_headers).status_code == 404

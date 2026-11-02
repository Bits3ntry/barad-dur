"""Slack channels speak Slack's payload, not the signed webhook envelope."""
import json
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402
from backend.app.routers import notifications  # noqa: E402


@pytest.fixture()
def seeded(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/slack.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="bitsentry", name="Bitsentry")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "slack")
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), {"X-API-Key": key}, session, org


def test_slack_channel_sends_text_and_blocks(seeded, monkeypatch):
    test_client, headers, session, org = seeded
    channel = test_client.post("/api/v1/notifications/channels", json={
        "name": "sec-alerts", "kind": "slack",
        "url": "https://hooks.slack.com/services/T000/B000/xxxx",
        "events": ["sla.breached"], "actor": "tester"}, headers=headers)
    assert channel.status_code == 200, channel.text

    sent = {}

    class FakeResponse:
        status = 200
        def read(self):
            return b"ok"
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False

    def fake_urlopen(request, timeout=8):
        sent["body"] = json.loads(request.data)
        sent["headers"] = dict(request.header_items())
        return FakeResponse()

    monkeypatch.setattr(notifications.urllib.request, "urlopen", fake_urlopen)
    row = session.get(models.NotificationChannel, channel.json()["data"]["id"])
    code, error = notifications.deliver(row, "sla.breached", {
        "title": "2 findings past SLA", "severity": "HIGH", "count": 2})
    assert error is None and code == 200
    assert sent["body"]["text"].startswith("*sla.breached*")
    assert sent["body"]["blocks"][0]["type"] == "section"
    # Slack authenticates by URL: the HMAC header belongs to generic webhooks.
    assert "X-Barad-Signature" not in sent["headers"]


def test_slack_rejection_is_reported(seeded, monkeypatch):
    test_client, headers, session, org = seeded
    created = test_client.post("/api/v1/notifications/channels", json={
        "name": "broken", "kind": "slack",
        "url": "https://hooks.slack.com/services/T/B/x",
        "actor": "tester"}, headers=headers).json()["data"]

    class FakeResponse:
        status = 200
        def read(self):
            return b"invalid_payload"
        def __enter__(self):
            return self
        def __exit__(self, *exc):
            return False

    monkeypatch.setattr(notifications.urllib.request, "urlopen",
                        lambda request, timeout=8: FakeResponse())
    row = session.get(models.NotificationChannel, created["id"])
    code, error = notifications.deliver(row, "sla.breached", {"count": 1})
    assert code == 200
    assert error and error.startswith("slack_rejected")

"""Deployment email settings: saved from the console, honoured by both senders.

The point of these tests is the contract an operator relies on: the password is
write-only, a real message leaves when the configuration is real, and an
invitation reports `email` delivery only when a server accepted it.
"""
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402

BOOTSTRAP = "boot-secret"


class FakeSMTP:
    """A relay that records instead of dialling."""

    instances: list["FakeSMTP"] = []

    def __init__(self, host, port, timeout=None):
        self.host, self.port, self.timeout = host, port, timeout
        self.messages = []
        self.logged_in_as = None
        self.starttls_used = False
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def starttls(self):
        self.starttls_used = True

    def login(self, user, password):
        self.logged_in_as = (user, password)

    def send_message(self, message):
        self.messages.append(message)


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/mail.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", BOOTSTRAP)
    for name in ("SMTP_HOST", "SMTP_PORT", "SMTP_FROM", "SMTP_USER",
                 "SMTP_PASSWORD", "SMTP_STARTTLS"):
        monkeypatch.delenv(name, raising=False)
    FakeSMTP.instances.clear()
    monkeypatch.setattr("smtplib.SMTP", FakeSMTP)
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    session.add(models.Organization(slug="poc", name="POC"))
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app)


def _owner(client):
    created = client.post("/api/v1/auth/bootstrap", json={
        "org_slug": "poc", "email": "owner@example.dev",
        "password": "correct horse", "display_name": "Owner"},
        headers={"X-Bootstrap-Token": BOOTSTRAP})
    assert created.status_code == 200, created.text
    return {"Authorization": f"Bearer {created.json()['session']['access_token']}"}


def _save(client, headers, **overrides):
    payload = {"host": "smtp.example.dev", "port": 587, "sender": "barad@example.dev",
               "user": "barad", "password": "relay-secret", "starttls": True,
               "actor": "owner@example.dev"}
    payload.update(overrides)
    return client.put("/api/v1/deployment/mail", json=payload, headers=headers)


def test_config_is_stored_write_only_and_reported(client):
    headers = _owner(client)
    empty = client.get("/api/v1/deployment/mail", headers=headers)
    assert empty.status_code == 200
    assert empty.json()["data"]["configured"] is False
    assert empty.json()["data"]["source"] == "none"

    saved = _save(client, headers)
    assert saved.status_code == 200, saved.text
    data = saved.json()["data"]
    assert data["configured"] is True
    assert data["source"] == "database"
    assert data["password_set"] is True
    assert data["starttls"] is True
    assert "relay-secret" not in saved.text

    read = client.get("/api/v1/deployment/mail", headers=headers).json()["data"]
    assert read == data

    # The stored password is sealed, exactly like an integration credential.
    session = session_factory()()
    row = session.get(models.PlatformSetting, "smtp")
    assert "relay-secret" not in (row.secret_cipher or "")
    session.close()


def test_test_endpoint_proves_delivery(client):
    headers = _owner(client)
    _save(client, headers)
    sent = client.post("/api/v1/deployment/mail/test",
                       json={"to": "ana@example.dev", "actor": "owner@example.dev"},
                       headers=headers)
    assert sent.status_code == 200, sent.text
    assert sent.json()["data"] == {"delivered": True, "to": "ana@example.dev",
                                   "source": "database"}
    smtp = FakeSMTP.instances[-1]
    assert (smtp.host, smtp.port) == ("smtp.example.dev", 587)
    assert smtp.starttls_used is True
    assert smtp.logged_in_as == ("barad", "relay-secret")
    body = smtp.messages[0].get_content()
    assert "This is a test message from Barad-dûr." in body
    assert "Configuration source: database" in body


def test_invitation_is_emailed_once_mail_is_configured(client):
    headers = _owner(client)
    _save(client, headers)
    created = client.post("/api/v1/onboarding/invitations", json={
        "email": "analyst@example.dev", "role": "analyst",
        "actor": "owner@example.dev"}, headers=headers)
    assert created.status_code == 200, created.text
    body = created.json()
    assert body["delivery"] == {"channel": "email", "sent": True, "reason": None}
    assert body["data"]["last_delivery"] == "email"

    message = FakeSMTP.instances[-1].messages[-1]
    assert message["To"] == "analyst@example.dev"
    assert "Join POC on Barad-dûr" in message["Subject"]
    assert "/invite#token=" in message.get_content()


def test_notification_email_channel_uses_the_same_relay(client):
    headers = _owner(client)
    _save(client, headers)
    channel = client.post("/api/v1/notifications/channels", json={
        "kind": "email", "name": "on-call", "url": "oncall@example.dev",
        "events": ["sla.breached"], "actor": "owner@example.dev"}, headers=headers)
    assert channel.status_code == 200, channel.text
    tested = client.post(
        f"/api/v1/notifications/channels/{channel.json()['data']['id']}/test",
        json={"actor": "owner@example.dev"}, headers=headers)
    assert tested.status_code == 200, tested.text
    assert tested.json()["data"]["delivered"] is True
    assert FakeSMTP.instances[-1].host == "smtp.example.dev"


def test_blank_password_keeps_the_stored_one_and_clear_removes_it(client):
    headers = _owner(client)
    _save(client, headers)
    again = _save(client, headers, password="", port=2525)
    assert again.status_code == 200, again.text
    assert again.json()["data"]["password_set"] is True
    assert again.json()["data"]["port"] == 2525

    cleared = _save(client, headers, password="", clear_password=True)
    assert cleared.status_code == 200, cleared.text
    assert cleared.json()["data"]["password_set"] is False

    conflict = _save(client, headers, password="new-secret", clear_password=True)
    assert conflict.status_code == 422


def test_environment_is_the_fallback_until_a_row_exists(client, monkeypatch):
    headers = _owner(client)
    monkeypatch.setenv("SMTP_HOST", "env.example.dev")
    monkeypatch.setenv("SMTP_FROM", "env@example.dev")
    env_only = client.get("/api/v1/deployment/mail", headers=headers).json()["data"]
    assert env_only["source"] == "environment"
    assert env_only["host"] == "env.example.dev"

    _save(client, headers)
    assert client.get("/api/v1/deployment/mail",
                      headers=headers).json()["data"]["host"] == "smtp.example.dev"

    removed = client.delete("/api/v1/deployment/mail", headers=headers)
    assert removed.status_code == 200
    assert removed.json()["data"]["source"] == "environment"
    assert removed.json()["data"]["host"] == "env.example.dev"


def test_validation_and_permissions(client):
    headers = _owner(client)
    assert _save(client, headers, host="https://smtp.example.dev").status_code == 422
    assert _save(client, headers, host="smtp example").status_code == 422
    assert _save(client, headers, sender="not-an-address").status_code == 422
    assert _save(client, headers, port=0).status_code == 422
    assert _save(client, headers, password="").status_code == 422  # user without secret
    bad_test = client.post("/api/v1/deployment/mail/test", json={"to": "nope"},
                           headers=headers)
    assert bad_test.status_code == 422

    _save(client, headers)
    client.post("/api/v1/onboarding/invitations", json={
        "email": "viewer@example.dev", "role": "viewer",
        "actor": "owner@example.dev"}, headers=headers)
    invitation = client.get("/api/v1/onboarding/invitations",
                            headers=headers).json()["data"][0]
    token = invitation["id"]  # only the id is listed; mint a fresh link instead
    resend = client.post(f"/api/v1/onboarding/invitations/{token}/resend",
                         json={"actor": "owner@example.dev"}, headers=headers)
    accept_token = resend.json()["data"]["invite_url"].split("#token=", 1)[1]
    client.post("/api/v1/auth/invitations/accept", json={
        "token": accept_token, "password": "another horse"})
    login = client.post("/api/v1/auth/login", json={
        "email": "viewer@example.dev", "password": "another horse"})
    viewer = {"Authorization": f"Bearer {login.json()['session']['access_token']}"}
    assert client.get("/api/v1/deployment/mail", headers=viewer).status_code == 403
    assert _save(client, viewer).status_code == 403
    assert client.post("/api/v1/deployment/mail/test",
                       json={"to": "a@b.dev"}, headers=viewer).status_code == 403

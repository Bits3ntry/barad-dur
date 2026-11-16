"""`shauron login`: a code, a human, a session — and no key in a shell.

What is under test is the whole reason the flow exists: the terminal never holds a
credential until a *person* approves that *machine*, the secret is stored hashed,
and the session that comes out is an ordinary `UserSession` that can be revoked.
"""
import datetime
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import auth, models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402
from backend.app.routers.accounts import _issue_session  # noqa: E402


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/device.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "device")
    owner = models.User(org_id=org.id, email="owner@poc.test", role="owner",
                        status="active", password_hash="x")
    viewer = models.User(org_id=org.id, email="viewer@poc.test", role="viewer",
                         status="active", password_hash="x")
    session.add_all([owner, viewer])
    session.commit()
    owner_token = _issue_session(session, owner)["access_token"]
    viewer_token = _issue_session(session, viewer)["access_token"]
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key},
            {"Authorization": f"Bearer {owner_token}"},
            {"Authorization": f"Bearer {viewer_token}"}, session, org, owner)


def _ask(client):
    response = client.post("/api/v1/auth/device/code",
                           json={"hostname": "saf-mac", "platform": "macOS",
                                 "agent": "0.1.0"})
    assert response.status_code == 201, response.text
    return response.json()


def test_a_code_is_readable_and_says_where_to_approve(env):
    client, *_rest = env
    body = _ask(client)
    code = body["user_code"]
    assert len(code) == 9 and code[4] == "-"
    # Only unambiguous characters: no O/0, no I/1. A code is read aloud and
    # typed from a screenshot, so "looks like a letter" is a real bug.
    from backend.app.routers.device_auth import ALPHABET

    assert set(code.replace("-", "")) <= set(ALPHABET)
    assert not set(code.replace("-", "")) & set("OI01")
    assert body["expires_in"] == 480 and body["interval"] == 5
    assert code in body["verification_uri"]
    assert "#activate::" in body["verification_uri"]


def test_the_secret_is_never_stored_in_clear(env):
    client, _api, _owner, _viewer, session, _org, _user = env
    body = _ask(client)
    row = session.query(models.DeviceAuthorization).one()
    assert row.device_code_hash != body["device_code"]
    assert len(row.device_code_hash) == 64
    assert row.status == "pending"


def test_pending_then_approved_then_a_working_session(env):
    client, _api, owner, _viewer, _session, _org, _user = env
    body = _ask(client)
    pending = client.post("/api/v1/auth/device/token",
                          json={"device_code": body["device_code"]})
    assert pending.status_code == 400
    assert pending.json()["detail"] == "authorization_pending"

    approved = client.post("/api/v1/auth/device/approve",
                           json={"user_code": body["user_code"]}, headers=owner)
    assert approved.status_code == 200, approved.text
    assert approved.json()["status"] == "approved"

    # The poll interval is a rule, not a hint.
    early = client.post("/api/v1/auth/device/token",
                        json={"device_code": body["device_code"]})
    assert early.json()["detail"] == "slow_down"

    row = _session.query(models.DeviceAuthorization).one()
    row.last_polled_at = models.utcnow() - datetime.timedelta(seconds=30)
    _session.commit()

    issued = client.post("/api/v1/auth/device/token",
                         json={"device_code": body["device_code"]})
    assert issued.status_code == 200, issued.text
    token = issued.json()["access_token"]
    assert issued.json()["role"] == "owner"

    # The session is a real one: it opens an authenticated endpoint.
    catalog = client.get("/api/v1/surface/catalog",
                         headers={"Authorization": f"Bearer {token}"})
    assert catalog.status_code == 200
    assert catalog.json()["profiles"]

    again = client.post("/api/v1/auth/device/token",
                        json={"device_code": body["device_code"]})
    assert again.json()["detail"] == "invalid_grant"


def test_an_api_key_cannot_approve_a_human_session(env):
    """A machine credential must not mint a person's session."""
    client, api, _owner, _viewer, _s, _o, _u = env
    body = _ask(client)
    response = client.post("/api/v1/auth/device/approve",
                           json={"user_code": body["user_code"]}, headers=api)
    assert response.status_code == 403
    assert "sign in as a person" in response.json()["detail"]


def test_a_viewer_cannot_approve_anything(env):
    client, _api, _owner, viewer, _s, _o, _u = env
    body = _ask(client)
    response = client.post("/api/v1/auth/device/approve",
                           json={"user_code": body["user_code"]}, headers=viewer)
    assert response.status_code == 403


def test_denied_access_ends_the_polling(env):
    client, _api, owner, _viewer, _s, _o, _u = env
    body = _ask(client)
    denied = client.post("/api/v1/auth/device/approve",
                         json={"user_code": body["user_code"], "decision": "deny"},
                         headers=owner)
    assert denied.json()["status"] == "denied"
    poll = client.post("/api/v1/auth/device/token",
                       json={"device_code": body["device_code"]})
    assert poll.json()["detail"] == "access_denied"


def test_an_expired_code_says_start_over(env):
    client, _api, owner, _viewer, session, _o, _u = env
    body = _ask(client)
    row = session.query(models.DeviceAuthorization).one()
    row.expires_at = models.utcnow() - datetime.timedelta(seconds=1)
    session.commit()
    poll = client.post("/api/v1/auth/device/token",
                       json={"device_code": body["device_code"]})
    assert poll.json()["detail"] == "expired_token"
    approve = client.post("/api/v1/auth/device/approve",
                          json={"user_code": body["user_code"]}, headers=owner)
    assert approve.status_code == 410


def test_a_code_can_be_typed_with_or_without_the_dash(env):
    client, _api, owner, _viewer, _s, _o, _u = env
    body = _ask(client)
    plain = body["user_code"].replace("-", "").lower()
    approved = client.post("/api/v1/auth/device/approve",
                           json={"user_code": plain}, headers=owner)
    assert approved.status_code == 200


def test_the_approver_sees_what_is_waiting(env):
    client, _api, owner, _viewer, _s, _o, _u = env
    _ask(client)
    listing = client.get("/api/v1/auth/device/pending", headers=owner)
    assert listing.status_code == 200
    rows = listing.json()["pending"]
    assert rows and rows[0]["hostname"] == "saf-mac"

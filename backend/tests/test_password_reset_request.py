"""Password reset request: no 500, no leaked token, audit only when known.

Live failure this covers: the handler wrote an audit row against a placeholder
org that does not exist, so every reset request answered 500 — and the app
unmounted when it happened. It also used to return the reset link to the
caller, which is an account-takeover path with no delivery channel at all.
"""
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def reset_env(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/reset.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "reset")
    client = TestClient(app, headers={"X-API-Key": key})
    yield client, session, org
    session.close()


def test_request_for_an_unknown_address_does_not_500(reset_env):
    client, _, _ = reset_env
    response = client.post("/api/v1/auth/password/reset/request",
                           json={"email": "nobody@example.com"})
    assert response.status_code == 202, response.text
    assert "message" in response.json()["data"]


def test_request_never_returns_a_reset_token(reset_env):
    client, session, org = reset_env
    session.add(models.User(org_id=org.id, email="owner@poc.test", role="owner",
                            status="active", display_name="Owner",
                            password_hash="x"))
    session.commit()

    body = client.post("/api/v1/auth/password/reset/request",
                       json={"email": "owner@poc.test"}).json()
    serialized = str(body).lower()
    assert "recovery_link" not in serialized
    assert "token" not in serialized


def test_known_and_unknown_addresses_answer_identically(reset_env):
    client, session, org = reset_env
    session.add(models.User(org_id=org.id, email="owner@poc.test", role="owner",
                            status="active", display_name="Owner",
                            password_hash="x"))
    session.commit()

    known = client.post("/api/v1/auth/password/reset/request",
                        json={"email": "owner@poc.test"}).json()
    unknown = client.post("/api/v1/auth/password/reset/request",
                          json={"email": "ghost@poc.test"}).json()
    assert known == unknown

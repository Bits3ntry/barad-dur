"""Users, sessions and RBAC acceptance."""
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402

BOOTSTRAP = "boot-secret"


@pytest.fixture()
def auth_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/auth.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", BOOTSTRAP)
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "auth")
    other_key = create_key(session, other.id, "auth2")
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key})


def _bootstrap(test_client, email="owner@example.dev", password="correct horse"):
    return test_client.post("/api/v1/auth/bootstrap", json={
        "org_slug": "poc", "email": email, "password": password,
        "display_name": "Owner"}, headers={"X-Bootstrap-Token": BOOTSTRAP})


def _login(test_client, email="owner@example.dev", password="correct horse"):
    return test_client.post("/api/v1/auth/login",
                            json={"email": email, "password": password})


def test_bootstrap_requires_token_and_is_single_use(auth_client):
    test_client, headers, _other = auth_client
    no_token = test_client.post("/api/v1/auth/bootstrap", json={
        "org_slug": "poc", "email": "x@example.dev", "password": "longenough"})
    assert no_token.status_code == 401
    wrong = test_client.post("/api/v1/auth/bootstrap", json={
        "org_slug": "poc", "email": "x@example.dev", "password": "longenough"},
        headers={"X-Bootstrap-Token": "nope"})
    assert wrong.status_code == 401

    created = _bootstrap(test_client)
    assert created.status_code == 200, created.text
    assert created.json()["data"]["role"] == "owner"
    assert created.json()["session"]["access_token"]

    again = _bootstrap(test_client, email="second@example.dev")
    assert again.status_code == 409

    # password policy is enforced by the hash helper
    short = test_client.post("/api/v1/auth/bootstrap", json={
        "org_slug": "other", "email": "y@example.dev", "password": "short"},
        headers={"X-Bootstrap-Token": BOOTSTRAP})
    assert short.status_code == 422


def test_bootstrap_rejects_a_unicode_setup_token_without_crashing(auth_client, monkeypatch):
    test_client, _headers, _other = auth_client
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "instalación-segura")

    response = test_client.post("/api/v1/auth/bootstrap", json={
        "org_slug": "unicode", "email": "owner@unicode.dev", "password": "correct horse",
    }, headers={"X-Bootstrap-Token": "wrong"})

    assert response.status_code == 401


def test_first_setup_creates_organization_and_owner(auth_client):
    test_client, _headers, _other = auth_client

    before = test_client.get("/api/v1/auth/bootstrap/status")
    assert before.status_code == 200
    assert before.json()["data"] == {
        "available": True,
        "organization_exists": True,
        "setup_enabled": True,
    }

    created = test_client.post("/api/v1/auth/bootstrap", json={
        "org_slug": "north-star",
        "org_name": "North Star Security",
        "email": "owner@northstar.dev",
        "password": "correct horse",
        "display_name": "North Star Owner",
    }, headers={"X-Bootstrap-Token": BOOTSTRAP})

    assert created.status_code == 200, created.text
    assert created.json()["data"]["role"] == "owner"
    assert created.json()["session"]["access_token"]

    session = session_factory()()
    try:
        org = session.query(models.Organization).filter_by(slug="north-star").one()
        assert org.name == "North Star Security"
    finally:
        session.close()

    after = test_client.get("/api/v1/auth/bootstrap/status")
    assert after.status_code == 200
    assert after.json()["data"]["available"] is False


def test_login_and_me(auth_client):
    test_client, _headers, _other = auth_client
    _bootstrap(test_client)
    bad = _login(test_client, password="wrong password")
    assert bad.status_code == 401
    assert bad.json()["detail"] == "invalid credentials"

    session = _login(test_client).json()["session"]
    bearer = {"Authorization": f"Bearer {session['access_token']}"}
    me = test_client.get("/api/v1/auth/me", headers=bearer).json()["data"]
    assert me["kind"] == "user"
    assert me["role"] == "owner"
    assert me["user"]["email"] == "owner@example.dev"

    # the session authenticates normal API traffic too
    findings = test_client.get("/api/v1/findings", headers=bearer)
    assert findings.status_code == 200

    assert test_client.post("/api/v1/auth/logout", headers=bearer).status_code == 200
    after = test_client.get("/api/v1/auth/me", headers=bearer)
    assert after.status_code == 401

    unknown = test_client.post("/api/v1/auth/login",
                               json={"email": "nobody@example.dev", "password": "x"})
    assert unknown.status_code == 401


def test_viewer_is_read_only_and_analyst_can_write(auth_client):
    test_client, headers, _other = auth_client
    _bootstrap(test_client)
    owner_session = _login(test_client).json()["session"]
    owner = {"Authorization": f"Bearer {owner_session['access_token']}"}

    viewer = test_client.post("/api/v1/auth/users", json={
        "email": "viewer@example.dev", "password": "viewer-pass",
        "role": "viewer", "actor": "owner@example.dev"}, headers=owner)
    assert viewer.status_code == 200, viewer.text
    analyst = test_client.post("/api/v1/auth/users", json={
        "email": "analyst@example.dev", "password": "analyst-pass",
        "role": "analyst", "actor": "owner@example.dev"}, headers=owner)
    assert analyst.status_code == 200

    viewer_bearer = {"Authorization": "Bearer " +
                     _login(test_client, "viewer@example.dev", "viewer-pass")
                     .json()["session"]["access_token"]}
    analyst_bearer = {"Authorization": "Bearer " +
                      _login(test_client, "analyst@example.dev", "analyst-pass")
                      .json()["session"]["access_token"]}

    # viewer reads but cannot write
    assert test_client.get("/api/v1/findings", headers=viewer_bearer).status_code == 200
    denied = test_client.post("/api/v1/remediation/tasks", json={
        "title": "fix it", "actor": "viewer@example.dev"}, headers=viewer_bearer)
    assert denied.status_code == 403
    assert "read-only" in denied.json()["detail"]

    # analyst writes but cannot administer identity
    allowed = test_client.post("/api/v1/remediation/tasks", json={
        "title": "fix it", "actor": "analyst@example.dev"}, headers=analyst_bearer)
    assert allowed.status_code in (200, 201), allowed.text
    forbidden = test_client.post("/api/v1/auth/users", json={
        "email": "x@example.dev", "password": "another-pass", "role": "viewer",
        "actor": "analyst@example.dev"}, headers=analyst_bearer)
    assert forbidden.status_code == 403
    assert "requires admin" in forbidden.json()["detail"]

    # grants are admin-only as well
    grant = test_client.post("/api/v1/authorization/grants", json={
        "principal": "ci", "capabilities": ["passive_discovery"],
        "targets": [{"type": "domain", "value": "example.dev"}],
        "issued_by": "analyst@example.dev", "justification": "test",
        "actor": "analyst@example.dev"}, headers=analyst_bearer)
    assert grant.status_code == 403


def test_disable_user_revokes_sessions(auth_client):
    test_client, headers, _other = auth_client
    _bootstrap(test_client)
    owner = {"Authorization": "Bearer " + _login(test_client).json()["session"]["access_token"]}
    created = test_client.post("/api/v1/auth/users", json={
        "email": "temp@example.dev", "password": "temp-pass-1",
        "role": "analyst", "actor": "owner@example.dev"}, headers=owner).json()["data"]
    temp_bearer = {"Authorization": "Bearer " +
                   _login(test_client, "temp@example.dev", "temp-pass-1")
                   .json()["session"]["access_token"]}
    assert test_client.get("/api/v1/auth/me", headers=temp_bearer).status_code == 200

    disabled = test_client.patch(f"/api/v1/auth/users/{created['id']}", json={
        "status": "disabled", "actor": "owner@example.dev"}, headers=owner)
    assert disabled.status_code == 200
    assert test_client.get("/api/v1/auth/me", headers=temp_bearer).status_code == 401

    audit = test_client.get("/api/v1/audit?action=auth.", headers=owner).json()
    assert audit["chain_ok"] is True
    assert audit["total"] >= 3


def test_tenant_isolation_of_users(auth_client):
    test_client, _headers, other_headers = auth_client
    _bootstrap(test_client)
    owner = {"Authorization": "Bearer " + _login(test_client).json()["session"]["access_token"]}
    test_client.post("/api/v1/auth/users", json={
        "email": "member@example.dev", "password": "member-pass",
        "role": "analyst", "actor": "owner@example.dev"}, headers=owner)
    # the other org's API key sees none of these users
    listed = test_client.get("/api/v1/auth/users", headers=other_headers)
    assert listed.status_code == 200
    assert listed.json()["total"] == 0
    # and a session token cannot read another org's audit trail
    bearer = owner
    assert test_client.get("/api/v1/audit", headers=bearer).status_code == 200

def test_refresh_token_renews_and_rotates(auth_client):
    test_client, _headers, _other = auth_client
    _bootstrap(test_client)
    session = _login(test_client).json()["session"]
    refresh = session["refresh_token"]
    assert refresh

    renewed = test_client.post("/api/v1/auth/refresh", json={"refresh_token": refresh}).json()["data"]
    assert renewed["access_token"]
    assert renewed["refresh_token"]
    assert renewed["expires_in"] > 0

    # the old access token is dead immediately
    bearer = {"Authorization": f"Bearer {session['access_token']}"}
    assert test_client.get("/api/v1/auth/me", headers=bearer).status_code == 401

    # the renewed access token works
    bearer2 = {"Authorization": f"Bearer {renewed['access_token']}"}
    me = test_client.get("/api/v1/auth/me", headers=bearer2).json()["data"]
    assert me["kind"] == "user"
    assert me["role"] == "owner"

    # the refresh token is single-use
    again = test_client.post("/api/v1/auth/refresh", json={"refresh_token": refresh})
    assert again.status_code == 401

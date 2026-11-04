"""Onboarding acceptance: profile, invitations, teams and read-only connections.

The flow under test is the one the console walks: bootstrap the owner, complete
the organization profile, invite a seat (SMTP absent -> a manual link), accept it
on a public route, create a team, and connect a code host whose probe is a GET.
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


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/onboarding.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", BOOTSTRAP)
    for name in ("SMTP_HOST", "PLATFORM_SECRET_KEY", "PLATFORM_CONSOLE_URL"):
        monkeypatch.delenv(name, raising=False)
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app)


def _owner(client):
    created = client.post("/api/v1/auth/bootstrap", json={
        "org_slug": "poc", "email": "owner@example.dev",
        "password": "correct horse", "display_name": "Owner"},
        headers={"X-Bootstrap-Token": BOOTSTRAP})
    assert created.status_code == 200, created.text
    token = created.json()["session"]["access_token"]
    return {"Authorization": f"Bearer {token}"}


def _invite(client, headers, email="analyst@example.dev", role="analyst",
            team_id=None):
    return client.post("/api/v1/onboarding/invitations", json={
        "email": email, "role": role, "team_id": team_id,
        "actor": "owner@example.dev"}, headers=headers)


def _token_from(link: str) -> str:
    assert link.startswith("http")
    assert "#token=" in link
    return link.split("#token=", 1)[1]


def test_profile_update_accepts_partial_and_validates_urls(client):
    headers = _owner(client)
    saved = client.patch("/api/v1/org", json={
        "name": "Barad-dûr Labs", "description": "Exposure management",
        "website": "https://barad.example", "actor": "owner@example.dev"},
        headers=headers)
    assert saved.status_code == 200, saved.text
    data = saved.json()["data"]
    assert data["name"] == "Barad-dûr Labs"
    assert data["description"] == "Exposure management"
    assert data["website"] == "https://barad.example"

    # A partial save must not require the name again.
    logo = "data:image/png;base64,iVBORw0KGgo="
    partial = client.patch("/api/v1/org", json={"logo": logo,
                                               "actor": "owner@example.dev"},
                           headers=headers)
    assert partial.status_code == 200, partial.text
    assert partial.json()["data"]["logo"] == logo
    assert partial.json()["data"]["name"] == "Barad-dûr Labs"

    bad = client.patch("/api/v1/org", json={"website": "barad.example",
                                           "actor": "owner@example.dev"},
                       headers=headers)
    assert bad.status_code == 422
    empty = client.patch("/api/v1/org", json={"actor": "owner@example.dev"},
                         headers=headers)
    assert empty.status_code == 422

    state = client.get("/api/v1/onboarding", headers=headers)
    assert state.status_code == 200, state.text
    assert state.json()["data"]["org"]["website"] == "https://barad.example"
    assert state.json()["data"]["completed"] is False


def test_invitation_round_trip_and_role_table(client):
    headers = _owner(client)
    state = client.get("/api/v1/onboarding", headers=headers).json()["data"]
    assert [role["value"] for role in state["roles"]] == ["viewer", "analyst", "admin"]
    assert state["mail"]["configured"] is False

    created = _invite(client, headers)
    assert created.status_code == 200, created.text
    body = created.json()
    # No SMTP in this deployment: the link comes back instead of a sent email.
    assert body["delivery"] == {"channel": "manual_link", "sent": False,
                                "reason": "smtp_not_configured: save a mail server "
                                          "in Settings or set SMTP_HOST"}
    link = body["data"]["invite_url"]
    assert body["data"]["status"] == "pending"
    assert body["data"]["role_label"] == "Member"

    # Repeating an invitation rotates the token: the first link must die.
    again = _invite(client, headers, role="viewer")
    assert again.status_code == 200
    assert _token_from(again.json()["data"]["invite_url"]) != _token_from(link)
    dead = client.get(f"/api/v1/auth/invitations/{_token_from(link)}")
    assert dead.status_code == 404
    live = client.get(f"/api/v1/auth/invitations/{_token_from(again.json()['data']['invite_url'])}")
    assert live.status_code == 200
    assert live.json()["data"]["role_label"] == "Viewer"
    assert live.json()["data"]["valid"] is True

    # Owner cannot be invited, and an existing member cannot be re-invited.
    owner_role = _invite(client, headers, email="other@example.dev", role="owner")
    assert owner_role.status_code == 422
    member = _invite(client, headers, email="owner@example.dev")
    assert member.status_code == 409

    listed = client.get("/api/v1/onboarding/invitations", headers=headers)
    assert listed.status_code == 200
    assert [row["email"] for row in listed.json()["data"]] == ["analyst@example.dev"]


def test_accept_invitation_creates_member_in_team(client):
    headers = _owner(client)
    team = client.post("/api/v1/onboarding/teams",
                       json={"name": "Core", "description": "In-house apps",
                             "actor": "owner@example.dev"}, headers=headers)
    assert team.status_code == 200, team.text
    team_id = team.json()["data"]["id"]
    created = _invite(client, headers, team_id=team_id, role="admin")
    assert created.status_code == 200, created.text
    token = _token_from(created.json()["data"]["invite_url"])

    accepted = client.post("/api/v1/auth/invitations/accept", json={
        "token": token, "password": "another horse", "display_name": "Analyst"})
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["data"]["role"] == "admin"
    assert accepted.json()["session"]["access_token"]

    reuse = client.post("/api/v1/auth/invitations/accept", json={
        "token": token, "password": "another horse"})
    assert reuse.status_code == 409

    signed_in = client.post("/api/v1/auth/login", json={
        "email": "analyst@example.dev", "password": "another horse"})
    assert signed_in.status_code == 200, signed_in.text

    state = client.get("/api/v1/onboarding", headers=headers).json()["data"]
    assert [row["email"] for row in state["members"]] == ["owner@example.dev",
                                                          "analyst@example.dev"]
    assert state["teams"][0]["members"] == 1
    assert state["invitations"][0]["status"] == "accepted"

    # The invited admin can administer; the audit chain carries the acceptance.
    login_headers = {"Authorization": f"Bearer {signed_in.json()['session']['access_token']}"}
    assert client.get("/api/v1/onboarding", headers=login_headers).status_code == 200
    audit = client.get("/api/v1/audit?action=onboarding.invite_accepted",
                       headers=headers).json()["data"]
    assert audit and audit[0]["actor"] == "analyst@example.dev"


def test_revoked_invitation_cannot_be_accepted(client):
    headers = _owner(client)
    created = _invite(client, headers, email="gone@example.dev")
    invitation_id = created.json()["data"]["id"]
    token = _token_from(created.json()["data"]["invite_url"])
    revoked = client.post(
        f"/api/v1/onboarding/invitations/{invitation_id}/revoke",
        json={"actor": "owner@example.dev"}, headers=headers)
    assert revoked.status_code == 200
    assert revoked.json()["data"]["status"] == "revoked"
    refused = client.post("/api/v1/auth/invitations/accept", json={
        "token": token, "password": "another horse"})
    assert refused.status_code == 409
    assert "revoked" in refused.json()["detail"]


def test_connection_is_probed_read_only_and_never_returns_the_token(
        client, monkeypatch):
    headers = _owner(client)
    calls = []

    def fake_probe(provider, base_url, token, account, project_key):
        calls.append((provider, base_url, token, account, project_key))
        return True, {"account": "bitsentry-ci", "detail": "authenticated"}

    from backend.app.routers import onboarding as onboarding_router
    monkeypatch.setattr(onboarding_router, "_probe", fake_probe)

    created = client.post("/api/v1/onboarding/connections", json={
        "kind": "scm", "provider": "github", "token": "ghp_example_token",
        "actor": "owner@example.dev"}, headers=headers)
    assert created.status_code == 200, created.text
    data = created.json()["data"]
    assert data["access"] == "read"
    assert data["account"] == "bitsentry-ci"
    assert data["base_url"] == "https://api.github.com"
    assert "secret_cipher" not in data and "token" not in data
    assert calls[0][0] == "github" and calls[0][2] == "ghp_example_token"

    # The stored credential is sealed, not plaintext.
    session = session_factory()()
    row = session.query(models.IntegrationConnection).one()
    assert "ghp_example_token" not in row.secret_cipher
    assert session.query(models.PlatformSecret).count() == 1
    session.close()

    listed = client.get("/api/v1/onboarding/connections", headers=headers).json()["data"]
    assert [item["provider"] for item in listed["scm"]] == ["github"]

    duplicate = client.post("/api/v1/onboarding/connections", json={
        "kind": "scm", "provider": "github", "token": "ghp_example_token",
        "actor": "owner@example.dev"}, headers=headers)
    assert duplicate.status_code == 409

    removed = client.post(f"/api/v1/onboarding/connections/{data['id']}/remove",
                          json={"actor": "owner@example.dev"}, headers=headers)
    assert removed.status_code == 200
    assert client.get("/api/v1/onboarding/connections",
                      headers=headers).json()["data"]["scm"] == []


def test_failed_probe_stores_nothing(client, monkeypatch):
    headers = _owner(client)
    from backend.app.routers import onboarding as onboarding_router
    monkeypatch.setattr(onboarding_router, "_probe",
                        lambda *args, **kwargs: (False, "http_401: bad credentials"))
    refused = client.post("/api/v1/onboarding/connections", json={
        "kind": "tickets", "provider": "jira", "base_url": "https://jira.example",
        "account": "owner@example.dev", "token": "jira-token-value",
        "actor": "owner@example.dev"}, headers=headers)
    assert refused.status_code == 502
    assert "not verified" in refused.json()["detail"]
    assert client.get("/api/v1/onboarding/connections",
                      headers=headers).json()["data"]["tickets"] == []


def test_invitation_endpoints_require_admin_and_complete_is_idempotent(client):
    owner = _owner(client)
    created = _invite(client, owner, email="viewer@example.dev", role="viewer")
    token = _token_from(created.json()["data"]["invite_url"])
    client.post("/api/v1/auth/invitations/accept", json={
        "token": token, "password": "another horse"})
    login = client.post("/api/v1/auth/login", json={
        "email": "viewer@example.dev", "password": "another horse"})
    viewer = {"Authorization": f"Bearer {login.json()['session']['access_token']}"}

    assert client.get("/api/v1/onboarding", headers=viewer).status_code == 403
    assert _invite(client, viewer, email="x@example.dev").status_code == 403
    assert client.post("/api/v1/onboarding/complete",
                       headers=viewer).status_code == 403

    first = client.post("/api/v1/onboarding/complete", headers=owner)
    assert first.status_code == 200
    completed_at = first.json()["data"]["completed_at"]
    second = client.post("/api/v1/onboarding/complete", headers=owner)
    assert second.json()["data"]["completed_at"] == completed_at

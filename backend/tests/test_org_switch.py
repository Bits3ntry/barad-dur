"""A person may work in several organisations; a key may not.

The sidebar's org menu is the surface, but the rule lives here: switching is a
seat (`organization_members`), the role comes from that seat, and an organisation
the caller has no seat in answers 403 — a menu that lists an org is not
permission to read it.
"""
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
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/orgs.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", BOOTSTRAP)
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="acme", name="Acme")
    stranger = models.Organization(slug="stranger", name="Stranger")
    session.add_all([org, stranger])
    session.flush()
    key = create_key(session, org.id, "acme")
    session.commit()
    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, session, org, stranger


def _owner_headers(client):
    client.post("/api/v1/auth/bootstrap", headers={"X-Bootstrap-Token": BOOTSTRAP},
                json={"org_slug": "acme", "email": "owner@acme.dev",
                      "password": "correct horse", "display_name": "Owner"})
    session = client.post("/api/v1/auth/login",
                          json={"email": "owner@acme.dev",
                                "password": "correct horse"}).json()["session"]
    return {"Authorization": f"Bearer {session['access_token']}"}


def test_creating_an_org_seats_the_caller_as_owner(env):
    client, _, _, org, _ = env
    owner = _owner_headers(client)

    created = client.post("/api/v1/orgs", headers=owner,
                          json={"name": "Bitsentry Labs", "actor": "owner@acme.dev"})
    assert created.status_code == 201, created.text
    row = created.json()["data"]
    assert row["slug"] == "bitsentry-labs"
    assert row["role"] == "owner"
    assert row["members"] == 1
    assert row["active"] is False   # the switch is the console's next step

    listed = client.get("/api/v1/orgs", headers=owner).json()["data"]
    assert {item["slug"] for item in listed} == {"acme", "bitsentry-labs"}
    assert next(item for item in listed if item["slug"] == "acme")["active"] is True


def test_a_name_with_accents_becomes_a_usable_slug(env):
    """`verificación` → `verificacion`, not `verificaci-n`.

    The slug is in every URL and every audit line: one that mangles the vowels of
    the language the console speaks in is a slug people rename by hand.
    """
    client, _, _, _, _ = env
    owner = _owner_headers(client)
    created = client.post("/api/v1/orgs", headers=owner,
                          json={"name": "Verificación temporal"})
    assert created.status_code == 201, created.text
    assert created.json()["data"]["slug"] == "verificacion-temporal"


def test_x_org_reads_the_other_organisation_and_only_that_one(env):
    client, _, _, org, stranger = env
    owner = _owner_headers(client)
    created = client.post("/api/v1/orgs", headers=owner,
                          json={"name": "Second"}).json()["data"]

    mine = client.get("/api/v1/org", headers={**owner, "X-Org": created["id"]})
    assert mine.status_code == 200
    assert mine.json()["data"]["name"] == "Second"

    # A seat is what allows the read: the stranger org exists, and is still 403.
    denied = client.get("/api/v1/org", headers={**owner, "X-Org": stranger.id})
    assert denied.status_code == 403

    # …and the write path in the other org is judged by the seat's role, not by
    # the role the person holds at home.
    patched = client.patch("/api/v1/org", headers={**owner, "X-Org": created["id"]},
                           json={"name": "Second Renamed", "actor": "owner@acme.dev"})
    assert patched.status_code == 200


def test_an_api_key_cannot_be_pointed_at_another_organisation(env):
    client, headers, _, org, stranger = env
    moved = client.get("/api/v1/org", headers={**headers, "X-Org": stranger.id})
    assert moved.status_code == 403
    assert "one organisation" in moved.json()["detail"]
    # The key's own org still answers with or without the header.
    assert client.get("/api/v1/org", headers={
        **headers, "X-Org": org.id}).json()["data"]["slug"] == "acme"


def test_a_viewer_seat_is_viewer_in_that_organisation(env):
    client, _, session, org, _ = env
    owner = _owner_headers(client)
    created = client.post("/api/v1/orgs", headers=owner,
                          json={"name": "Read Only"}).json()["data"]
    user = session.query(models.User).filter_by(email="owner@acme.dev").one()
    # Same seat, narrower role: what changes is the membership, not the account.
    seat = (session.query(models.OrganizationMember)
            .filter_by(org_id=created["id"], user_id=user.id).one())
    seat.role = "viewer"
    session.commit()

    headers = {**owner, "X-Org": created["id"]}
    assert client.get("/api/v1/org", headers=headers).status_code == 200
    denied = client.patch("/api/v1/org", headers=headers,
                          json={"name": "Nope", "actor": "owner@acme.dev"})
    assert denied.status_code == 403

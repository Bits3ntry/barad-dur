"""Org settings and API-key lifecycle."""
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def org_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/org.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "admin")
    other_key = create_key(session, other.id, "other")
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key}, org.id)


def test_read_and_rename_org(org_client):
    test_client, headers, _other, _org_id = org_client
    org = test_client.get("/api/v1/org", headers=headers).json()["data"]
    assert org["slug"] == "poc" and org["name"] == "POC"

    renamed = test_client.patch("/api/v1/org", json={
        "name": "Councilbox Security", "actor": "santiago"}, headers=headers)
    assert renamed.status_code == 200
    assert renamed.json()["data"]["name"] == "Councilbox Security"
    audit = test_client.get("/api/v1/audit?action=org.", headers=headers).json()
    assert audit["total"] >= 1 and audit["chain_ok"] is True


def test_key_lifecycle(org_client):
    test_client, headers, _other, _org_id = org_client
    before = test_client.get("/api/v1/org/keys", headers=headers).json()
    assert before["total"] == 1

    created = test_client.post("/api/v1/org/keys", json={
        "label": "ci-runner", "actor": "santiago"}, headers=headers)
    assert created.status_code == 200, created.text
    raw = created.json()["data"]["key"]
    assert raw and len(raw) == 64
    # the raw key works immediately
    assert test_client.get("/api/v1/findings",
                           headers={"X-API-Key": raw}).status_code == 200

    listing = test_client.get("/api/v1/org/keys", headers=headers).json()
    assert listing["total"] == 2
    assert all("key" not in row for row in listing["data"])  # never re-exposed

    key_id = [row for row in listing["data"]
              if row["label"] == "ci-runner"][0]["id"]
    revoked = test_client.post(f"/api/v1/org/keys/{key_id}/revoke", json={
        "actor": "santiago", "reason": "rotated"}, headers=headers)
    assert revoked.status_code == 200
    assert test_client.get("/api/v1/findings",
                           headers={"X-API-Key": raw}).status_code == 401

    again = test_client.post(f"/api/v1/org/keys/{key_id}/revoke",
                             json={"actor": "santiago"}, headers=headers)
    assert again.status_code == 409


def test_cannot_revoke_last_key(org_client):
    test_client, headers, _other, _org_id = org_client
    only = test_client.get("/api/v1/org/keys", headers=headers).json()["data"][0]
    denied = test_client.post(f"/api/v1/org/keys/{only['id']}/revoke",
                              json={"actor": "santiago"}, headers=headers)
    assert denied.status_code == 409
    assert "last active" in denied.json()["detail"]


def test_isolation(org_client):
    test_client, headers, other_headers, _org_id = org_client
    org = test_client.get("/api/v1/org/keys", headers=headers).json()["data"][0]
    assert test_client.post(f"/api/v1/org/keys/{org['id']}/revoke",
                            json={"actor": "intruder"},
                            headers=other_headers).status_code == 404
    assert test_client.get("/api/v1/org", headers=other_headers).json()["data"]["slug"] == "other"

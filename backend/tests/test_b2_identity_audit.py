"""B2 acceptance: members/roles + the tamper-evident audit ledger."""
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

import hashlib  # noqa: E402
import json  # noqa: E402

from backend.app import models  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402
from backend.app.routers.identity import GENESIS_HASH  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/b2.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "b2")
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), key, session


H = {"X-API-Key": ""}


def test_member_lifecycle_and_audit_chain(client):
    test_client, key, session = client
    H["X-API-Key"] = key

    added = test_client.post("/api/v1/members", json={
        "identity": "santiago@councilbox.com", "role": "admin", "added_by": "root"
    }, headers=H)
    assert added.status_code == 200, added.text
    member = added.json()["data"]

    # Missing actor (with auth) breaks the accountability requirement.
    actorless = test_client.post("/api/v1/members", json={
        "identity": "noactor@councilbox.com", "role": "viewer"}, headers=H)
    assert actorless.status_code == 422
    # No key at all: unauthorized, never validated.
    unkeyed = test_client.post("/api/v1/members", json={
        "identity": "noactor@councilbox.com", "role": "viewer"})
    assert unkeyed.status_code == 401

    patched = test_client.patch(f"/api/v1/members/{member['id']}", json={
        "role": "analyst", "changed_by": "root"}, headers=H)
    assert patched.json()["data"]["role"] == "analyst"

    removed = test_client.delete(
        f"/api/v1/members/{member['id']}?changed_by=root", headers=H)
    assert removed.json()["data"]["status"] == "removed"

    audit = test_client.get("/api/v1/audit", headers=H).json()
    assert audit["chain_ok"] is True
    actions = [row["action"] for row in audit["data"]]
    assert actions == ["member.added", "member.role_changed", "member.removed"]


def test_audit_chain_detects_tampering(client):
    test_client, key, session = client
    H["X-API-Key"] = key
    test_client.post("/api/v1/members", json={
        "identity": "santiago@councilbox.com", "role": "admin", "added_by": "root"
    }, headers=H)
    test_client.get("/api/v1/audit", headers=H).json()["chain_ok"] is True

    # Tamper with the row directly underneath the server.
    entry = session.query(models.AuditLog).first()
    entry.actor = "attacker"
    session.commit()

    audit = test_client.get("/api/v1/audit", headers=H).json()
    assert audit["chain_ok"] is False
    real = json.dumps({"actor": "attacker", "action": entry.action,
                       "resource_type": entry.resource_type,
                       "resource_id": entry.resource_id,
                       "detail": entry.detail}, sort_keys=True, separators=(",", ":"))
    expected = hashlib.sha256(f"{entry.prev_hash}|{entry.chain_position}|".encode() + real.encode()).hexdigest()
    assert expected != entry.hash


def test_role_validation(client):
    test_client, key, _ = client
    H["X-API-Key"] = key
    bad = test_client.post("/api/v1/members", json={
        "identity": "person@councilbox.com", "role": "superadmin",
        "added_by": "root"}, headers=H)
    assert bad.status_code == 422
    dup = test_client.post("/api/v1/members", json={
        "identity": "a@councilbox.com", "role": "viewer", "added_by": "root"},
        headers=H)
    again = test_client.post("/api/v1/members", json={
        "identity": "a@councilbox.com", "role": "viewer", "added_by": "root"},
        headers=H)
    assert dup.status_code == 200
    assert again.status_code == 409

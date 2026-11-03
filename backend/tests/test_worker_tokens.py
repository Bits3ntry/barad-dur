"""Worker tokens: scoped credentials that can only drive their own jobs."""
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
def worker_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/wt.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "wt")
    other_key = create_key(session, other.id, "wt2")
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key})


def _scanner_and_worker(test_client, headers):
    test_client.post("/api/v1/orchestration/scanners", json={
        "name": "trivy", "display_name": "Trivy",
        "capability": "vulnerability_analysis", "actor": "santiago"}, headers=headers)
    worker = test_client.post("/api/v1/orchestration/workers", json={
        "name": "edge-1", "capabilities": ["vulnerability_analysis"],
        "actor": "santiago"}, headers=headers).json()["data"]
    return worker


def test_issue_and_use_token(worker_client):
    test_client, headers, _other = worker_client
    worker = _scanner_and_worker(test_client, headers)
    issued = test_client.post(
        f"/api/v1/orchestration/workers/{worker['id']}/tokens",
        json={"label": "edge-1", "expires_hours": 24, "actor": "santiago"},
        headers=headers)
    assert issued.status_code == 200, issued.text
    token = issued.json()["data"]["token"]
    worker_auth = {"X-Worker-Token": token}

    claim = test_client.post("/api/v1/orchestration/jobs/claim",
                             json={"worker_id": worker["id"], "actor": "edge-1"},
                             headers=worker_auth)
    assert claim.status_code == 200, claim.text
    assert claim.json()["data"] is None  # no jobs queued, but the credential works

    beat = test_client.post(
        f"/api/v1/orchestration/workers/{worker['id']}/heartbeat",
        headers=worker_auth)
    assert beat.status_code == 200

    # the raw token is never listed again
    listing = test_client.get(
        f"/api/v1/orchestration/workers/{worker['id']}/tokens",
        headers=headers).json()
    assert listing["total"] == 1
    assert "token" not in listing["data"][0]


def test_worker_token_cannot_read_findings_or_grants(worker_client):
    test_client, headers, _other = worker_client
    worker = _scanner_and_worker(test_client, headers)
    token = test_client.post(
        f"/api/v1/orchestration/workers/{worker['id']}/tokens",
        json={"actor": "santiago"}, headers=headers).json()["data"]["token"]
    worker_auth = {"X-Worker-Token": token}

    for path in ("/api/v1/findings", "/api/v1/audit",
                 "/api/v1/authorization/grants", "/api/v1/auth/users"):
        denied = test_client.get(path, headers=worker_auth)
        assert denied.status_code == 403, path
    # and it cannot mint more tokens
    mint = test_client.post(
        f"/api/v1/orchestration/workers/{worker['id']}/tokens",
        json={"actor": "edge-1"}, headers=worker_auth)
    assert mint.status_code == 403


def test_worker_token_cannot_claim_for_another_worker(worker_client):
    test_client, headers, _other = worker_client
    worker = _scanner_and_worker(test_client, headers)
    token = test_client.post(
        f"/api/v1/orchestration/workers/{worker['id']}/tokens",
        json={"actor": "santiago"}, headers=headers).json()["data"]["token"]
    other_worker = test_client.post("/api/v1/orchestration/workers", json={
        "name": "edge-2", "actor": "santiago"}, headers=headers).json()["data"]
    # worker_id in the body is another worker's id → must be refused
    claim = test_client.post("/api/v1/orchestration/jobs/claim",
                             json={"worker_id": other_worker["id"],
                                   "actor": "edge-1"},
                             headers={"X-Worker-Token": token})
    assert claim.status_code == 403


def test_revocation_and_expiry(worker_client):
    test_client, headers, _other = worker_client
    worker = _scanner_and_worker(test_client, headers)
    issued = test_client.post(
        f"/api/v1/orchestration/workers/{worker['id']}/tokens",
        json={"actor": "santiago"}, headers=headers).json()["data"]
    worker_auth = {"X-Worker-Token": issued["token"]}
    assert test_client.post("/api/v1/orchestration/jobs/claim",
                            json={"worker_id": worker["id"], "actor": "edge-1"},
                            headers=worker_auth).status_code == 200

    revoked = test_client.post(
        f"/api/v1/orchestration/worker-tokens/{issued['id']}/revoke",
        json={"actor": "santiago", "reason": "rotated"}, headers=headers)
    assert revoked.status_code == 200
    again = test_client.post(
        f"/api/v1/orchestration/jobs/claim",
        json={"worker_id": worker["id"], "actor": "edge-1"},
        headers=worker_auth)
    assert again.status_code == 401
    assert "worker token" in again.json()["detail"]


def test_isolation_of_token_management(worker_client):
    test_client, headers, other_headers = worker_client
    worker = _scanner_and_worker(test_client, headers)
    assert test_client.post(
        f"/api/v1/orchestration/workers/{worker['id']}/tokens",
        json={"actor": "intruder"},
        headers=other_headers).status_code == 404
    assert test_client.get(
        f"/api/v1/orchestration/workers/{worker['id']}/tokens",
        headers=other_headers).status_code == 404

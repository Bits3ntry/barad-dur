"""BL-020 acceptance: orchestration lifecycle, authorization and leases."""
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


@pytest.fixture()
def orch_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/orch.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "orch")
    other_key = create_key(session, other.id, "orch2")
    session.commit()
    from fastapi.testclient import TestClient

    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key})


def _scanner(test_client, headers, name="trivy", capability="vulnerability_analysis"):
    return test_client.post("/api/v1/orchestration/scanners", json={
        "name": name, "display_name": name.title(), "capability": capability,
        "version": "0.55.0", "actor": "santiago"}, headers=headers)


def _grant(test_client, headers, value, capability="vulnerability_analysis"):
    response = test_client.post("/api/v1/authorization/grants", json={
        "principal": "ci", "capabilities": [capability],
        "targets": [{"type": "repository", "value": value}],
        "tools": ["trivy"], "environment": "ci",
        "issued_by": "santiago", "justification": "pipeline scans",
        "actor": "santiago"}, headers=headers)
    assert response.status_code in (200, 201), response.text
    return response.json()["data"]


def _repo(test_client, headers, slug="saria"):
    test_client.post("/api/v1/projects", json={
        "slug": slug, "name": slug, "actor": "santiago"}, headers=headers)
    repo = test_client.post("/api/v1/repositories", json={
        "remote_url": f"https://github.com/acme/{slug}", "name": slug,
        "actor": "santiago"}, headers=headers)
    if repo.status_code not in (200, 201):
        repo = test_client.get("/api/v1/repositories", headers=headers)
    return repo


def test_job_requires_authorization(orch_client):
    test_client, headers, _other = orch_client
    _scanner(test_client, headers)
    denied = test_client.post("/api/v1/orchestration/jobs", json={
        "scanner": "trivy", "capability": "vulnerability_analysis",
        "principal": "ci", "targets": [{"type": "repository", "value": "acme/saria"}],
        "environment": "ci", "actor": "santiago"}, headers=headers)
    assert denied.status_code == 403
    assert "not authorized" in denied.json()["detail"]
    jobs = test_client.get("/api/v1/orchestration/jobs", headers=headers).json()
    assert jobs["total"] == 0


def test_full_lifecycle_with_lease_and_result(orch_client):
    test_client, headers, _other = orch_client
    _scanner(test_client, headers)
    repo_value = "acme/saria"
    _grant(test_client, headers, repo_value)

    created = test_client.post("/api/v1/orchestration/jobs", json={
        "scanner": "trivy", "capability": "vulnerability_analysis",
        "principal": "ci", "targets": [{"type": "repository", "value": repo_value}],
        "environment": "ci", "actor": "santiago"}, headers=headers)
    assert created.status_code == 200, created.text
    job = created.json()["data"]
    assert job["status"] == "queued"
    assert job["authorization"]["decision"] == "allow"

    worker = test_client.post("/api/v1/orchestration/workers", json={
        "name": "worker-1", "capabilities": ["vulnerability_analysis"],
        "max_concurrent": 1, "actor": "santiago"}, headers=headers).json()["data"]

    claim = test_client.post("/api/v1/orchestration/jobs/claim", json={
        "worker_id": worker["id"], "actor": "worker-1"}, headers=headers).json()
    assert claim["data"]["id"] == job["id"]
    assert claim["data"]["status"] == "leased"
    assert claim["lease_seconds"] > 0

    # concurrency ceiling holds
    blocked = test_client.post("/api/v1/orchestration/jobs/claim", json={
        "worker_id": worker["id"], "actor": "worker-1"}, headers=headers)
    assert blocked.status_code == 409

    started = test_client.post(f"/api/v1/orchestration/jobs/{job['id']}/start",
                               json={"actor": "worker-1"}, headers=headers).json()
    assert started["cancelled"] is False

    finished = test_client.post(f"/api/v1/orchestration/jobs/{job['id']}/result", json={
        "actor": "worker-1", "outcome": "succeeded",
        "summary": {"findings": 2, "duration_s": 12},
        "artifacts": [{"kind": "log", "content": "scan ok"}],
    }, headers=headers).json()["data"]
    assert finished["status"] == "succeeded"
    assert finished["result"]["findings"] == 2

    detail = test_client.get(f"/api/v1/orchestration/jobs/{job['id']}",
                             headers=headers).json()["data"]
    assert detail["artifacts"][0]["kind"] == "log"
    artifacts = test_client.get(
        f"/api/v1/orchestration/jobs/{job['id']}/artifacts",
        headers=headers).json()
    assert artifacts["data"][0]["content"] == "scan ok"


def test_claim_revalidates_authorization(orch_client):
    test_client, headers, _other = orch_client
    _scanner(test_client, headers)
    _repo(test_client, headers)
    grant = _grant(test_client, headers, "acme/saria")
    job = test_client.post("/api/v1/orchestration/jobs", json={
        "scanner": "trivy", "capability": "vulnerability_analysis",
        "principal": "ci", "targets": [{"type": "repository", "value": "acme/saria"}],
        "environment": "ci", "actor": "santiago"}, headers=headers).json()["data"]
    worker = test_client.post("/api/v1/orchestration/workers", json={
        "name": "worker-2", "capabilities": [], "actor": "santiago"},
        headers=headers).json()["data"]

    # grant revoked before the worker claims the job
    revoked = test_client.post(
        f"/api/v1/authorization/grants/{grant['id']}/revoke",
        json={"actor": "santiago", "reason": "window closed"}, headers=headers)
    assert revoked.status_code in (200, 201), revoked.text

    claim = test_client.post("/api/v1/orchestration/jobs/claim", json={
        "worker_id": worker["id"], "actor": "worker-2"}, headers=headers).json()
    assert claim["data"] is None
    assert claim["rejected"]["job_id"] == job["id"]
    assert "authorized" in claim["rejected"]["reason"] or \
        "exclusion" in claim["rejected"]["reason"] or \
        "grant" in claim["rejected"]["reason"]
    detail = test_client.get(f"/api/v1/orchestration/jobs/{job['id']}",
                             headers=headers).json()["data"]
    assert detail["status"] == "failed"
    assert "authorization revalidation denied" in detail["error"]


def test_cancel_retry_and_isolation(orch_client):
    test_client, headers, other_headers = orch_client
    _scanner(test_client, headers)
    _grant(test_client, headers, "acme/saria")
    job = test_client.post("/api/v1/orchestration/jobs", json={
        "scanner": "trivy", "capability": "vulnerability_analysis",
        "principal": "ci", "targets": [{"type": "repository", "value": "acme/saria"}],
        "environment": "ci", "actor": "santiago"}, headers=headers).json()["data"]

    cancelled = test_client.post(f"/api/v1/orchestration/jobs/{job['id']}/cancel",
                                 json={"actor": "santiago", "reason": "no longer needed"},
                                 headers=headers)
    assert cancelled.status_code == 200
    assert cancelled.json()["data"]["status"] == "cancelled"
    again = test_client.post(f"/api/v1/orchestration/jobs/{job['id']}/cancel",
                             json={"actor": "santiago"}, headers=headers)
    assert again.status_code == 409

    retried = test_client.post(f"/api/v1/orchestration/jobs/{job['id']}/retry",
                               json={"actor": "santiago"}, headers=headers)
    assert retried.status_code == 200
    assert retried.json()["data"]["status"] == "queued"

    # tenant isolation
    assert test_client.get(f"/api/v1/orchestration/jobs/{job['id']}",
                           headers=other_headers).status_code == 404
    assert test_client.get("/api/v1/orchestration/jobs",
                           headers=other_headers).json()["total"] == 0
    assert test_client.post(f"/api/v1/orchestration/jobs/{job['id']}/cancel",
                            json={"actor": "intruder"},
                            headers=other_headers).status_code == 404


def test_scanner_capability_mismatch(orch_client):
    test_client, headers, _other = orch_client
    _scanner(test_client, headers, name="gitleaks", capability="passive_discovery")
    mismatch = test_client.post("/api/v1/orchestration/jobs", json={
        "scanner": "gitleaks", "capability": "intrusive_testing",
        "principal": "ci", "targets": [{"type": "repository", "value": "acme/saria"}],
        "environment": "ci", "actor": "santiago"}, headers=headers)
    assert mismatch.status_code == 422
    assert "registered for" in mismatch.json()["detail"]

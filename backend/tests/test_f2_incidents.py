"""F2 acceptance tests: multi-kind ingest, suppression workflow, dispositions."""
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
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/f2.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "f2")
    project = models.Project(org_id=org.id, slug="fixture", name="fixture")
    session.add(project)
    session.flush()
    session.add(models.ProjectVersion(project_id=project.id, version="1.2.0"))
    session.commit()
    from fastapi.testclient import TestClient

    test_client = TestClient(app)
    return test_client, key, session


def _ingest(client, key, findings, *, source="web"):
    return client.post(
        "/api/v1/findings/ingest?project=fixture&version=1.2.0"
        + (f"&source={source}" if source else ""),
        json={"schema": "barad-findings-v1", "tool": "trivy", "findings": findings},
        headers={"X-API-Key": key})


def test_multikind_ingest_creates_the_five_ipso_fingerprints(client):
    test_client, key, session = client
    findings = [
        {"kind": "secret", "title": "AWS key in settings.py", "severity": "CRITICAL",
         "tool": "trivy", "rule_id": "aws-access-key-id", "path": "settings.py"},
        {"kind": "misconfiguration", "title": ":latest tag used", "severity": "MEDIUM",
         "tool": "trivy", "rule_id": "DS-0001", "path": "Dockerfile", "line": 1},
        {"kind": "code-weakness", "title": "Avoid shell=True", "severity": "HIGH",
         "tool": "opengrep", "rule_id": "python-subprocess-shell-true", "path": "app.py",
         "line": 6},
    ]
    response = _ingest(test_client, key, findings)
    assert response.status_code == 200, response.text
    counts = response.json()["counts"]
    assert counts == {"received": 3, "created": 3, "refreshed": 0,
                      "suppressed_by_rule": 0, "skipped_missing_identity": 0}

    listed = test_client.get("/api/v1/findings", headers={"X-API-Key": key}).json()
    kinds = {row["kind"] for row in listed["data"]}
    assert kinds == {"secret", "misconfiguration", "code-weakness"}
    fingerprints = {row["fingerprint"] for row in listed["data"]}
    assert len(fingerprints) == 3

    # Rescan: identical conditions must not duplicate (fingerprint recipes).
    rescan = _ingest(test_client, key, findings, source="cli")
    assert rescan.json()["counts"]["created"] == 0
    assert rescan.json()["counts"]["refreshed"] == 3
    assert test_client.get("/api/v1/findings", headers={"X-API-Key": key}).json()["total"] == 3


def test_findings_without_identity_are_rejected_with_counter(client):
    test_client, key, session = client
    response = _ingest(test_client, key,
                       [{"kind": "secret", "title": "no rule and no path"}])
    assert response.status_code == 200
    assert response.json()["counts"]["skipped_missing_identity"] == 1
    assert response.json()["counts"]["created"] == 0


def test_invalid_payload_is_422_with_bounded_detail(client):
    test_client, key, session = client
    response = _ingest(test_client, key,
                       [{"kind": "aliens", "title": "x", "rule_id": "r", "path": "p"}])
    assert response.status_code == 422
    detail = response.json()["detail"][0]["msg"]
    assert "kind must be one of" in detail


def test_selfapproval_refused_and_reviewer_applies_rule(client):
    test_client, key, session = client
    _ingest(test_client, key, [
        {"kind": "secret", "title": "AWS key in settings.py", "severity": "CRITICAL",
         "rule_id": "aws-access-key-id", "path": "settings.py"},
        {"kind": "code-weakness", "title": "Avoid shell=True", "severity": "HIGH",
         "rule_id": "python-subprocess-shell-true", "path": "app.py"},
    ])
    requester = "santiago"
    created = test_client.post(
        "/api/v1/suppressions",
        json={"kind": "secret", "rule_id": "aws-access-key-id",
              "suppression_type": "false_positive",
              "reason": "test credential, not a real deployment key",
              "requested_by": requester},
        headers={"X-API-Key": key}).json()["data"]
    rule_id = created["id"]
    assert created["status"] == "pending"

    # Contract: the requester cannot approve their own rule.
    self_review = test_client.post(
        f"/api/v1/suppressions/{rule_id}/approve",
        json={"approver": requester}, headers={"X-API-Key": key})
    assert self_review.status_code == 409
    assert "own" in self_review.json()["detail"]

    # A different reviewer approves: matching findings suppress in bulk.
    approved = test_client.post(
        f"/api/v1/suppressions/{rule_id}/approve",
        json={"approver": "reviewer"}, headers={"X-API-Key": key}).json()
    assert approved["data"]["status"] == "approved"
    assert approved["findings_suppressed"] == 1

    # Default view hides the suppressed finding; it stays reachable.
    default_view = test_client.get("/api/v1/findings", headers={"X-API-Key": key}).json()
    assert default_view["total"] == 1
    assert default_view["data"][0]["kind"] == "code-weakness"
    everything = test_client.get("/api/v1/findings", params={"include_suppressed": True},
                                 headers={"X-API-Key": key}).json()
    suppressed = [row for row in everything["data"] if row["kind"] == "secret"]
    assert suppressed and suppressed[0]["status"] == "suppressed"
    assert "test credential" in suppressed[0]["status_reason"]


def test_new_findings_matching_approved_rules_are_suppressed_at_ingest(client):
    test_client, key, session = client
    rule = test_client.post(
        "/api/v1/suppressions",
        json={"path_pattern": "Dockerfile",
              "suppression_type": "accepted_risk",
              "reason": "scratch container, nightly rebuild",
              "requested_by": "santiago"},
        headers={"X-API-Key": key}).json()["data"]
    test_client.post(f"/api/v1/suppressions/{rule['id']}/approve",
                     json={"approver": "reviewer"}, headers={"X-API-Key": key})
    response = _ingest(test_client, key, [
        {"kind": "misconfiguration", "title": "Image user should not be root",
         "severity": "HIGH", "rule_id": "DS-0002", "path": "Dockerfile"},
        {"kind": "misconfiguration", "title": "No HEALTHCHECK defined",
         "severity": "LOW", "rule_id": "DS-0026", "path": "docker-compose.yml"},
    ])
    counts = response.json()["counts"]
    assert counts["created"] == 2
    assert counts["suppressed_by_rule"] == 1
    everything = test_client.get("/api/v1/findings", params={"include_suppressed": True},
                                 headers={"X-API-Key": key}).json()["data"]
    by_path = {row["path"]: row["status"] for row in everything}
    assert by_path["Dockerfile"] == "suppressed"
    assert by_path["docker-compose.yml"] == "open"


def test_manual_disposition_around_suppression(client):
    test_client, key, session = client
    _ingest(test_client, key, [
        {"kind": "secret", "title": "AWS key", "severity": "CRITICAL",
         "rule_id": "aws-access-key-id", "path": "settings.py"}])
    listed = test_client.get("/api/v1/findings", headers={"X-API-Key": key}).json()
    finding_id = listed["data"][0]["id"]

    ok = test_client.patch(
        f"/api/v1/findings/{finding_id}/status",
        json={"status": "acknowledged", "reason": "queued for rotation",
              "actor": "santiago"},
        headers={"X-API-Key": key})
    assert ok.status_code == 200
    assert ok.json()["data"]["status"] == "acknowledged"

    bad = test_client.patch(
        f"/api/v1/findings/{finding_id}/status",
        json={"status": "bogus", "actor": "santiago"},
        headers={"X-API-Key": key})
    assert bad.status_code == 422

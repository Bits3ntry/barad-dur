"""v0 web surface, lookalikes, review and the weekly summary.

Acceptance step 8: an excluded path is shown as not evaluated, a lookalike is an
external resource, and neither receives implicit authorization.
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


@pytest.fixture()
def seeded(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/web.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="bitsentry", name="Bitsentry")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    project = models.Project(org_id=org.id, name="AUREA", slug="aurea")
    session.add(project)
    session.flush()
    asset = models.Asset(org_id=org.id, type="domain",
                         value="api-aurea.bitsentry.xyz", source="scope")
    session.add(asset)
    session.flush()
    key = create_key(session, org.id, "web")
    other_key = create_key(session, other.id, "web-other")
    session.commit()
    from fastapi.testclient import TestClient
    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key},
            asset.id, project.slug)


def test_paths_returning_200_are_observed_not_vulnerable(seeded):
    test_client, headers, _other, _asset, _project = seeded
    excluded = test_client.post("/api/v1/scope/exclusions", json={
        "target_type": "domain", "value": "legacy.bitsentry.xyz",
        "reason": "operated by a third party"}, headers=headers)
    assert excluded.status_code == 200

    imported = test_client.post("/api/v1/attack-surface/web-endpoints", json={
        "endpoints": [
            {"origin": "https://api-aurea.bitsentry.xyz", "path": "/login",
             "status_code": 200, "source": "import"},
            {"origin": "https://api-aurea.bitsentry.xyz", "path": "/admin/users",
             "status_code": 200, "evidence": "200 without a session cookie"},
            {"origin": "https://legacy.bitsentry.xyz", "path": "/admin",
             "status_code": 200},
        ], "actor": "importer"}, headers=headers)
    assert imported.status_code == 200, imported.text
    counters = imported.json()["data"]["counters"]
    assert counters["created"] == 3
    assert counters["excluded"] == 1

    listing = test_client.get("/api/v1/attack-surface/web-endpoints",
                              headers=headers).json()
    assert listing["counters"]["endpoints"] == 3
    assert listing["counters"]["not_evaluated"] == 1
    assert listing["counters"]["sensitive_observed"] == 1
    legacy = next(row for row in listing["data"]
                  if row["origin"] == "https://legacy.bitsentry.xyz")
    assert legacy["state"] == "not_evaluated"
    assert "excluded by scope" in legacy["evidence"]
    assert "not a vulnerability" in listing["note"]

    # Confirming a finding requires an actual finding in this organization.
    login = next(row for row in listing["data"] if row["path"] == "/login")
    naked = test_client.post(
        f"/api/v1/attack-surface/web-endpoints/{login['id']}/state",
        json={"state": "confirmed_finding"}, headers=headers)
    assert naked.status_code == 422

    session = session_factory()()
    org = session.query(models.Organization).filter_by(slug="bitsentry").one()
    project = session.query(models.Project).filter_by(slug="aurea").one()
    finding = models.Finding(org_id=org.id, project_id=project.id, kind="code-weakness",
                             fingerprint="fp-idor", source="manual", severity="HIGH",
                             title="IDOR", status="open",
                             first_seen_at=models.utcnow(), last_seen_at=models.utcnow())
    session.add(finding)
    session.commit()
    finding_id = finding.id
    session.close()

    confirmed = test_client.post(
        f"/api/v1/attack-surface/web-endpoints/{login['id']}/state",
        json={"state": "confirmed_finding", "finding_id": finding_id},
        headers=headers).json()["data"]
    assert confirmed["state"] == "confirmed_finding"
    assert confirmed["finding_id"] == finding_id


def test_lookalikes_are_external_and_never_authorize(seeded):
    test_client, headers, _other, _asset, _project = seeded
    imported = test_client.post("/api/v1/attack-surface/lookalikes", json={
        "root_domain": "bitsentry.xyz",
        "candidates": [
            {"candidate": "bitsentry-login.xyz", "similarity": "combosquatting",
             "dns": {"addresses": ["203.0.113.99"]}, "registration_state": "unconfirmed"},
            {"candidate": "bitsentry.xy", "similarity": "tld_swap",
             "registration_state": "unknown"},
        ], "actor": "importer"}, headers=headers)
    assert imported.status_code == 200, imported.text
    assert imported.json()["data"]["counters"]["created"] == 3

    listing = test_client.get("/api/v1/attack-surface/lookalikes",
                              headers=headers).json()
    assert listing["counts"]["candidate"] == 2
    assert listing["counts"]["confirmed"] == 1
    candidate = next(row for row in listing["data"]
                     if row["candidate"] == "bitsentry-login.xyz")
    assert candidate["authorization"].startswith("none")
    assert candidate["registration_state"] == "unconfirmed", "DNS is not registration"

    no_reason = test_client.post(
        f"/api/v1/attack-surface/lookalikes/{candidate['id']}/decide",
        json={"action": "dismiss"}, headers=headers)
    assert no_reason.status_code == 422

    decided = test_client.post(
        f"/api/v1/attack-surface/lookalikes/{candidate['id']}/decide", json={
            "action": "external", "reason": "registered by a third party in 2021",
            "evidence": {"whois": "redacted"}, "actor": "ana"}, headers=headers).json()["data"]
    assert decided["state"] == "external"
    assert decided["registration_evidence"]["whois"] == "redacted"

    # Nothing was added to scope: an impersonating domain is not a target.
    assert test_client.get("/api/v1/scope/targets",
                           headers=headers).json()["total"] == 0


def test_review_queue_confirms_ownership_but_grants_nothing(seeded):
    test_client, headers, _other, asset_id, project = seeded
    queue = test_client.get("/api/v1/attack-surface/review", headers=headers).json()
    assert queue["total"] == 1
    assert "never grants" in queue["note"]

    no_reason = test_client.post(f"/api/v1/attack-surface/review/{asset_id}",
                                 json={"action": "external"}, headers=headers)
    assert no_reason.status_code == 422

    confirmed = test_client.post(f"/api/v1/attack-surface/review/{asset_id}", json={
        "action": "confirm", "project": project, "owner": "ana@bitsentry.xyz",
        "actor": "ana"}, headers=headers).json()["data"]
    assert confirmed["classification_status"] == "confirmed"
    assert confirmed["owner"] == "ana@bitsentry.xyz"
    assert "not a scan grant" in confirmed["authorization"]
    assert test_client.get("/api/v1/attack-surface/review",
                           headers=headers).json()["total"] == 0
    assert test_client.get("/api/v1/scope/targets",
                           headers=headers).json()["total"] == 0


def test_weekly_summary_declares_delivery_not_configured(seeded):
    test_client, headers, _other, _asset, _project = seeded
    body = test_client.get("/api/v1/attack-surface/summary/weekly",
                           headers=headers).json()["data"]
    assert body["delivery"]["configured"] is False
    assert "scheduler" in body["delivery"]["reason"]
    for key in ("changes", "total_changes", "new_paths", "lookalike_candidates",
                "open_exposures", "coverage_notes"):
        assert key in body


def test_attack_surface_is_isolated(seeded):
    test_client, headers, other_headers, asset_id, project = seeded
    test_client.post("/api/v1/attack-surface/web-endpoints", json={
        "endpoints": [{"origin": "https://api-aurea.bitsentry.xyz", "path": "/a",
                       "status_code": 200}]}, headers=headers)
    test_client.post("/api/v1/attack-surface/lookalikes", json={
        "root_domain": "bitsentry.xyz",
        "candidates": [{"candidate": "bitsentry-login.xyz"}]}, headers=headers)

    assert test_client.get("/api/v1/attack-surface/web-endpoints",
                           headers=other_headers).json()["total"] == 0
    assert test_client.get("/api/v1/attack-surface/lookalikes",
                           headers=other_headers).json()["total"] == 0
    assert test_client.get("/api/v1/attack-surface/review",
                           headers=other_headers).json()["total"] == 0
    assert test_client.post(f"/api/v1/attack-surface/review/{asset_id}",
                            json={"action": "confirm", "actor": "x"},
                            headers=other_headers).status_code == 404

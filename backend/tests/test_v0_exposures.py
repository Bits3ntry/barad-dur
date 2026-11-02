"""v0 attack surface + exposures: coverage-aware changes, stable events.

Acceptance step 7 of the spec lives here: an imported observation shows up in
Activity and in Changes, the relevant condition is managed in Exposures, and the
same condition observed twice does not duplicate the event.
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
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/surface.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="bitsentry", name="Bitsentry")
    other = models.Organization(slug="other", name="Other")
    session.add_all([org, other])
    session.flush()
    key = create_key(session, org.id, "surface")
    other_key = create_key(session, other.id, "surface-other")
    session.commit()
    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key}


def _observe(test_client, headers, ports=None, coverage="full", value=None,
             kind="host", asset="api-aurea.bitsentry.xyz", actor="importer"):
    body = {"observations": [{
        "asset": {"type": "domain", "value": asset},
        "kind": kind, "coverage": coverage,
        "source": "nmap-import",
        "value": value if value is not None else {
            "ports": ports or [],
            "addresses": ["203.0.113.10"],
            "technology": ["nginx"],
        },
    }], "actor": actor}
    response = test_client.post("/api/v1/observations", json=body, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["data"]


def test_changes_require_equal_coverage(seeded):
    test_client, headers, _other = seeded
    first = _observe(test_client, headers, ports=["80", "443"])
    assert first["counters"]["events_created"] == 1, "the new host is an exposure event"

    second = _observe(test_client, headers, ports=["80", "443", "8080"])
    assert second["counters"]["changes"] == 1
    assert second["changes"][0]["category"] == "open_port"
    assert second["changes"][0]["port"] == 8080

    failed = _observe(test_client, headers, ports=[], coverage="failed")
    assert failed["counters"]["changes"] == 0
    assert "not comparable" in failed["coverage_notes"][0]["note"]
    assert not any(change["category"] == "closed_port" for change in failed["changes"])

    listing = test_client.get("/api/v1/attack-surface/changes?days=7",
                              headers=headers).json()
    assert listing["counts"].get("open_port") == 1
    assert listing["counts"].get("closed_port") is None
    assert listing["coverage_notes"], "the failed collection is visible as a coverage gap"


def test_repeated_condition_bumps_one_event(seeded):
    test_client, headers, _other = seeded
    _observe(test_client, headers, ports=["80"])
    _observe(test_client, headers, ports=["80", "8080"])
    repeated = _observe(test_client, headers, ports=["80", "8080"])

    events = test_client.get("/api/v1/exposures?state=open", headers=headers).json()
    kinds = [row["kind"] for row in events["data"]]
    assert kinds.count("open_port") == 1, "the same port does not create a second event"
    open_port = next(row for row in events["data"] if row["kind"] == "open_port")
    detail = test_client.get(f"/api/v1/exposures/{open_port['id']}",
                             headers=headers).json()["data"]
    assert detail["occurrences"] >= 2
    assert detail["state"] == "open"


def test_decisions_need_a_reason_and_reopen_explicitly(seeded):
    test_client, headers, _other = seeded
    _observe(test_client, headers, ports=["80"])
    _observe(test_client, headers, ports=["80", "8080"])
    event = next(row for row in
                 test_client.get("/api/v1/exposures", headers=headers).json()["data"]
                 if row["kind"] == "open_port")

    no_reason = test_client.post(f"/api/v1/exposures/{event['id']}/decide",
                                 json={"action": "accept"}, headers=headers)
    assert no_reason.status_code == 422

    accepted = test_client.post(f"/api/v1/exposures/{event['id']}/decide", json={
        "action": "accept", "reason": "internal-only port, firewalled",
        "valid_until": "2099-01-01T00:00:00+00:00", "actor": "ana"}, headers=headers)
    assert accepted.status_code == 200, accepted.text
    assert accepted.json()["data"]["state"] == "accepted"
    assert accepted.json()["data"]["accepted_until"].startswith("2099")

    # An acceptance with a validity window holds while the condition persists.
    again = _observe(test_client, headers, ports=["80", "8080", "9090"])
    still_accepted = test_client.get(f"/api/v1/exposures/{event['id']}",
                                     headers=headers).json()["data"]
    assert still_accepted["state"] == "accepted"
    assert again["counters"]["events_updated"] >= 1

    expired_accept = test_client.post(f"/api/v1/exposures/{event['id']}/decide", json={
        "action": "accept", "reason": "short window",
        "valid_until": "2000-01-01T00:00:00+00:00"}, headers=headers)
    assert expired_accept.status_code == 422

    resolved = test_client.post(f"/api/v1/exposures/{event['id']}/decide", json={
        "action": "resolve", "reason": "port closed in the firewall", "actor": "ana"},
        headers=headers).json()["data"]
    assert resolved["state"] == "resolved"

    # A resolved condition observed again reopens the same event under its policy.
    reopened = _observe(test_client, headers, ports=["80", "8080", "9090"])
    assert reopened["counters"]["events_reopened"] == 1
    state = test_client.get(f"/api/v1/exposures/{event['id']}",
                            headers=headers).json()["data"]
    assert state["state"] == "open"

    history = test_client.get(f"/api/v1/exposures/{event['id']}",
                              headers=headers).json()["data"]["decisions"]
    actions = {row["action"] for row in history}
    assert {"accept", "resolve", "reopened_by_observation"} <= actions


def test_exposure_isolation_and_findings_summary(seeded):
    test_client, headers, other_headers = seeded
    _observe(test_client, headers, ports=["80"])
    _observe(test_client, headers, ports=["80", "8080"])
    event = test_client.get("/api/v1/exposures", headers=headers).json()["data"][0]
    assert test_client.get("/api/v1/exposures", headers=other_headers).json()["total"] == 0
    assert test_client.get(f"/api/v1/exposures/{event['id']}",
                           headers=other_headers).status_code == 404
    assert test_client.post(f"/api/v1/exposures/{event['id']}/decide", json={
        "action": "resolve", "reason": "x"}, headers=other_headers).status_code == 404
    assert test_client.get("/api/v1/attack-surface/changes",
                           headers=other_headers).json()["total"] == 0

    # Findings are exported as filtered summaries, not copies.
    session = session_factory()()
    org = session.query(models.Organization).filter_by(slug="bitsentry").one()
    project = models.Project(org_id=org.id, name="AUREA", slug="aurea")
    session.add(project)
    session.flush()
    session.add_all([
        models.Finding(org_id=org.id, project_id=project.id, kind="secret",
                       fingerprint="fp-secret", source="manual", severity="HIGH",
                       title="AWS key in repo", status="open",
                       first_seen_at=models.utcnow(), last_seen_at=models.utcnow()),
        models.Finding(org_id=org.id, project_id=project.id, kind="secret",
                       fingerprint="fp-secret-2", source="manual", severity="LOW",
                       title="Test token", status="resolved",
                       first_seen_at=models.utcnow(), last_seen_at=models.utcnow()),
        models.Finding(org_id=org.id, project_id=project.id, kind="code-weakness",
                       fingerprint="fp-weak", source="manual", severity="MEDIUM",
                       title="IDOR", status="open",
                       first_seen_at=models.utcnow(), last_seen_at=models.utcnow()),
    ])
    session.commit()
    session.close()

    summary = test_client.get("/api/v1/exposures/summary/findings", headers=headers).json()
    by_kind = {row["kind"]: row for row in summary["data"]}
    assert by_kind["secret"]["total"] == 2 and by_kind["secret"]["open"] == 1
    assert by_kind["code-weakness"]["open"] == 1
    assert by_kind["secret"]["finding_ids"], "the summary links to the same finding ids"

    activity = test_client.get("/api/v1/activity?resource_type=observation",
                               headers=headers).json()["data"]
    assert activity and activity[0]["action"] == "surface.observations_imported"

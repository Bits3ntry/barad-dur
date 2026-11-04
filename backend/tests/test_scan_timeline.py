"""The timeline: two clocks, abandonment, and a revival that rewrites nothing.

The sentence this file protects is the one the product exists for: "launched at
23:00, abandoned at 02:12 for silence, answered at 03:00 — and the process in
between abandoned". `status` stays `abandoned`; only the evidence axis moves.
"""
import datetime
import hashlib
import json
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models, scan_flow  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402

COMMIT = "3f9a1c0b8d2e4f5a6b7c8d9e0f1a2b3c4d5e6f70"


@pytest.fixture()
def flow(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/timeline.db")
    monkeypatch.delenv("SHAURON_DAEMON_URL", raising=False)
    monkeypatch.delenv("SCAN_SIGNING_KEY", raising=False)
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "timeline")
    project = models.Project(org_id=org.id, slug="aurea", name="Aurea")
    repository = models.Repository(
        org_id=org.id, provider="github", name="aurea",
        remote_url="https://github.com/bitsentry/aurea")
    session.add_all([project, repository])
    session.flush()
    session.add(models.ProjectRepository(
        org_id=org.id, project_id=project.id, repository_id=repository.id,
        added_by="santiago"))
    session.commit()

    from fastapi.testclient import TestClient

    return {"client": TestClient(app), "headers": {"X-API-Key": key},
            "org_id": org.id, "db": lambda: session_factory()()}


def _mint(ctx, **overrides):
    body = {"action": "code", "project": "aurea", "commit": COMMIT,
            "origin": "ci", "actor": "santiago"}
    body.update(overrides)
    response = ctx["client"].post("/api/v1/scans", json=body, headers=ctx["headers"])
    assert response.status_code == 201, response.text
    return response.json()


def _abandon(ctx, job_id):
    session = ctx["db"]()
    try:
        job = session.get(models.ScanJob, job_id)
        job.deadline_at = models.utcnow() - datetime.timedelta(minutes=5)
        session.commit()
    finally:
        session.close()
    swept = ctx["client"].post("/api/v1/scans/sweep", headers=ctx["headers"])
    assert swept.status_code == 200, swept.text
    return swept.json()


def _evidence(ctx, ticket, kind="sast"):
    content = json.dumps({"kind": kind, "results": []})
    return ctx["client"].post(
        f"/api/v1/scans/{ticket['ticket_id']}/evidence",
        json={"schema": "barad-evidence-v1", "ticket_id": ticket["ticket_id"],
              "kind": kind, "format": "sarif-2.1.0",
              "content_hash": "sha256:" + hashlib.sha256(content.encode()).hexdigest(),
              "content": content},
        headers={"X-Ticket-Token": ticket["evidence"]["upload_token"]})


def test_timeline_orders_by_server_time_and_keeps_the_client_claim(flow):
    minted = _mint(flow)
    ticket = minted["ticket"]
    job_id = ticket["ticket_id"]
    client_says = (datetime.datetime.now(datetime.timezone.utc)
                   + datetime.timedelta(hours=3)).isoformat()
    flow["client"].post(
        f"/api/v1/scans/{job_id}/events",
        json={"schema": "barad-event-v1", "ticket_id": job_id,
              "event": "started", "at": client_says,
              "detail": {"host": "runner-3"}},
        headers={"X-Ticket-Token": ticket["evidence"]["upload_token"]})

    timeline = flow["client"].get(f"/api/v1/scans/{job_id}/timeline",
                                  headers=flow["headers"]).json()["data"]
    kinds = [row["kind"] for row in timeline]
    assert kinds == ["requested", "minted", "started"]
    assert [row["seq"] for row in timeline] == [1, 2, 3]
    started = timeline[-1]
    # The client's clock is preserved as evidence and never reorders history.
    assert started["at_client"] is not None
    assert started["at_server"] < started["at_client"]
    assert started["host"] == "runner-3"


def test_sweep_declares_a_silent_flow_abandoned(flow):
    minted = _mint(flow)
    job_id = minted["ticket"]["ticket_id"]
    swept = _abandon(flow, job_id)
    assert swept["abandoned"] == 1

    detail = flow["client"].get(f"/api/v1/scans/{job_id}",
                                headers=flow["headers"]).json()["data"]
    assert detail["status"] == "abandoned"
    kinds = [row["kind"] for row in flow["client"].get(
        f"/api/v1/scans/{job_id}/timeline", headers=flow["headers"]).json()["data"]]
    assert kinds[-2:] == ["lease_expired", "abandoned"]


def test_late_evidence_revives_without_rewriting_the_status(flow):
    minted = _mint(flow)
    ticket = minted["ticket"]
    job_id = ticket["ticket_id"]
    _abandon(flow, job_id)

    response = _evidence(flow, ticket)
    assert response.status_code == 201, response.text
    assert response.json()["data"]["revived"] is True

    detail = flow["client"].get(f"/api/v1/scans/{job_id}",
                                headers=flow["headers"]).json()["data"]
    # The verdict stays abandoned: that is the whole point of two axes.
    assert detail["status"] == "abandoned"
    assert detail["revived_at"] is not None
    assert detail["revival_count"] == 1
    assert detail["evidence"] == "partial"

    timeline = flow["client"].get(f"/api/v1/scans/{job_id}/timeline",
                                  headers=flow["headers"]).json()["data"]
    kinds = [row["kind"] for row in timeline]
    assert "revived" in kinds
    revived = next(row for row in timeline if row["kind"] == "revived")
    assert revived["detail"]["reason"] == "late_evidence"


def test_a_newer_flow_owns_the_commit_and_blocks_revival(flow):
    first = _mint(flow)
    _abandon(flow, first["ticket"]["ticket_id"])
    second = _mint(flow)
    assert second["ticket"]["ticket_id"] != first["ticket"]["ticket_id"]

    response = _evidence(flow, first["ticket"])
    assert response.status_code == 201
    assert response.json()["data"]["revived"] is False

    detail = flow["client"].get(f"/api/v1/scans/{first['ticket']['ticket_id']}",
                                headers=flow["headers"]).json()["data"]
    assert detail["status"] == "abandoned"
    assert detail["revival_count"] == 0


def test_liveness_is_a_gauge_not_a_status(flow):
    minted = _mint(flow)
    job_id = minted["ticket"]["ticket_id"]
    fresh = flow["client"].get(f"/api/v1/scans/{job_id}",
                               headers=flow["headers"]).json()["data"]
    assert fresh["indicators"]["alive"] is True

    session = flow["db"]()
    try:
        job = session.get(models.ScanJob, job_id)
        job.status = "abandoned"
        job.last_event_at = models.utcnow() - datetime.timedelta(minutes=10)
        session.commit()
    finally:
        session.close()

    stale = flow["client"].get(f"/api/v1/scans/{job_id}",
                               headers=flow["headers"]).json()["data"]
    assert stale["status"] == "abandoned"
    assert stale["indicators"]["alive"] is False
    assert stale["indicators"]["terminal"] is True


def test_cancel_is_an_instruction_and_it_sticks(flow):
    minted = _mint(flow)
    job_id = minted["ticket"]["ticket_id"]
    response = flow["client"].post(f"/api/v1/scans/{job_id}/cancel",
                                   params={"actor": "santiago"},
                                   headers=flow["headers"])
    assert response.status_code == 200
    assert response.json()["cancelled"] == "cancelled"
    detail = flow["client"].get(f"/api/v1/scans/{job_id}",
                                headers=flow["headers"]).json()["data"]
    assert detail["status"] == "cancelled"
    assert detail["indicators"]["killable"] is False


def test_a_confirmed_cancel_closes_the_flow(flow, monkeypatch):
    """When the executor acknowledges, the flow is cancelled — not left waiting
    for an event it has no reason to send."""
    from backend.app.routers import scans as scans_router

    minted = _mint(flow)
    job_id = minted["ticket"]["ticket_id"]
    session = flow["db"]()
    try:
        job = session.get(models.ScanJob, job_id)
        job.daemon_url = "http://daemon.test"
        session.commit()
    finally:
        session.close()
    monkeypatch.setattr(scans_router, "_post_json",
                        lambda *args, **kwargs: (200, {"cancelled": True}))

    response = flow["client"].post(f"/api/v1/scans/{job_id}/cancel",
                                   params={"actor": "santiago"},
                                   headers=flow["headers"])
    assert response.status_code == 200
    assert response.json()["cancelled"] == "confirmed"
    detail = flow["client"].get(f"/api/v1/scans/{job_id}",
                                headers=flow["headers"]).json()["data"]
    assert detail["status"] == "cancelled"
    assert detail["indicators"]["killable"] is False


def test_an_unconfirmed_cancel_stays_pending(flow, monkeypatch):
    from backend.app.routers import scans as scans_router

    minted = _mint(flow)
    job_id = minted["ticket"]["ticket_id"]
    session = flow["db"]()
    try:
        job = session.get(models.ScanJob, job_id)
        job.daemon_url = "http://daemon.test"
        session.commit()
    finally:
        session.close()
    monkeypatch.setattr(scans_router, "_post_json",
                        lambda *args, **kwargs: (0, {"error": "unreachable"}))

    response = flow["client"].post(f"/api/v1/scans/{job_id}/cancel",
                                   params={"actor": "santiago"},
                                   headers=flow["headers"])
    assert response.json()["cancelled"] == "requested_not_confirmed"
    detail = flow["client"].get(f"/api/v1/scans/{job_id}",
                                headers=flow["headers"]).json()["data"]
    assert detail["status"] == "cancel_requested"
    assert detail["indicators"]["killable"] is True


def test_a_flow_revives_once_and_the_rest_is_evidence(flow):
    """One revival per flow. Everything after it is evidence, never a second
    life: a second silent cycle has to be a new flow, or the timeline would claim
    one flow was abandoned twice."""
    minted = _mint(flow)
    ticket = minted["ticket"]
    job_id = ticket["ticket_id"]
    _abandon(flow, job_id)
    _evidence(flow, ticket, kind="sast")
    _evidence(flow, ticket, kind="secrets")

    detail = flow["client"].get(f"/api/v1/scans/{job_id}",
                                headers=flow["headers"]).json()["data"]
    assert detail["revival_count"] == 1
    assert detail["status"] == "abandoned"
    assert detail["evidence"] == "complete"
    kinds = [row["kind"] for row in flow["client"].get(
        f"/api/v1/scans/{job_id}/timeline", headers=flow["headers"]).json()["data"]]
    assert kinds.count("revived") == 1
    assert kinds.count("abandoned") == 1

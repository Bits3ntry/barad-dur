"""v0 cycles and My work: frozen reference, review/close, real queues, policy.

Acceptance steps 9, 10 and 12 of the spec are pinned here: activation freezes
the membership so later group edits do not rewrite it, candidates stay outside
the reference, the queues equal the authorized lists, and a requester can never
approve their own request.
"""
import sys
from datetime import timedelta
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
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/cycles.db")
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
    asset = models.Asset(org_id=org.id, type="domain", value="api-aurea.bitsentry.xyz",
                         source="scope", project_id=project.id)
    group = models.InventoryGroup(org_id=org.id, name="Production", tags=[])
    session.add_all([asset, group])
    session.flush()
    session.add(models.InventoryGroupMember(org_id=org.id, group_id=group.id,
                                            asset_id=asset.id, added_by="tester"))
    finding = models.Finding(org_id=org.id, project_id=project.id, kind="code-weakness",
                             fingerprint="fp-idor", source="manual", severity="HIGH",
                             title="IDOR on invoices", status="open",
                             first_seen_at=models.utcnow(), last_seen_at=models.utcnow())
    session.add(finding)
    session.flush()
    key = create_key(session, org.id, "cycles")
    other_key = create_key(session, other.id, "cycles-other")
    session.commit()
    from fastapi.testclient import TestClient
    return (TestClient(app), {"X-API-Key": key}, {"X-API-Key": other_key},
            {"project": project.slug, "asset": asset.id, "group": group.id,
             "finding": finding.id})


def _cycle(test_client, headers, **overrides):
    body = {"name": "Q4 AUREA", "description": "quarterly evaluation",
            "owner": "ana@bitsentry.xyz",
            "charter": {"objectives": ["validate AUREA"],
                        "success_criteria": ["no critical open at close"]},
            "selection": {"projects": ["aurea"]}, "actor": "tester"}
    body.update(overrides)
    response = test_client.post("/api/v1/cycles", json=body, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()["data"]


def test_activation_freezes_the_reference(seeded):
    test_client, headers, _other, ids = seeded
    empty = _cycle(test_client, headers, name="Empty", selection={})
    preview = test_client.post(f"/api/v1/cycles/{empty['id']}/preview",
                               headers=headers).json()["data"]
    assert preview["incomplete"] is True
    assert any("empty selection" in gap for gap in preview["gaps"])
    blocked = test_client.post(f"/api/v1/cycles/{empty['id']}/activate",
                               headers=headers)
    assert blocked.status_code == 409
    assert "empty selection" in blocked.json()["detail"]

    cycle = _cycle(test_client, headers)
    preview = test_client.post(f"/api/v1/cycles/{cycle['id']}/preview",
                               headers=headers).json()["data"]
    assert preview["incomplete"] is False
    assert preview["assets"] == 1
    assert preview["grants_authorization"] is False
    assert "does not authorize anything" in preview["note"]

    activated = test_client.post(f"/api/v1/cycles/{cycle['id']}/activate?actor=tester",
                                 headers=headers).json()
    assert activated["data"]["state"] == "active"
    assert activated["data"]["snapshot_at"]
    assert activated["data"]["members"] >= 2

    # Frozen: changing the group and adding a new asset does not rewrite it.
    test_client.delete(
        f"/api/v1/inventory/groups/{ids['group']}/assets/{ids['asset']}?actor=tester",
        headers=headers)
    session = session_factory()()
    org = session.query(models.Organization).filter_by(slug="bitsentry").one()
    project = session.query(models.Project).filter_by(slug="aurea").one()
    session.add(models.Asset(org_id=org.id, type="domain", value="new-aurea.bitsentry.xyz",
                             source="manual", project_id=project.id,
                             discovered_at=models.utcnow(),
                             last_seen_at=models.utcnow()))
    session.commit()
    session.close()

    detail = test_client.get(f"/api/v1/cycles/{cycle['id']}", headers=headers).json()["data"]
    assert detail["members"] >= 2, "the snapshot is untouched by later group edits"
    assert any(member["entity_type"] == "asset"
               for member in detail["membership"])

    candidates = test_client.get(f"/api/v1/cycles/{cycle['id']}/candidates",
                                 headers=headers).json()
    assert candidates["total"] == 1
    assert candidates["data"][0]["asset"]["value"] == "new-aurea.bitsentry.xyz"
    assert "next cycle" in candidates["note"]


def test_findings_review_and_close_keep_history(seeded):
    test_client, headers, _other, ids = seeded
    cycle = _cycle(test_client, headers)
    early = test_client.post(f"/api/v1/cycles/{cycle['id']}/link-findings",
                             json={"finding_ids": [ids["finding"]]}, headers=headers)
    assert early.status_code == 409, "link only after activation"

    test_client.post(f"/api/v1/cycles/{cycle['id']}/activate", headers=headers)
    linked = test_client.post(f"/api/v1/cycles/{cycle['id']}/link-findings", json={
        "finding_ids": [ids["finding"]], "actor": "tester"}, headers=headers).json()["data"]
    assert linked["linked"] == 1
    again = test_client.post(f"/api/v1/cycles/{cycle['id']}/link-findings", json={
        "finding_ids": [ids["finding"]], "actor": "tester"}, headers=headers).json()["data"]
    assert again["linked"] == 0, "linking twice does not duplicate"

    auto = test_client.post(f"/api/v1/cycles/{cycle['id']}/link-findings", json={
        "auto": True, "actor": "tester"}, headers=headers).json()["data"]
    assert auto["linked"] == 0, "the auto pass finds nothing new"

    bad_review = test_client.post(f"/api/v1/cycles/{cycle['id']}/review", json={
        "criteria": [{"name": "x", "verdict": "maybe"}]}, headers=headers)
    assert bad_review.status_code == 422

    review = test_client.post(f"/api/v1/cycles/{cycle['id']}/review", json={
        "results": "found one IDOR, one open",
        "criteria": [{"name": "no critical open", "verdict": "met"},
                     {"name": "all findings triaged", "verdict": "not_met"}],
        "learnings": "import SBOM earlier", "actor": "ana"}, headers=headers)
    assert review.status_code == 200, review.text
    assert review.json()["data"]["state"] == "review"

    closed = test_client.post(f"/api/v1/cycles/{cycle['id']}/close?actor=ana",
                              headers=headers).json()["data"]
    assert closed["state"] == "closed"

    history = test_client.get(f"/api/v1/cycles/{cycle['id']}", headers=headers).json()["data"]
    assert history["review"]["results"].startswith("found one IDOR")
    assert len(history["review"]["criteria"]) == 2
    assert history["findings"][0]["id"] == ids["finding"]


def test_my_work_trays_and_decision_policy(seeded):
    test_client, headers, _other, ids = seeded
    now = models.utcnow()
    soon = (now + timedelta(hours=48)).isoformat()
    later = (now + timedelta(days=10)).isoformat()

    test_client.patch(f"/api/v1/findings/{ids['finding']}/assignee", json={
        "assignee": "ana", "actor": "bob"}, headers=headers)

    task = test_client.post("/api/v1/my-work/items", json={
        "kind": "task", "title": "Fix the IDOR", "assignee": "ana",
        "requested_by": "bob", "finding_id": ids["finding"], "due_at": soon,
        "actor": "bob"}, headers=headers)
    assert task.status_code == 201, task.text
    task_id = task.json()["data"]["id"]

    far = test_client.post("/api/v1/my-work/items", json={
        "kind": "task", "title": "Later task", "assignee": "ana",
        "due_at": later, "actor": "bob"}, headers=headers).json()["data"]

    request = test_client.post("/api/v1/my-work/items", json={
        "kind": "request", "title": "Accept the risk", "requested_by": "bob",
        "reviewer": "ana", "due_at": soon, "actor": "bob"}, headers=headers)
    assert request.status_code == 201, request.text
    request_id = request.json()["data"]["id"]

    acceptance = test_client.post("/api/v1/my-work/items", json={
        "kind": "acceptance", "title": "Firewall exception", "requested_by": "bob",
        "reviewer": "ana", "valid_until": (now + timedelta(days=20)).isoformat(),
        "actor": "bob"}, headers=headers).json()["data"]

    work = test_client.get("/api/v1/my-work?actor=ana", headers=headers).json()["data"]
    trays = work["trays"]
    assert trays["assigned_to_me"]["count"] == 1
    assert trays["my_tasks"]["count"] == 2
    assert trays["awaiting_my_review"]["count"] == 1, "acceptances live in their own tray"
    assert trays["acceptances_expiring"]["count"] == 1

    urgent = test_client.get("/api/v1/my-work?actor=ana&due_within_hours=72",
                             headers=headers).json()["data"]["trays"]
    assert urgent["my_tasks"]["count"] == 1, "the 10-day task is outside 72h"
    assert urgent["my_tasks"]["items"][0]["id"] == task_id
    assert far["id"] not in [item["id"] for item in urgent["my_tasks"]["items"]]

    # Self-approval is refused at creation and at decision time.
    self_review = test_client.post("/api/v1/my-work/items", json={
        "kind": "request", "title": "I approve myself", "requested_by": "ana",
        "reviewer": "ana", "actor": "ana"}, headers=headers)
    assert self_review.status_code == 409

    as_requester = test_client.post(
        f"/api/v1/my-work/items/{request_id}/decide", json={
            "action": "approve", "reason": "mine", "actor": "bob"}, headers=headers)
    assert as_requester.status_code == 409 or as_requester.status_code == 403

    no_reason = test_client.post(
        f"/api/v1/my-work/items/{request_id}/decide", json={
            "action": "approve", "actor": "ana"}, headers=headers)
    assert no_reason.status_code == 422

    approved = test_client.post(
        f"/api/v1/my-work/items/{request_id}/decide", json={
            "action": "approve", "reason": "risk accepted for one quarter",
            "actor": "ana"}, headers=headers).json()["data"]
    assert approved["status"] == "approved"
    assert approved["decided_by"] == "ana"

    # Only the requester reminds, and not twice inside an hour.
    first = test_client.post(f"/api/v1/my-work/items/{task_id}/decide", json={
        "action": "remind", "actor": "bob"}, headers=headers)
    assert first.status_code == 200, first.text
    second = test_client.post(f"/api/v1/my-work/items/{task_id}/decide", json={
        "action": "remind", "actor": "bob"}, headers=headers)
    assert second.status_code == 429
    stolen = test_client.post(f"/api/v1/my-work/items/{task_id}/decide", json={
        "action": "remind", "actor": "ana"}, headers=headers)
    assert stolen.status_code == 403

    withdrawn = test_client.post(f"/api/v1/my-work/items/{task_id}/decide", json={
        "action": "withdraw", "actor": "ana"}, headers=headers)
    assert withdrawn.status_code == 403

    # Trays and their counters agree, and isolation holds.
    assert acceptance["valid_until"]
    other = test_client.get("/api/v1/my-work?actor=ana",
                            headers=seeded[2]).json()["data"]["trays"]
    assert other["my_tasks"]["count"] == 0
    assert test_client.post(f"/api/v1/my-work/items/{task_id}/decide", json={
        "action": "start", "actor": "ana"}, headers=seeded[2]).status_code == 404

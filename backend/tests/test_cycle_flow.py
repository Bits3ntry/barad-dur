"""The cycle flow: kinds, hand-written claims, and the per-cycle ledger.

Pins the parts of docs/planning/ctem-cycle-flow.md that make a cycle usable by a
person before any scanner runs: a closed set of exercise kinds (a KPI bucket is not
a free string), a manual finding that enters as a claim, the ledger filter that a
KPI reads, and the refusal to write into a closed window.
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
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/flow.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "flow")
    project = models.Project(org_id=org.id, name="AUREA", slug="aurea")
    session.add(project)
    session.flush()
    asset = models.Asset(org_id=org.id, type="domain", value="api.aurea.test",
                         source="scope", project_id=project.id)
    session.add(asset)
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), {"X-API-Key": key}, session, org, project, asset


def _create(client, headers, **body):
    payload = {"name": "External pentest Q4", "actor": "santiago"}
    payload.update(body)
    return client.post("/api/v1/cycles", json=payload, headers=headers)


def test_a_cycle_declares_which_exercise_it_is(env):
    client, headers, _session, _org, _project, _asset = env
    created = _create(client, headers, kind="pentest_external")
    assert created.status_code == 201, created.text
    assert created.json()["data"]["kind"] == "pentest_external"


def test_an_unknown_kind_is_refused_and_the_cycle_is_not_created(env):
    client, headers, session, org, _project, _asset = env
    refused = _create(client, headers, kind="pentest-ish")
    assert refused.status_code == 422
    assert "kind must be one of" in refused.json()["detail"]
    assert session.query(models.Cycle).filter_by(org_id=org.id).count() == 0


def test_a_cycle_without_a_kind_is_a_sweep(env):
    client, headers, _session, _org, _project, _asset = env
    assert _create(client, headers).json()["data"]["kind"] == "sweep"


def test_the_kind_is_frozen_once_the_cycle_is_activated(env):
    client, headers, _session, _org, _project, _asset = env
    cycle = _create(client, headers, kind="campaign",
                    selection={"whole_org": True}).json()["data"]
    still_planning = client.patch(f"/api/v1/cycles/{cycle['id']}",
                                  json={"kind": "pentest_internal"},
                                  headers=headers)
    assert still_planning.status_code == 200
    assert still_planning.json()["data"]["kind"] == "pentest_internal"
    activated = client.post(f"/api/v1/cycles/{cycle['id']}/activate",
                            headers=headers)
    assert activated.status_code == 200, activated.text
    frozen = client.patch(f"/api/v1/cycles/{cycle['id']}",
                          json={"kind": "sweep"}, headers=headers)
    assert frozen.status_code == 409


def test_a_hand_written_vulnerability_is_a_claim_linked_to_the_cycle(env):
    client, headers, session, org, _project, asset = env
    cycle = _create(client, headers, kind="pentest_external").json()["data"]
    client.post(f"/api/v1/cycles/{cycle['id']}/activate", headers=headers)

    recorded = client.post(
        f"/api/v1/cycles/{cycle['id']}/findings",
        json={"title": "Stored XSS in invoice preview", "severity": "high",
              "kind": "vulnerability", "vector": "network",
              "description": "Reported in the external pentest, page 12.",
              "asset_id": asset.id, "evidence_level": "observed",
              "actor": "santiago"},
        headers=headers)
    assert recorded.status_code == 201, recorded.text
    body = recorded.json()
    assert body["created"] is True
    assert body["data"]["triage_status"] == "new"

    claim = session.get(models.Finding, body["data"]["id"])
    # `origin` is the "who said so" axis. This claim came out of an external
    # pentest, so it says so — "manual" was the old answer and it made a pentest
    # finding indistinguishable from a note somebody typed.
    assert claim.origin == "pentest-external"
    assert claim.asset_id == asset.id
    assert claim.project_id == asset.project_id
    assert claim.triage_status == "new"
    assert session.query(models.CycleFinding).filter_by(
        cycle_id=cycle["id"], finding_id=claim.id).one().source == "manual"

    # And it does not count as posture until somebody confirms it.
    overview = client.get("/api/v1/ctem/overview", headers=headers).json()["data"]
    prioritization = next(p for p in overview["phases"] if p["key"] == "prioritization")
    counters = {metric["label"]: metric["value"] for metric in prioritization["metrics"]}
    assert counters["open findings"] == 0, counters


def test_recording_the_same_report_twice_does_not_mint_a_second_row(env):
    client, headers, session, org, _project, asset = env
    cycle = _create(client, headers, kind="pentest_external").json()["data"]
    body = {"title": "IDOR on /api/invoices", "severity": "critical",
            "asset_id": asset.id, "actor": "santiago"}
    first = client.post(f"/api/v1/cycles/{cycle['id']}/findings", json=body,
                        headers=headers)
    second = client.post(f"/api/v1/cycles/{cycle['id']}/findings", json=body,
                         headers=headers)
    assert first.status_code == 201
    assert second.status_code == 200
    assert second.json()["created"] is False
    assert second.json()["data"]["id"] == first.json()["data"]["id"]
    assert session.query(models.Finding).filter_by(org_id=org.id).count() == 1


def test_the_ledger_filter_answers_one_cycle_only(env):
    client, headers, session, org, _project, asset = env
    pentest = _create(client, headers, name="Pentest Q4",
                      kind="pentest_external").json()["data"]
    sweep = _create(client, headers, name="Sweep Q4", kind="sweep").json()["data"]
    client.post(f"/api/v1/cycles/{pentest['id']}/findings",
                json={"title": "Weak TLS on the API", "asset_id": asset.id},
                headers=headers)
    client.post(f"/api/v1/cycles/{sweep['id']}/findings",
                json={"title": "Expired certificate on the CDN"},
                headers=headers)

    ledger = client.get(f"/api/v1/findings?cycle={pentest['id']}",
                        headers=headers).json()
    assert ledger["total"] == 1
    assert ledger["data"][0]["title"] == "Weak TLS on the API"
    queue = client.get(f"/api/v1/findings?cycle={pentest['id']}&queue=true",
                       headers=headers).json()
    assert queue["total"] == 1, "a hand-written claim waits for a human"


def test_a_claim_cannot_be_recorded_in_a_closed_cycle(env):
    client, headers, _session, _org, _project, _asset = env
    cycle = _create(client, headers, kind="campaign",
                    selection={"whole_org": True}).json()["data"]
    client.post(f"/api/v1/cycles/{cycle['id']}/activate", headers=headers)
    client.post(f"/api/v1/cycles/{cycle['id']}/review",
                json={"results": "done", "criteria": [], "actor": "santiago"},
                headers=headers)
    client.post(f"/api/v1/cycles/{cycle['id']}/close", headers=headers)

    refused = client.post(f"/api/v1/cycles/{cycle['id']}/findings",
                          json={"title": "Late finding"}, headers=headers)
    assert refused.status_code == 409
    assert "closed cycle" in refused.json()["detail"]


def test_the_cycle_ledger_applies_the_human_key_and_attaches_the_asset(env):
    client, headers, session, org, _project, asset = env
    cycle = _create(client, headers, kind="pentest_external").json()["data"]
    client.post(f"/api/v1/cycles/{cycle['id']}/activate", headers=headers)
    recorded = client.post(
        f"/api/v1/cycles/{cycle['id']}/findings",
        json={"title": "Reflected XSS in search", "severity": "high",
              "url": f"https://{asset.value}/search?q=", "actor": "santiago"},
        headers=headers).json()["data"]
    claim = session.get(models.Finding, recorded["id"])
    assert claim.asset_id is None, "typing a finding does not attach it"

    decision = client.post(
        f"/api/v1/cycles/{cycle['id']}/findings/{claim.id}/decide",
        json={"decision": "validate", "actor": "santiago",
              "reason": "reproduced with a payload"},
        headers=headers)
    assert decision.status_code == 200, decision.text
    body = decision.json()["data"]
    assert body["triage_status"] == "triaged"
    assert body["status"] == "acknowledged"
    assert body["attached_asset"] == asset.id
    session.expire_all()
    confirmed = session.get(models.Finding, claim.id)
    assert confirmed.asset_id == asset.id
    assert confirmed.triaged_by == "santiago"
    assert confirmed.triage_note == "reproduced with a payload"


def test_a_decision_cannot_be_taken_through_another_cycles_ledger(env):
    client, headers, _session, _org, _project, _asset = env
    first = _create(client, headers, name="Pentest Q4",
                    kind="pentest_external").json()["data"]
    second = _create(client, headers, name="Sweep Q4", kind="sweep").json()["data"]
    finding = client.post(f"/api/v1/cycles/{first['id']}/findings",
                          json={"title": "Open S3 bucket"}, headers=headers).json()["data"]
    refused = client.post(
        f"/api/v1/cycles/{second['id']}/findings/{finding['id']}/decide",
        json={"decision": "dismiss"}, headers=headers)
    assert refused.status_code == 404
    assert "ledger" in refused.json()["detail"]


def test_a_closed_cycle_takes_no_decisions(env):
    client, headers, _session, _org, _project, _asset = env
    cycle = _create(client, headers, kind="campaign",
                    selection={"whole_org": True}).json()["data"]
    client.post(f"/api/v1/cycles/{cycle['id']}/activate", headers=headers)
    finding = client.post(f"/api/v1/cycles/{cycle['id']}/findings",
                          json={"title": "Late claim"}, headers=headers).json()["data"]
    client.post(f"/api/v1/cycles/{cycle['id']}/review",
                json={"results": "done", "criteria": [], "actor": "santiago"},
                headers=headers)
    client.post(f"/api/v1/cycles/{cycle['id']}/close", headers=headers)
    refused = client.post(
        f"/api/v1/cycles/{cycle['id']}/findings/{finding['id']}/decide",
        json={"decision": "validate"}, headers=headers)
    assert refused.status_code == 409
    assert "historical record" in refused.json()["detail"]


def test_the_charter_can_be_amended_while_the_cycle_runs(env):
    """Refusing the edit does not stop the learning, it only hides it. The frozen
    reference is what the review judges, so an amendment moves nothing."""
    client, headers, _session, _org, _project, _asset = env
    cycle = _create(client, headers, kind="campaign",
                    selection={"whole_org": True},
                    charter={"success_criteria": [
                        {"name": "no critical open", "metric": "open_critical",
                         "target": "0"}]}).json()["data"]
    client.post(f"/api/v1/cycles/{cycle['id']}/activate", headers=headers)

    amended = client.patch(f"/api/v1/cycles/{cycle['id']}", json={
        "charter": {"success_criteria": [
            {"name": "no critical open", "metric": "open_critical", "target": "0"}],
            "profiles": ["opportunistic external"],
            "objectives": ["reach the admin panel"]},
        "actor": "santiago"}, headers=headers)
    assert amended.status_code == 200, amended.text
    body = amended.json()["data"]
    assert body["amended"] is True
    assert body["charter"]["profiles"] == ["opportunistic external"]
    # The frozen copy still carries the charter as it was at activation.
    assert body["frozen_charter"].get("profiles") in (None, [])
    assert body["frozen_charter"]["success_criteria"][0]["name"] == "no critical open"


def test_a_selection_amendment_after_activation_rebuilds_the_membership(env):
    """The snapshot keeps the reference; the membership follows what is in scope now,
    so the engine and the screen cannot disagree about the campaign."""
    client, headers, session, org, _project, _asset = env
    cycle = _create(client, headers, selection={"whole_org": True}).json()["data"]
    client.post(f"/api/v1/cycles/{cycle['id']}/activate", headers=headers)
    amended = client.patch(f"/api/v1/cycles/{cycle['id']}",
                           json={"selection": {"projects": ["aurea"]}},
                           headers=headers)
    assert amended.status_code == 200, amended.text
    detail = client.get(f"/api/v1/cycles/{cycle['id']}", headers=headers).json()["data"]
    assert detail["amended"] is True
    assert detail["snapshot"]["selection"] == {"whole_org": True}
    assert {row["entity_type"] for row in detail["membership"]} <= {"project", "asset"}
    assert all(row["label"] == "aurea" or row["entity_type"] == "asset"
               for row in detail["membership"])


def test_a_closed_cycle_cannot_be_amended(env):
    client, headers, _session, _org, _project, _asset = env
    cycle = _create(client, headers, selection={"whole_org": True}).json()["data"]
    client.post(f"/api/v1/cycles/{cycle['id']}/activate", headers=headers)
    client.post(f"/api/v1/cycles/{cycle['id']}/review",
                json={"results": "done", "criteria": []}, headers=headers)
    client.post(f"/api/v1/cycles/{cycle['id']}/close", headers=headers)
    refused = client.patch(f"/api/v1/cycles/{cycle['id']}",
                           json={"charter": {"objectives": ["late"]}}, headers=headers)
    assert refused.status_code == 409
    assert "historical record" in refused.json()["detail"]

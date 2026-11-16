"""Cycle intake: a run's finding is a claim, and a person is what makes it a fact.

Pins D13-D16 of docs/planning/ctem-cycle-flow.md:

  * a job carries the cycle it was launched into;
  * ingest writes a finding for every target — including a host nobody has
    claimed — with `triage_status='new'` and no asset;
  * the claim links to the cycle, appears in no counted posture, and survives a
    second run as a duplicate;
  * validating from the run is what attaches the asset and puts the row into
    `COUNTED_TRIAGE`; dismissing keeps it as history and attaches nothing.
"""
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
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/intake.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "intake")
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), {"X-API-Key": key}, session, org


def _unclaimed_asset(session, org, value="nobody-claimed.example.com"):
    """A host in the inventory that nobody has filed into a project."""
    asset = models.Asset(org_id=org.id, type="domain", value=value, source="crt.sh")
    session.add(asset)
    session.commit()
    return asset


def _cycle(session, org, state="active", name="npm supply chain"):
    cycle = models.Cycle(org_id=org.id, name=name, state=state,
                         charter={"kind": "campaign"}, selection={"whole_org": True})
    session.add(cycle)
    session.commit()
    return cycle


def _job(session, org, cycle_id=None, status_value="running"):
    job = models.ScanJob(
        org_id=org.id, scanner="shauron-surface", capability="passive_discovery",
        principal="collector", targets=json.dumps([{"type": "domain",
                                                    "value": "nobody-claimed.example.com"}]),
        profile=json.dumps({"name": "recon.simple", "level": "simple"}),
        status=status_value, origin="cloud", executor="shauron",
        tasks="[]", ticket_json="{}", cycle_id=cycle_id)
    session.add(job)
    session.commit()
    return job


def _finding_payload(value="nobody-claimed.example.com"):
    return {"observations": [{
                "kind": "host", "subject": value, "coverage": "full",
                "value": {"state": "answered"}}],
            "findings": [{"rule_id": "exposed-git", "name": "Exposed .git directory",
                          "severity": "medium", "tool": "nuclei",
                          "matched_at": f"https://{value}/.git/config"}],
            "actor": "cli"}


def test_a_claim_is_written_for_an_unclaimed_host_and_links_to_the_cycle(env):
    client, headers, session, org = env
    asset = _unclaimed_asset(session, org)
    cycle = _cycle(session, org)
    job = _job(session, org, cycle_id=cycle.id)

    response = client.post(f"/api/v1/surface/runs/{job.id}/observations",
                           json=_finding_payload(), headers=headers)
    assert response.status_code == 200, response.text
    receipt = response.json()["findings"]
    assert receipt["created"] == 1
    assert receipt["cycle_linked"] == 1
    # The host was in the inventory but nobody filed it into a project: the claim
    # records where it pointed (and is named in the receipt) — nothing is attached
    # to the asset until a person says so.
    assert receipt["unattached"] == ["exposed-git"]

    claim = session.query(models.Finding).filter_by(org_id=org.id).one()
    assert claim.triage_status == "new"
    assert claim.asset_id is None
    assert claim.origin_run_id == job.id
    assert claim.evidence_level == "observed"
    assert session.query(models.CycleFinding).filter_by(
        cycle_id=cycle.id, finding_id=claim.id).one().source == "run"
    assert asset.id  # the asset exists and stayed unlinked on purpose


def test_a_claim_does_not_count_as_posture_until_a_person_confirms_it(env):
    client, headers, session, org = env
    _unclaimed_asset(session, org)
    cycle = _cycle(session, org)
    job = _job(session, org, cycle_id=cycle.id)
    client.post(f"/api/v1/surface/runs/{job.id}/observations",
                json=_finding_payload(), headers=headers)

    overview = client.get("/api/v1/ctem/overview", headers=headers).json()["data"]
    prioritization = next(p for p in overview["phases"] if p["key"] == "prioritization")
    counters = {metric["label"]: metric["value"] for metric in prioritization["metrics"]}
    assert counters["open findings"] == 0, counters
    assert counters["hypotheses"] == 0, counters

    claim = session.query(models.Finding).filter_by(org_id=org.id).one()
    decision = client.post(f"/api/v1/surface/runs/{job.id}/findings/{claim.id}",
                           json={"decision": "validate", "reason": "reproduced by hand",
                                 "actor": "santiago"}, headers=headers)
    assert decision.status_code == 200, decision.text
    session.expire_all()
    confirmed = session.get(models.Finding, claim.id)
    assert confirmed.triage_status == "triaged"
    assert confirmed.status == "acknowledged"
    assert confirmed.asset_id is not None
    assert confirmed.triaged_by == "santiago"

    overview = client.get("/api/v1/ctem/overview", headers=headers).json()["data"]
    prioritization = next(p for p in overview["phases"] if p["key"] == "prioritization")
    counters = {metric["label"]: metric["value"] for metric in prioritization["metrics"]}
    assert counters["open findings"] == 1, counters


def test_dismissing_a_claim_keeps_it_as_history_and_attaches_nothing(env):
    client, headers, session, org = env
    _unclaimed_asset(session, org)
    cycle = _cycle(session, org)
    job = _job(session, org, cycle_id=cycle.id)
    client.post(f"/api/v1/surface/runs/{job.id}/observations",
                json=_finding_payload(), headers=headers)
    claim = session.query(models.Finding).filter_by(org_id=org.id).one()

    decision = client.post(f"/api/v1/surface/runs/{job.id}/findings/{claim.id}",
                           json={"decision": "dismiss", "reason": "not exploitable",
                                 "actor": "santiago"}, headers=headers)
    assert decision.status_code == 200, decision.text
    session.expire_all()
    dismissed = session.get(models.Finding, claim.id)
    assert dismissed.status == "false_positive"
    assert dismissed.triage_status == "rejected"
    assert dismissed.asset_id is None
    assert dismissed.triage_note == "not exploitable"


def test_a_second_run_of_the_same_claim_is_a_duplicate_not_a_new_row(env):
    client, headers, session, org = env
    _unclaimed_asset(session, org)
    cycle = _cycle(session, org)
    job = _job(session, org, cycle_id=cycle.id)
    client.post(f"/api/v1/surface/runs/{job.id}/observations",
                json=_finding_payload(), headers=headers)
    again = client.post(f"/api/v1/surface/runs/{job.id}/observations",
                        json=_finding_payload(), headers=headers).json()["findings"]
    assert again["created"] == 0
    assert again["duplicates"] == 1
    assert session.query(models.Finding).filter_by(org_id=org.id).count() == 1


def test_a_claim_on_a_host_outside_the_inventory_is_kept_and_named(env):
    """The estate is 261/274 unclaimed: dropping these rows is what made a deep
    recon report nothing at all."""
    client, headers, session, org = env
    cycle = _cycle(session, org)
    job = _job(session, org, cycle_id=cycle.id)

    response = client.post(f"/api/v1/surface/runs/{job.id}/observations",
                           json=_finding_payload("never-seen.example.com"),
                           headers=headers)
    receipt = response.json()["findings"]
    assert receipt["created"] == 1
    assert receipt["unattached"] == ["exposed-git"]
    claim = session.query(models.Finding).filter_by(org_id=org.id).one()
    assert claim.asset_id is None and claim.project_id is None
    assert claim.triage_status == "new"


def test_a_run_without_a_cycle_still_records_the_claim(env):
    """System jobs are exempt from the cycle, not from the ledger."""
    client, headers, session, org = env
    _unclaimed_asset(session, org)
    job = _job(session, org, cycle_id=None)
    receipt = client.post(f"/api/v1/surface/runs/{job.id}/observations",
                          json=_finding_payload(), headers=headers).json()["findings"]
    assert receipt["created"] == 1
    assert receipt["cycle_linked"] == 0
    assert session.query(models.CycleFinding).count() == 0

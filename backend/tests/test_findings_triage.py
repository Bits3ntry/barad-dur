"""One triage queue (F3, D29–D30): four axes, one human gate, honest counts.

The properties that make the queue trustworthy, one test each:

* an agent's hypothesis is visible in the queue and invisible in the posture;
* a row cannot leave `new` without a person's name against it;
* proof is an artifact, not a label;
* impact cannot outrun proof;
* an asset-only finding exists without a fake project;
* a pentest engagement's finding is the same object as its queue row.
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
def context(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/triage.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "triage")
    project = models.Project(org_id=org.id, slug="api", name="api")
    session.add(project)
    asset = models.Asset(org_id=org.id, type="domain",
                         value="shop.example.test", source="manual")
    session.add(asset)
    session.commit()
    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, session, org, project, asset


def _finding(session, org, project, index=1, **extra):
    extra.setdefault("severity", "high")
    row = models.Finding(
        org_id=org.id, project_id=project.id if project else None,
        kind="sast", fingerprint=f"fp-{index}", source="openGrep",
        status="open", title=f"finding {index}",
        first_seen_at=models.utcnow(), last_seen_at=models.utcnow(), **extra)
    session.add(row)
    session.commit()
    return row


def _attachment(session, org, finding, name="request.txt"):
    row = models.FindingAttachment(
        org_id=org.id, finding_id=finding.id, name=name,
        media_type="text/plain", size_bytes=12, sha256="0" * 64,
        content="GET / HTTP/1.1")
    session.add(row)
    session.commit()
    return row


def test_axes_default_to_the_scanner_reading(context):
    http, headers, session, org, project, _ = context
    row = _finding(session, org, project)
    session.refresh(row)
    assert (row.origin, row.triage_status) == ("scanner", "triaged")
    assert (row.evidence_level, row.exploit_state) == ("observed", "none")
    data = http.get(f"/api/v1/findings/{row.id}", headers=headers).json()["data"]
    assert data["origin"] == "scanner"
    assert data["triage_status"] == "triaged"
    assert data["evidence_level"] == "observed"


def test_a_hypothesis_is_in_the_queue_and_out_of_the_posture(context):
    http, headers, session, org, project, _ = context
    _finding(session, org, project, index=1)
    hypothesis = _finding(session, org, project, index=2, origin="shauron-ai",
                          triage_status="new", evidence_level="hypothesis",
                          severity="critical")

    queue = http.get("/api/v1/findings?queue=true", headers=headers).json()
    assert [row["id"] for row in queue["data"]] == [hypothesis.id]

    overview = http.get("/api/v1/ctem/overview", headers=headers).json()["data"]
    phases = {phase["key"]: phase for phase in overview["phases"]}
    metrics = {metric["label"]: metric for metric in phases["prioritization"]["metrics"]}
    assert metrics["open findings"]["value"] == 1, "the hypothesis is not a finding yet"
    assert metrics["hypotheses"]["value"] == 1
    assert "awaiting triage" in metrics["open findings"]["hint"]
    assert "1" in metrics["open findings"]["hint"]


def test_leaving_new_records_who_did_it(context):
    http, headers, session, org, project, _ = context
    row = _finding(session, org, project, origin="shauron-ai",
                   triage_status="new", evidence_level="hypothesis")

    moved = http.post(f"/api/v1/findings/{row.id}/triage",
                      json={"triage_status": "triaged", "actor": "santiago",
                            "note": "reproducido a mano"}, headers=headers)
    assert moved.status_code == 200, moved.text
    data = moved.json()["data"]
    assert data["triage_status"] == "triaged"
    assert data["triaged_by"] == "santiago"
    assert data["triaged_at"]
    assert data["triage_note"] == "reproducido a mano"

    rejected = http.post(f"/api/v1/findings/{row.id}/triage",
                         json={"triage_status": "rejected", "actor": "santiago"},
                         headers=headers).json()["data"]
    assert rejected["triage_status"] == "rejected"


def test_a_verdict_needs_an_actor(context):
    http, headers, session, org, project, _ = context
    row = _finding(session, org, project, origin="shauron-ai", triage_status="new")
    assert http.post(f"/api/v1/findings/{row.id}/triage",
                     json={"triage_status": "triaged"}, headers=headers
                     ).status_code == 422


def test_proof_is_an_artifact(context):
    http, headers, session, org, project, _ = context
    row = _finding(session, org, project, origin="shauron-ai",
                   triage_status="new", evidence_level="hypothesis", path=None, line=None)

    # static without file:line is a claim, not a proof
    assert http.post(f"/api/v1/findings/{row.id}/triage",
                     json={"evidence_level": "static", "actor": "santiago"},
                     headers=headers).status_code == 422

    row.path = "src/db.py"
    row.line = 42
    session.commit()
    static = http.post(f"/api/v1/findings/{row.id}/triage",
                       json={"evidence_level": "static", "actor": "santiago"},
                       headers=headers)
    assert static.status_code == 200, static.text
    assert static.json()["data"]["evidence_level"] == "static"
    # a person made a call about it, so it left the queue in the same move
    assert static.json()["data"]["triage_status"] == "triaged"
    assert static.json()["data"]["triaged_by"] == "santiago"

    # observed with no attachment and no run is also just a claim
    bare = _finding(session, org, project, index=9, origin="shauron-ai",
                    triage_status="new", evidence_level="hypothesis")
    assert http.post(f"/api/v1/findings/{bare.id}/triage",
                     json={"evidence_level": "observed", "actor": "santiago"},
                     headers=headers).status_code == 422

    attachment = _attachment(session, org, bare)
    observed = http.post(f"/api/v1/findings/{bare.id}/triage",
                         json={"evidence_level": "observed",
                               "evidence_id": attachment.id,
                               "actor": "santiago"}, headers=headers)
    assert observed.status_code == 200, observed.text
    assert observed.json()["data"]["evidence_id"] == attachment.id


def test_impact_cannot_outrun_proof(context):
    http, headers, session, org, project, _ = context
    row = _finding(session, org, project, origin="shauron-ai",
                   triage_status="new", evidence_level="hypothesis")
    attachment = _attachment(session, org, row)

    early = http.post(f"/api/v1/findings/{row.id}/triage",
                      json={"exploit_state": "reproduced", "evidence_id": attachment.id,
                            "actor": "santiago"}, headers=headers)
    assert early.status_code == 422
    assert "proof" in early.json()["detail"]

    no_artifact = http.post(f"/api/v1/findings/{row.id}/triage",
                            json={"evidence_level": "observed",
                                  "exploit_state": "reproduced", "actor": "santiago"},
                            headers=headers)
    assert no_artifact.status_code == 422

    proven = http.post(f"/api/v1/findings/{row.id}/triage",
                       json={"evidence_level": "observed", "evidence_id": attachment.id,
                             "exploit_state": "reproduced", "actor": "santiago"},
                       headers=headers)
    assert proven.status_code == 200, proven.text
    assert proven.json()["data"]["exploit_state"] == "reproduced"

    overclaim = http.post(f"/api/v1/findings/{row.id}/triage",
                          json={"exploit_state": "effect_proven", "actor": "santiago"},
                          headers=headers)
    assert overclaim.status_code == 422, "effect_proven needs demonstrated evidence"

    demonstrated = http.post(f"/api/v1/findings/{row.id}/triage",
                             json={"evidence_level": "demonstrated",
                                   "evidence_id": attachment.id,
                                   "exploit_state": "effect_proven",
                                   "actor": "santiago"}, headers=headers)
    assert demonstrated.status_code == 200, demonstrated.text


def test_an_asset_only_finding_exists_without_a_project(context):
    http, headers, session, org, _project, asset = context
    row = models.Finding(org_id=org.id, project_id=None, asset_id=asset.id,
                         kind="misconfig", fingerprint="fp-asset", source="manual",
                         severity="medium", status="open", title="wp-admin expuesto",
                         origin="pentest-external", triage_status="new",
                         evidence_level="hypothesis",
                         first_seen_at=models.utcnow(), last_seen_at=models.utcnow())
    session.add(row)
    session.commit()

    listed = http.get("/api/v1/findings", headers=headers).json()
    assert [item["id"] for item in listed["data"]] == [row.id]
    data = http.get(f"/api/v1/findings/{row.id}", headers=headers).json()["data"]
    assert data["project_id"] is None
    assert data["asset_id"] == asset.id
    assert data["origin"] == "pentest-external"


def test_a_rejected_row_stops_counting(context):
    http, headers, session, org, project, _ = context
    row = _finding(session, org, project)
    before = http.get("/api/v1/ctem/overview", headers=headers).json()["data"]
    phases = {phase["key"]: phase for phase in before["phases"]}
    assert {m["label"]: m for m in phases["prioritization"]["metrics"]}[
        "open findings"]["value"] == 1

    http.post(f"/api/v1/findings/{row.id}/triage",
              json={"triage_status": "rejected", "actor": "santiago",
                    "note": "falso positivo"}, headers=headers)
    after = http.get("/api/v1/ctem/overview", headers=headers).json()["data"]
    phases = {phase["key"]: phase for phase in after["phases"]}
    assert {m["label"]: m for m in phases["prioritization"]["metrics"]}[
        "open findings"]["value"] == 0
    # Still visible in the queue view: rejection is a verdict, not a deletion.
    listed = http.get("/api/v1/findings?triage_status=rejected", headers=headers).json()
    assert [item["id"] for item in listed["data"]] == [row.id]


def test_a_pentest_finding_becomes_one_queue_row(context):
    http, headers, session, org, project, asset = context
    engagement = http.post("/api/v1/pentest/engagements",
                           json={"name": "Q4 externo", "project": "api"},
                           headers=headers)
    assert engagement.status_code in {200, 201}, engagement.text
    engagement_id = engagement.json()["data"]["id"]
    created = http.post(f"/api/v1/pentest/engagements/{engagement_id}/findings",
                        json={"title": "IDOR en /api/orders/{id}",
                              "severity": "HIGH", "actor": "pentester",
                              "asset_id": asset.id, "method": "manual",
                              "target": "https://shop.example.test",
                              "request_evidence": "GET /api/orders/2",
                              "response_evidence": "HTTP/1.1 200 ...",
                              "reproduction": "cambiar el id a otro tenant"},
                        headers=headers)
    assert created.status_code in {200, 201}, created.text
    pentest_id = created.json()["data"]["id"]

    first = http.post(f"/api/v1/pentest/findings/{pentest_id}/ingest",
                      json={"origin": "pentest-external", "actor": "santiago"},
                      headers=headers)
    assert first.status_code == 201, first.text
    queue_id = first.json()["data"]["finding_id"]

    # Ingesting twice is one row, not two: the engagement finding and the queue row
    # are the same object seen from two screens.
    again = http.post(f"/api/v1/pentest/findings/{pentest_id}/ingest",
                      json={"origin": "pentest-external", "actor": "santiago"},
                      headers=headers)
    assert again.json()["already_known"] is True
    assert again.json()["data"]["finding_id"] == queue_id
    assert session.query(models.Finding).filter_by(kind="pentest").count() == 1

    row = http.get(f"/api/v1/findings/{queue_id}", headers=headers).json()["data"]
    assert row["origin"] == "pentest-external"
    assert row["triage_status"] == "new", "a pentester's word is not a triage decision"
    assert row["evidence_level"] == "observed", "request/response is proof"
    assert row["asset_id"] == asset.id
    assert row["project_id"] == project.id

    pentest_rows = http.get(f"/api/v1/pentest/engagements/{engagement_id}/findings",
                            headers=headers).json()["data"]
    assert pentest_rows[0]["ingested_finding_id"] == queue_id


def test_unknown_values_are_refused(context):
    http, headers, session, org, project, _ = context
    row = _finding(session, org, project)
    assert http.post(f"/api/v1/findings/{row.id}/triage",
                     json={"triage_status": "meh", "actor": "x"},
                     headers=headers).status_code == 422
    assert http.post(f"/api/v1/findings/{row.id}/triage",
                     json={"evidence_level": "vibes", "actor": "x"},
                     headers=headers).status_code == 422
    assert http.post(f"/api/v1/findings/{row.id}/triage",
                     json={"actor": "x"}, headers=headers).status_code == 422

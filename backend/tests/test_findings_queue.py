"""A claim is not a finding until a person says so.

The cycle flow records what a pentester reported as a `Finding` row with
`triage_status="new"`, and `GET /findings` used to return it immediately — so
"reported in a cycle" and "confirmed in the estate" were the same row. The queue
(`?queue=true`) and the cycle's own ledger are the two places it belongs until the
decision is made.
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
def queue_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/queue.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    project = models.Project(org_id=org.id, slug="aurea", name="Aurea")
    session.add(project)
    cycle = models.Cycle(org_id=org.id, name="External Q4", kind="pentest_external",
                         state="active", created_by="tester")
    session.add(cycle)
    session.flush()

    def finding(fingerprint, triage, title):
        row = models.Finding(org_id=org.id, project_id=project.id, kind="vulnerability",
                             vector="sast", source="manual", fingerprint=fingerprint,
                             title=title, severity="HIGH", status="open",
                             triage_status=triage, origin="manual")
        session.add(row)
        session.flush()
        return row

    confirmed = finding("confirmed-1", "triaged", "SQL injection in /login")
    claim = finding("claim-1", "new", "IDOR in /orders/{id}")
    # A scanner's own claim is not held by a cycle, so it keeps the lifecycle it
    # always had: it is listed, with triage_status=new, until somebody moves it.
    scanner_claim = finding("scan-1", "new", "Outdated TLS cipher")
    scanner_claim.origin = "scanner"
    session.add(models.CycleFinding(org_id=org.id, cycle_id=cycle.id,
                                    finding_id=claim.id, source="manual"))
    session.commit()
    key = create_key(session, org.id, "queue")
    session.commit()
    session.close()
    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, {"cycle": cycle.id, "claim": claim.id}


def test_the_estate_list_does_not_show_a_claim_a_cycle_is_holding(queue_client):
    client, headers, ids = queue_client
    body = client.get("/api/v1/findings", headers=headers).json()
    titles = [row["title"] for row in body["data"]]
    assert "SQL injection in /login" in titles
    # A scanner's untriaged row survives: this screen hides what a cycle is still
    # deciding, not what a scan just reported.
    assert "Outdated TLS cipher" in titles
    assert "IDOR in /orders/{id}" not in titles
    # ...and the queue is a number the reader can see, so its absence is not silent.
    assert body["counters"]["queue"] == 2
    assert body["counters"]["listed"] == 2


def test_the_queue_asks_for_exactly_those_rows(queue_client):
    client, headers, _ids = queue_client
    body = client.get("/api/v1/findings?queue=true", headers=headers).json()
    assert {row["title"] for row in body["data"]} == {
        "IDOR in /orders/{id}", "Outdated TLS cipher"}
    assert body["total"] == 2


def test_the_cycle_ledger_keeps_its_own_claims(queue_client):
    client, headers, ids = queue_client
    body = client.get(f"/api/v1/findings?cycle={ids['cycle']}", headers=headers).json()
    # The decision is made here, so hiding the claim here would make the ledger
    # disagree with the screen that records it.
    assert [row["id"] for row in body["data"]] == [ids["claim"]]


def test_a_claim_keeps_the_exercise_and_the_build_it_came_from(queue_client):
    """Where it comes from and where it lives are part of the record, not detail."""
    client, headers, ids = queue_client
    session = session_factory()()
    org = session.query(models.Organization).first()
    project = session.query(models.Project).first()
    build = models.ProjectVersion(project_id=project.id, version="1.4.0")
    session.add(build)
    session.commit()
    cycle = session.get(models.Cycle, ids["cycle"])
    cycle.kind = "pentest_external"
    session.commit()
    session.close()

    body = client.post(f"/api/v1/cycles/{ids['cycle']}/findings",
                       json={"title": "Privilege escalation via JWT none-alg",
                             "severity": "critical", "kind": "code-weakness",
                             "vector": "sast", "version_id": build.id,
                             "actor": "tester"}, headers=headers).json()
    finding_id = body["data"]["id"]
    assert body["data"]["origin"] == "pentest-external"
    assert body["data"]["version_id"] == build.id
    assert body["data"]["triage_status"] == "new"

    seen = client.get(f"/api/v1/findings?cycle={ids['cycle']}", headers=headers).json()
    row = next(item for item in seen["data"] if item["id"] == finding_id)
    assert row["cycle"]["name"] == "External Q4"
    assert row["cycle"]["kind"] == "pentest_external"
    assert row["last_seen_version_id"] == build.id

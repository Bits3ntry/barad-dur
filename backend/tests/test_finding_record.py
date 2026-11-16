"""The professional record of a hand-written finding.

A pentest report is not a title and a url. These tests pin the fields that make a
claim reproducible — where it happened, with which session, what we expected and
what came back — and the reusable session recipe behind it.
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
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/record.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "record")
    project = models.Project(org_id=org.id, name="AUREA", slug="aurea")
    session.add(project)
    session.flush()
    jewel = models.ApplicationComponent(org_id=org.id, project_id=project.id,
                                        name="Backend", slug="backend",
                                        criticality="crown")
    asset = models.Asset(org_id=org.id, type="domain", value="api.aurea.test",
                         source="scope", project_id=project.id)
    session.add_all([jewel, asset])
    session.commit()
    from fastapi.testclient import TestClient

    return TestClient(app), {"X-API-Key": key}, session, org, project, asset, jewel


def _cycle(client, headers):
    return client.post("/api/v1/cycles", json={
        "name": "External pentest", "kind": "pentest_external",
        "selection": {"whole_org": True},
    }, headers=headers).json()["data"]


FULL_RECORD = {
    "title": "IDOR en /api/v1/invoices/{id}",
    "kind": "vulnerability",
    "severity": "high",
    "cwe": "CWE-639",
    "impact": "Cualquier cliente autenticado lee las facturas de otro.",
    "reproduction": "1. login como A  2. GET /api/v1/invoices/1042 con la cookie de A",
    "http_method": "GET",
    "endpoint": "/api/v1/invoices/1042",
    "url": "https://api.aurea.test/api/v1/invoices/1042",
    "auth_required": True,
    "expected_result": "403 para una factura ajena",
    "observed_result": "200 con el PDF de otro cliente",
    "validation_output": "HTTP/1.1 200 OK · 42 KB · invoice 1042 de B",
    "proof_request": "GET /api/v1/invoices/1042 HTTP/1.1\nHost: api.aurea.test\nCookie: session=A",
    "proof_response": "HTTP/1.1 200 OK\nContent-Type: application/pdf",
}


def _auth_profile(client, headers):
    created = client.post("/api/v1/auth-profiles", json={
        "name": "cliente A", "kind": "cookie", "headers": "Cookie: session=A",
        "login_steps": "POST /login {user:A,pass:A} -> cookie session",
    }, headers=headers)
    assert created.status_code == 201, created.text
    return created.json()["data"]


def test_a_finding_keeps_what_happened_where_and_how_to_replay_it(env):
    client, headers, _session, _org, _project, asset, jewel = env
    cycle = _cycle(client, headers)
    profile = _auth_profile(client, headers)
    recorded = client.post(f"/api/v1/cycles/{cycle['id']}/findings", json={
        **FULL_RECORD, "auth_profile_id": profile["id"],
        "asset_id": asset.id, "product_component_id": jewel.id,
    }, headers=headers)
    assert recorded.status_code == 201, recorded.text
    data = recorded.json()["data"]
    assert data["cwe"] == "CWE-639"
    assert data["http_method"] == "GET"
    assert data["endpoint"] == "/api/v1/invoices/1042"
    assert data["auth_required"] is True
    assert data["auth_profile_id"] == profile["id"]
    assert data["product_component_id"] == jewel.id
    assert "403" in data["expected_result"] and "200" in data["observed_result"]
    assert "Cookie: session=A" in data["proof_request"]
    assert data["first_seen_at"]

    listed = client.get(f"/api/v1/findings?cycle={cycle['id']}", headers=headers).json()
    row = listed["data"][0]
    assert row["auth_profile_name"] == "cliente A"
    assert row["product_component_name"] == "Backend"
    assert row["validation_output"].startswith("HTTP/1.1 200")


def test_the_same_weakness_on_two_endpoints_is_two_findings(env):
    client, headers, _session, _org, _project, _asset, _jewel = env
    cycle = _cycle(client, headers)
    first = client.post(f"/api/v1/cycles/{cycle['id']}/findings",
                        json=FULL_RECORD, headers=headers)
    second = client.post(f"/api/v1/cycles/{cycle['id']}/findings",
                         json={**FULL_RECORD, "endpoint": "/api/v1/invoices/1043"},
                         headers=headers)
    assert first.status_code == 201 and second.status_code == 201
    assert first.json()["data"]["id"] != second.json()["data"]["id"]


def test_the_same_endpoint_twice_is_one_claim(env):
    client, headers, _session, _org, _project, _asset, _jewel = env
    cycle = _cycle(client, headers)
    first = client.post(f"/api/v1/cycles/{cycle['id']}/findings",
                        json=FULL_RECORD, headers=headers)
    second = client.post(f"/api/v1/cycles/{cycle['id']}/findings",
                         json=FULL_RECORD, headers=headers)
    assert first.json()["created"] is True
    assert second.json()["created"] is False
    assert first.json()["data"]["id"] == second.json()["data"]["id"]


def test_a_session_recipe_is_reusable_and_cannot_be_deleted_while_in_use(env):
    client, headers, _session, _org, _project, _asset, _jewel = env
    cycle = _cycle(client, headers)
    profile = _auth_profile(client, headers)
    for endpoint in ("/a", "/b"):
        client.post(f"/api/v1/cycles/{cycle['id']}/findings",
                    json={**FULL_RECORD, "endpoint": endpoint,
                          "auth_profile_id": profile["id"]}, headers=headers)
    listed = client.get("/api/v1/auth-profiles", headers=headers).json()["data"]
    assert [row["name"] for row in listed] == ["cliente A"]
    refused = client.delete(f"/api/v1/auth-profiles/{profile['id']}", headers=headers)
    assert refused.status_code == 409
    assert "2 findings" in refused.json()["detail"]


def test_an_unknown_authentication_profile_is_refused(env):
    client, headers, _session, _org, _project, _asset, _jewel = env
    cycle = _cycle(client, headers)
    refused = client.post(f"/api/v1/cycles/{cycle['id']}/findings", json={
        **FULL_RECORD, "auth_profile_id": "0" * 32}, headers=headers)
    assert refused.status_code == 404


# ── the same record, from the estate door ──────────────────────────────────────
# The form that writes this is reachable from `#findings::new`; a claim does not
# need an engagement to exist, but it always needs to say where it lives.

def test_a_record_without_a_cycle_still_says_where_it_lives(env):
    client, headers, _session, _org, project, asset, jewel = env
    recorded = client.post("/api/v1/findings/record", json={
        **FULL_RECORD, "project": "aurea",
        "asset_id": asset.id, "product_component_id": jewel.id,
    }, headers=headers)
    assert recorded.status_code == 201, recorded.text
    data = recorded.json()["data"]
    assert data["project_id"] == project.id
    assert data["asset_id"] == asset.id
    assert data["cycle_id"] is None
    # A hand-written row is a claim until a person decides: no self-triage.
    assert data["triage_status"] == "new"


def test_naming_a_cycle_links_the_ledger(env):
    client, headers, _session, _org, _project, _asset, _jewel = env
    cycle = _cycle(client, headers)
    recorded = client.post("/api/v1/findings/record",
                           json={**FULL_RECORD, "project": "aurea",
                                 "cycle_id": cycle["id"]}, headers=headers)
    assert recorded.status_code == 201, recorded.text
    data = recorded.json()["data"]
    assert data["cycle_id"] == cycle["id"]
    listed = client.get(f"/api/v1/findings?cycle={cycle['id']}", headers=headers).json()
    assert [row["id"] for row in listed["data"]] == [data["id"]]


def test_the_same_record_twice_answers_already_known(env):
    client, headers, _session, _org, _project, _asset, _jewel = env
    first = client.post("/api/v1/findings/record",
                        json={**FULL_RECORD, "project": "aurea"}, headers=headers)
    second = client.post("/api/v1/findings/record",
                         json={**FULL_RECORD, "project": "aurea"}, headers=headers)
    assert first.status_code == 201
    assert second.status_code == 200
    assert second.json()["created"] is False
    assert second.json()["data"]["id"] == first.json()["data"]["id"]


def test_a_project_that_does_not_exist_is_a_404_not_an_orphan_record(env):
    client, headers, _session, _org, _project, _asset, _jewel = env
    refused = client.post("/api/v1/findings/record",
                          json={**FULL_RECORD, "project": "nope"}, headers=headers)
    assert refused.status_code == 404
    assert "project" in refused.json()["detail"]


def test_a_closed_cycle_takes_no_new_records(env):
    client, headers, session, _org, _project, _asset, _jewel = env
    cycle = _cycle(client, headers)
    row = session.get(models.Cycle, cycle["id"])
    row.state = "closed"
    session.commit()
    refused = client.post("/api/v1/findings/record",
                          json={**FULL_RECORD, "project": "aurea",
                                "cycle_id": cycle["id"]}, headers=headers)
    assert refused.status_code == 409

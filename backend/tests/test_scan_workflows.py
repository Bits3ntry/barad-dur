"""A workflow an organisation writes is a catalog profile that Shauron never shipped.

Three promises, each tested here: the rules are the engine's (a `simple` workflow
cannot smuggle in `nuclei`), cloning copies instead of inheriting, and a plan made
from a custom workflow is the same plan — same steps, same verdicts, same ticket.

The document rules matter more than the CRUD: a workflow that validates here and
fails in the engine would be a scan that costs a night and reports nothing.
"""
import datetime
import json
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import authorization, models, surface_plan  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/workflows.db")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="org", name="Org")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "workflows")
    # A grant wide enough for the passive/active steps these workflows use.
    grant = models.ScanGrant(
        org_id=org.id, principal=authorization.COLLECTOR_PRINCIPAL,
        capabilities="passive_discovery,active_verification", status="active",
        justification="test", issued_by="tester", policy_version=1, level="simple",
        source="manual", valid_from=models.utcnow(),
        valid_until=models.utcnow() + datetime.timedelta(days=30))
    session.add(grant)
    session.flush()
    grant.targets.append(models.ScanGrantTarget(
        grant_id=grant.id, target_type="domain", target_value="example.com"))
    session.commit()
    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, session, org


TWO_STAGES = [
    {"id": "discover", "from": "targets", "tools": ["dns"]},
    {"id": "probe", "from": "discover", "tools": ["tls", "http-head"]},
]


def test_clone_from_catalog_keeps_the_engine_document(env):
    client, headers, session, org = env
    body = client.post("/api/v1/surface/workflows",
                       headers=headers,
                       json={"label": "Mi recon", "clone_from": "recon.simple"}).json()["data"]
    assert body["slug"] == "org.mi-recon"
    assert body["cloned_from"] == "recon.simple"
    assert [stage["tools"] for stage in body["stages"]] == [
        stage["tools"] for stage in surface_plan.profile("recon.simple")["stages"]]


def test_a_simple_workflow_cannot_carry_a_redteam_tool(env):
    client, headers, _, _ = env
    response = client.post("/api/v1/surface/workflows", headers=headers, json={
        "label": "Atajo", "level": "simple", "stages": [
            {"id": "probe", "from": "targets", "tools": ["nuclei"]}]})
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "workflow.tool_above_level"
    assert response.json()["detail"]["at"] == "nuclei"


@pytest.mark.parametrize("document,code", [
    ({"stages": [{"id": "probe", "from": "targets", "tools": ["no-such-tool"]}]},
     "workflow.unknown_tool"),
    ({"stages": [{"id": "probe", "from": "nowhere", "tools": ["dns"]}]},
     "workflow.stage_unknown_from"),
    ({"stages": [{"id": "probe", "from": "targets", "tools": ["dns"]},
                 {"id": "probe", "from": "probe", "tools": ["tls"]}]},
     "workflow.stage_duplicate"),
    ({"stages": []}, "workflow.stage_empty"),
    ({"stages": [{"id": "probe", "from": "targets", "tools": []}]},
     "workflow.stage_tools_empty"),
    ({"stages": TWO_STAGES, "level": "ultra"}, "workflow.bad_level"),
    ({"stages": TWO_STAGES, "limits": {"timeout_s": 1}}, "workflow.limit_out_of_range"),
])
def test_the_engine_rules_are_the_rules(env, document, code):
    client, headers, _, _ = env
    payload = {"label": "Prueba", "level": "simple"}
    payload.update(document)
    response = client.post("/api/v1/surface/workflows", headers=headers, json=payload)
    assert response.status_code == 422, response.text
    assert response.json()["detail"]["code"] == code


def test_a_custom_workflow_plans_and_runs_like_a_catalog_one(env):
    client, headers, session, org = env
    created = client.post("/api/v1/surface/workflows", headers=headers, json={
        "label": "Dos etapas", "level": "simple", "slug": "dos-etapas",
        "stages": TWO_STAGES, "plane": ["cloud"]}).json()["data"]
    targets = [{"type": "domain", "value": "example.com"}]

    plan = client.post("/api/v1/surface/plan", headers=headers,
                       json={"workflow_id": created["id"], "plane": "cloud",
                             "targets": targets}).json()
    assert plan["plan"]["profile"] == "org.dos-etapas"
    assert plan["states"] == {"allow": 3}

    run = client.post("/api/v1/surface/runs", headers=headers,
                      json={"workflow_id": created["id"], "plane": "cloud",
                            "targets": targets})
    assert run.status_code == 201, run.text
    job = session.query(models.ScanJob).filter_by(org_id=org.id).one()
    ticket = json.loads(job.ticket_json)
    assert ticket["profile"] == "org.dos-etapas"
    # The ticket carries the steps, which is what the executor reads — the slug
    # is a label, never a lookup the worker has to be taught.
    assert [step["tool"] for stage in ticket["stages"] for step in stage["steps"]] == [
        "dns", "tls", "http-head"]


def test_editing_a_workflow_revalidates_the_whole_document(env):
    client, headers, _, _ = env
    created = client.post("/api/v1/surface/workflows", headers=headers, json={
        "label": "Editable", "level": "advanced", "stages": TWO_STAGES}).json()["data"]
    # Adding a redteam tool means raising the level in the same request: a
    # document is judged whole, so half an edit would be judged as half a doc.
    ok = client.patch(f"/api/v1/surface/workflows/{created['id']}", headers=headers,
                      json={"level": "redteam",
                            "stages": [{"id": "probe", "from": "targets",
                                        "tools": ["nuclei"]}]})
    assert ok.status_code == 200, ok.text
    assert ok.json()["data"]["stages"][0]["tools"] == ["nuclei"]
    # …and the same document under a `simple` level is refused, not stored.
    bad = client.patch(f"/api/v1/surface/workflows/{created['id']}", headers=headers,
                       json={"level": "simple"})
    assert bad.status_code == 422
    assert bad.json()["detail"]["code"] == "workflow.tool_above_level"


def test_archiving_hides_it_from_the_list_but_keeps_the_record(env):
    client, headers, session, org = env
    created = client.post("/api/v1/surface/workflows", headers=headers, json={
        "label": "Temporal", "level": "simple", "stages": TWO_STAGES}).json()["data"]
    client.delete(f"/api/v1/surface/workflows/{created['id']}?actor=tester", headers=headers)
    listed = client.get("/api/v1/surface/workflows", headers=headers).json()
    assert all(row["id"] != created["id"] for row in listed["mine"])
    assert session.query(models.ScanWorkflow).filter_by(id=created["id"]).one().archived

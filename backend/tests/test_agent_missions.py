"""The field runtime's platform half (F4): the envelope, the token, the gateway.

Five properties, one test each — every one of them is a way this loop could betray
the operator:

* a target outside the scope never becomes a mission;
* a task token opens one task and dies with its lease;
* the envelope is signed, and the signature covers the targets and the tools;
* the gateway refuses the next completion at the ceiling instead of truncating;
* a revoked mission stops at the boundary and keeps what it already produced.
"""
import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import auth_local, models  # noqa: E402
from backend.app.ai import engine  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def context(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/agent.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "agent")
    viewer = models.User(org_id=org.id, email="viewer@example.test", role="viewer")
    session.add(viewer)
    session.flush()
    raw = "viewer-token-agent"
    session.add(models.UserSession(
        org_id=org.id, user_id=viewer.id,
        token_hash=auth_local.token_hash(raw),
        expires_at=models.utcnow() + timedelta(hours=2)))
    session.add(models.ScopeTarget(
        org_id=org.id, target_type="url", value="https://app.example.test",
        status="active", capabilities=["active_verification", "passive_discovery"],
        include_apex=True))
    session.commit()
    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, {"Authorization": f"Bearer {raw}"}, \
        session, org


def _mission(http, headers, approve=True, **extra):
    """Create a mission. Approved by default: the gate has its own test, and every
    other test is about what happens once a human said yes."""
    payload = {"goal": "reproduce finding f-1 (SQLi in /api/search)",
               "capability": "validate",
               "targets": [{"kind": "url", "value": "https://app.example.test",
                            "methods": ["GET", "POST"]}],
               "tools": ["curl", "python"], "actor": "santiago",
               "budget": {"steps": 6, "tokens": 2000, "wall_s": 300, "usd": 0.5},
               **extra}
    created = http.post("/api/v1/agent/missions", json=payload, headers=headers)
    if approve and created.status_code == 201:
        mission_id = created.json()["data"]["id"]
        http.post(f"/api/v1/agent/missions/{mission_id}/approve", headers=headers)
        return http.get(f"/api/v1/agent/missions/{mission_id}", headers=headers)
    return created


def _claimed(context, **task_extra):
    http, headers, _, session, _ = context
    mission = _mission(http, headers).json()["data"]
    task = http.post(f"/api/v1/agent/missions/{mission['id']}/tasks",
                     json={"kind": "validate.finding",
                           "target": {"kind": "url",
                                      "value": "https://app.example.test",
                                      "methods": ["GET", "POST"]},
                           "must_return": ["request", "response"], **task_extra},
                     headers=headers).json()["data"]
    claim = http.post(f"/api/v1/agent/tasks/{task['id']}/claim",
                      json={"worker": "shauron-1"}, headers=headers).json()["data"]
    return mission, task, claim


def test_the_exploit_lane_needs_a_permission_and_a_grant(context):
    http, headers, _, session, _ = context

    # Morgoth may ask for `exploit`, but red teaming is off by default.
    off = http.post("/api/v1/agent/missions", json={
        "goal": "prove impact", "capability": "exploit", "actor": "santiago",
        "grant_id": "g-1",
        "targets": [{"kind": "url", "value": "https://app.example.test"}]},
        headers=headers)
    assert off.status_code == 403
    assert "red-team" in off.json()["detail"]

    settings = session.get(models.AiSettings, "default")
    if settings is None:
        settings = models.AiSettings(id="default")
        session.add(settings)
    settings.redteam_allowed = True
    session.commit()

    no_grant = http.post("/api/v1/agent/missions", json={
        "goal": "prove impact", "capability": "exploit", "actor": "santiago",
        "targets": [{"kind": "url", "value": "https://app.example.test"}]},
        headers=headers)
    assert no_grant.status_code == 422
    assert "grant_id" in no_grant.json()["detail"]

    allowed = http.post("/api/v1/agent/missions", json={
        "goal": "prove impact", "capability": "exploit", "actor": "santiago",
        "grant_id": "g-1", "grant_level": "redteam",
        "targets": [{"kind": "url", "value": "https://app.example.test"}]},
        headers=headers)
    assert allowed.status_code == 201, allowed.text
    assert allowed.json()["data"]["profile"] == "morgoth"


def test_a_profile_cannot_open_a_lane_it_does_not_own(context):
    http, headers, _, _, _ = context
    wrong = http.post("/api/v1/agent/missions", json={
        "goal": "scan the surface", "capability": "discover", "profile": "angmar",
        "actor": "santiago",
        "targets": [{"kind": "url", "value": "https://app.example.test"}]},
        headers=headers)
    assert wrong.status_code == 422
    assert "may not open" in wrong.json()["detail"]


def test_the_capability_decides_the_profile(context):
    http, headers, _, _, _ = context
    validate = _mission(http, headers).json()["data"]
    assert validate["profile"] == "angmar"
    discover = http.post("/api/v1/agent/missions", json={
        "goal": "map the surface", "capability": "discover", "actor": "santiago",
        "targets": [{"kind": "url", "value": "https://app.example.test"}]},
        headers=headers).json()["data"]
    assert discover["profile"] == "morgoth"


def test_the_envelope_names_the_profile(context):
    _, _, claim = _claimed(context)
    assert claim["envelope"]["profile"] == "angmar"


def test_a_target_outside_the_scope_never_becomes_a_mission(context):
    http, headers, _, session, org = context
    refused = http.post("/api/v1/agent/missions", json={
        "goal": "probe a customer's site",
        "capability": "validate",
        "targets": [{"kind": "url", "value": "https://no-es-nuestro.example.com"}],
        "tools": ["curl"], "actor": "santiago"}, headers=headers)
    assert refused.status_code == 422
    detail = refused.json()["detail"]
    assert "outside the effective scope" in json.dumps(detail)
    assert session.query(models.AgentMission).count() == 0


def test_a_viewer_cannot_authorize_a_mission(context):
    http, _, viewer_headers, _, _ = context
    response = http.post("/api/v1/agent/missions", json={
        "goal": "x", "capability": "validate", "actor": "v",
        "targets": [{"kind": "url", "value": "https://app.example.test"}]},
        headers=viewer_headers)
    assert response.status_code == 403


def test_the_envelope_is_signed_and_carries_the_budget(context):
    http, headers = context[0], context[1]
    mission, _, claim = _claimed(context)
    envelope = claim["envelope"]
    assert envelope["schema"] == "barad-mission-v1"
    assert envelope["signature"].startswith("ed25519:")
    assert envelope["key_id"] == "barad-scan-v1"
    assert envelope["targets"][0]["value"] == "https://app.example.test"
    assert envelope["tools"] == ["curl", "python"]
    assert envelope["budget"]["tokens"] == 2000
    assert envelope["must_return"] == ["request", "response"]
    assert mission["status"] == "approved", "a mission is authorized before it runs"
    running = http.get(f"/api/v1/agent/missions/{mission['id']}",
                       headers=headers).json()["data"]
    assert running["status"] == "running", "the first claim opens the mission"
    assert claim["token"] and len(claim["token"]) == 48
    # the token is stored hashed, never in the clear
    assert claim["token"] not in json.dumps(mission)


def test_a_task_is_leased_to_one_worker(context):
    http, headers, _, _, _ = context
    mission, task, _ = _claimed(context)
    second = http.post(f"/api/v1/agent/tasks/{task['id']}/claim",
                       json={"worker": "shauron-2"}, headers=headers)
    assert second.status_code == 409
    assert "leased" in second.json()["detail"]


def test_a_task_cannot_widen_the_mission(context):
    http, headers, _, _, _ = context
    mission = _mission(http, headers).json()["data"]
    widened = http.post(f"/api/v1/agent/missions/{mission['id']}/tasks",
                        json={"kind": "validate.finding",
                              "target": {"kind": "url",
                                         "value": "https://otro.example.com"}},
                        headers=headers)
    assert widened.status_code == 422
    assert "not in the mission envelope" in widened.json()["detail"]


def test_events_are_batched_and_the_final_one_closes_the_task(context):
    http, headers, _, session, _ = context
    mission, task, claim = _claimed(context)
    token_headers = {"X-Agent-Token": claim["token"]}

    posted = http.post(f"/api/v1/agent/tasks/{task['id']}/events", json={"events": [
        {"kind": "tool", "tool": "curl", "payload": {"cmd": "curl -s"}},
        {"kind": "observation", "payload": {"status": 200, "len": 42}},
        {"kind": "final", "payload": {"request": "GET /api/search?q='",
                                      "response": "HTTP/1.1 500",
                                      "state": "reproduced"}},
    ]}, headers=token_headers)
    assert posted.status_code == 202, posted.text
    assert posted.json()["data"]["accepted"] == 3
    assert posted.json()["task"]["status"] == "done"

    events = http.get(f"/api/v1/agent/tasks/{task['id']}/events",
                      headers=headers).json()["data"]
    assert [event["kind"] for event in events] == ["tool", "observation", "final"]
    assert events[2]["payload"]["state"] == "reproduced"

    detail = http.get(f"/api/v1/agent/missions/{mission['id']}",
                      headers=headers).json()["data"]
    assert detail["status"] == "done"


def test_a_token_opens_only_its_own_task(context):
    http, headers, _, _, _ = context
    mission, first, claim = _claimed(context)
    second = http.post(f"/api/v1/agent/missions/{mission['id']}/tasks",
                       json={"kind": "validate.finding",
                             "target": {"kind": "url",
                                        "value": "https://app.example.test"}},
                       headers=headers).json()["data"]
    crossed = http.post(f"/api/v1/agent/tasks/{second['id']}/events",
                        json={"events": [{"kind": "note", "payload": {}}]},
                        headers={"X-Agent-Token": claim["token"]})
    assert crossed.status_code == 403
    assert "another task" in crossed.json()["detail"]

    anonymous = http.post(f"/api/v1/agent/tasks/{first['id']}/events",
                          json={"events": [{"kind": "note", "payload": {}}]},
                          headers={"X-API-Key": headers["X-API-Key"]})
    assert anonymous.status_code == 401, "an API key is not a task token"


def test_the_scope_proxy_records_the_refusal(context):
    http, headers, _, _, _ = context
    _, task, claim = _claimed(context)
    token_headers = {"X-Agent-Token": claim["token"]}

    inside = http.post("/api/v1/agent/scope/check",
                       json={"target_type": "url", "value": "https://app.example.test",
                             "capability": "validate"}, headers=token_headers)
    assert inside.json()["data"]["allowed"] is True

    outside = http.post("/api/v1/agent/scope/check",
                        json={"target_type": "url", "value": "https://elsewhere.test",
                              "capability": "validate"}, headers=token_headers)
    assert outside.json()["data"]["allowed"] is False
    assert outside.json()["data"]["reason"]

    events = http.get(f"/api/v1/agent/tasks/{task['id']}/events",
                      headers=headers).json()["data"]
    refusals = [event for event in events if event["kind"] == "refusal"]
    assert refusals and refusals[0]["payload"]["target"] == "https://elsewhere.test"


def test_revoking_stops_the_boundary_and_keeps_the_work(context):
    http, headers, _, session, _ = context
    mission, task, claim = _claimed(context)
    token_headers = {"X-Agent-Token": claim["token"]}
    http.post(f"/api/v1/agent/tasks/{task['id']}/events",
              json={"events": [{"kind": "observation",
                                "payload": {"partial": "half the payload"}}]},
              headers=token_headers)

    revoked = http.post(f"/api/v1/agent/missions/{mission['id']}/revoke",
                        headers=headers)
    assert revoked.status_code == 200
    assert revoked.json()["stopped"] == 1
    assert revoked.json()["data"]["status"] == "revoked"

    blocked = http.post(f"/api/v1/agent/scope/check",
                        json={"value": "https://app.example.test"},
                        headers=token_headers)
    assert blocked.status_code == 403
    assert "revoked" in blocked.json()["detail"]

    again = http.post(f"/api/v1/agent/tasks/{task['id']}/claim",
                      json={"worker": "shauron-3"}, headers=headers)
    assert again.status_code == 409

    # The partial observation survives the kill switch: evidence is not rolled back.
    events = http.get(f"/api/v1/agent/tasks/{task['id']}/events",
                      headers=headers).json()["data"]
    assert events[0]["payload"]["partial"] == "half the payload"


def test_the_token_dies_with_the_final_event(context):
    """A finished task holds no credential: the lease ends where the work ends."""
    http, headers, _, _, _ = context
    _, task, claim = _claimed(context)
    token_headers = {"X-Agent-Token": claim["token"]}
    http.post(f"/api/v1/agent/tasks/{task['id']}/events",
              json={"events": [{"kind": "final",
                                "payload": {"request": "GET /", "response": "200"}}]},
              headers=token_headers)
    spent = http.post("/api/v1/agent/scope/check",
                      json={"value": "https://app.example.test"},
                      headers=token_headers)
    assert spent.status_code == 401
    assert "spent" in spent.json()["detail"]


def test_the_gateway_refuses_at_the_ceiling_and_records_usage(context, monkeypatch):
    http, headers, _, session, org = context
    mission, task, claim = _claimed(context)
    token_headers = {"X-Agent-Token": claim["token"]}

    provider = models.AiProvider(name="stub", kind="openai-compatible",
                                 base_url="http://llm.test/v1", model="small",
                                 secret_cipher="sealed", price_in=1.0, price_out=1.0,
                                 is_default=True)
    session.add(provider)
    session.flush()
    run = models.AiRun(org_id=org.id, actor="santiago", actor_role="analyst",
                       question=mission["goal"], mode="act", status="running",
                       provider_id=provider.id, model="small")
    session.add(run)
    session.flush()
    row = session.get(models.AgentMission, mission["id"])
    row.run_id = run.id
    session.commit()

    monkeypatch.setattr("backend.app.secrets.open_sealed", lambda s, c: "sk")
    monkeypatch.setattr(engine, "complete",
                        lambda provider, key, messages, tools, transport=None,
                        session_id=None, max_tokens=None: {
                            "content": "llamá a curl -s https://app.example.test",
                            "tool_calls": [], "tokens_in": 700, "tokens_out": 300})

    first = http.post("/api/v1/agent/llm/complete",
                      json={"messages": [{"role": "user", "content": "hola"}]},
                      headers=token_headers)
    assert first.status_code == 200, first.text
    assert first.json()["data"]["mission_tokens_spent"] == 1000

    step = (session.query(models.AiStep).filter_by(run_id=run.id).one())
    assert step.role == "field"
    assert step.tokens_in == 700 and step.tokens_out == 300

    # The mission's own ceiling is 2000 tokens; two more 1000-token calls hit it.
    http.post("/api/v1/agent/llm/complete",
              json={"messages": [{"role": "user", "content": "otra"}]},
              headers=token_headers)
    capped = http.post("/api/v1/agent/llm/complete",
                       json={"messages": [{"role": "user", "content": "y otra"}]},
                       headers=token_headers)
    assert capped.status_code == 429
    assert "mission token budget reached" in capped.json()["detail"]


def test_the_gateway_without_a_provider_says_so(context):
    http, headers, _, _, _ = context
    _, _, claim = _claimed(context)
    response = http.post("/api/v1/agent/llm/complete",
                         json={"messages": [{"role": "user", "content": "hola"}]},
                         headers={"X-Agent-Token": claim["token"]})
    assert response.status_code == 503
    assert "Settings" in response.json()["detail"]


def test_a_mission_waits_for_a_human_before_anything_is_dispatched(context):
    """The gate: creation is not authorization, and a task cannot jump it."""
    http, headers, _, session, _ = context
    created = _mission(http, headers, approve=False)
    assert created.status_code == 201
    mission = created.json()["data"]
    assert mission["status"] == "awaiting_approval"
    assert mission["approved_by"] is None

    blocked = http.post(f"/api/v1/agent/missions/{mission['id']}/tasks",
                        json={"kind": "validate.finding",
                              "target": {"kind": "url",
                                         "value": "https://app.example.test"}},
                        headers=headers)
    assert blocked.status_code == 409
    assert "awaits approval" in blocked.json()["detail"]

    approved = http.post(f"/api/v1/agent/missions/{mission['id']}/approve",
                         headers=headers).json()["data"]
    assert approved["status"] == "approved"
    assert approved["approved_by"] == "console"
    assert approved["approved_at"]

    allowed = http.post(f"/api/v1/agent/missions/{mission['id']}/tasks",
                        json={"kind": "validate.finding",
                              "target": {"kind": "url",
                                         "value": "https://app.example.test"}},
                        headers=headers)
    assert allowed.status_code == 201


def test_rejecting_a_mission_keeps_the_reason(context):
    http, headers, _, session, _ = context
    mission = _mission(http, headers, approve=False).json()["data"]
    rejected = http.post(f"/api/v1/agent/missions/{mission['id']}/reject",
                         json={"reason": "targets outside this quarter"},
                         headers=headers).json()["data"]
    assert rejected["status"] == "revoked"

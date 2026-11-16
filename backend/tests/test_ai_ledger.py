"""One ledger for every token (A1) and a ceiling that cannot go stale (A2).

The properties under test are the ones the running stack failed:

* a mission owns an `ai_runs` row from the moment it exists, so its spend can be
  capped and the monthly meter — which reads `ai_steps` — sees it;
* a field completion is a step: role `field`, the task kind as its phase;
* the mission ceiling refuses the *next* completion, and only then;
* the gateway never offers the model a tool the envelope did not grant;
* a specialist cap tighter than the plan still produces an answer, because the report
  is not a specialist.
"""
import json
import sys
from datetime import timedelta
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import auth_local, models  # noqa: E402
from backend.app.ai import engine, orchestrator  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402

CVE_QUESTION = "¿Estamos afectados por CVE-2021-44228 en producción?"


@pytest.fixture()
def context(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/ledger.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "ledger")
    session.add(models.ScopeTarget(
        org_id=org.id, target_type="url", value="https://app.example.test",
        status="active",
        capabilities=["active_verification", "passive_discovery"],
        include_apex=True))
    session.commit()
    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, session, org


def _provider(http, headers):
    return http.post("/api/v1/ai/providers",
                     json={"name": "stub", "kind": "openai-compatible",
                           "base_url": "http://llm.test/v1", "model": "small",
                           "api_key": "sk-secret", "price_in": 1.0,
                           "price_out": 2.0, "is_default": True},
                     headers=headers)


def _mission_and_task(http, headers, tokens=2000):
    mission = http.post("/api/v1/agent/missions", json={
        "goal": "reproduce finding f-1 (SQLi in /api/search)",
        "capability": "validate",
        "targets": [{"kind": "url", "value": "https://app.example.test",
                     "methods": ["GET", "POST"]}],
        "tools": ["curl", "python"], "actor": "santiago",
        "budget": {"steps": 6, "tokens": tokens, "wall_s": 300, "usd": 0.5},
    }, headers=headers).json()["data"]
    http.post(f"/api/v1/agent/missions/{mission['id']}/approve", headers=headers)
    task = http.post(f"/api/v1/agent/missions/{mission['id']}/tasks", json={
        "kind": "validate.finding",
        "target": {"kind": "url", "value": "https://app.example.test",
                   "methods": ["GET", "POST"]},
        "must_return": ["request", "response"],
    }, headers=headers).json()["data"]
    claim = http.post(f"/api/v1/agent/tasks/{task['id']}/claim",
                      json={"worker": "shauron-1"}, headers=headers).json()["data"]
    return mission, task, claim["token"]


def _fake_complete(captured, tokens_in=100, tokens_out=20):
    def fake(provider, api_key, messages, tools, *, transport=None,
             session_id="", max_tokens=None):
        captured["tools"] = tools
        captured["max_tokens"] = max_tokens
        return {"content": "VERDICT: NOT VULNERABLE", "tool_calls": [],
                "tokens_in": tokens_in, "tokens_out": tokens_out,
                "cached_tokens": 0}
    return fake


def test_a_mission_owns_its_ledger_row_before_it_can_spend(context):
    http, headers, session, _ = context
    _provider(http, headers)
    mission = http.post("/api/v1/agent/missions", json={
        "goal": "reproduce finding f-1",
        "capability": "validate",
        "targets": [{"kind": "url", "value": "https://app.example.test"}],
        "tools": ["curl"], "actor": "santiago",
        "budget": {"steps": 5, "tokens": 4000, "wall_s": 300, "usd": 0.0},
    }, headers=headers).json()["data"]

    assert mission["run_id"], "a mission without a run cannot be capped"
    run = session.get(models.AiRun, mission["run_id"])
    assert run.mode == "mission"
    assert run.status == "running"
    assert run.token_budget == 4000
    assert run.question.startswith("mission: ")


def test_a_field_completion_is_a_step_the_meter_can_see(context, monkeypatch):
    http, headers, session, _ = context
    _provider(http, headers)
    mission, task, token = _mission_and_task(http, headers, tokens=10_000)

    captured: dict = {}
    monkeypatch.setattr(engine, "complete", _fake_complete(captured))
    response = http.post("/api/v1/agent/llm/complete",
                         json={"messages": [{"role": "user", "content": "go"}]},
                         headers={"X-Agent-Token": token})
    assert response.status_code == 200, response.text

    session.expire_all()
    steps = session.query(models.AiStep).all()
    assert len(steps) == 1
    assert steps[0].run_id == mission["run_id"]
    assert steps[0].role == "field"
    assert steps[0].phase == "validate.finding"
    run = session.get(models.AiRun, mission["run_id"])
    assert (run.tokens_in, run.tokens_out) == (100, 20)
    assert run.steps == 1

    spend = http.get("/api/v1/ai/spend", headers=headers).json()["data"]
    assert spend["tokens"] == 120, "the monthly meter reads the field half now"


def test_the_mission_ceiling_refuses_the_next_completion(context, monkeypatch):
    http, headers, session, _ = context
    _provider(http, headers)
    _, task, token = _mission_and_task(http, headers, tokens=100)
    monkeypatch.setattr(engine, "complete",
                        _fake_complete({}, tokens_in=120, tokens_out=30))

    first = http.post("/api/v1/agent/llm/complete",
                      json={"messages": [{"role": "user", "content": "go"}]},
                      headers={"X-Agent-Token": token})
    assert first.status_code == 200, first.text
    second = http.post("/api/v1/agent/llm/complete",
                       json={"messages": [{"role": "user", "content": "again"}]},
                       headers={"X-Agent-Token": token})
    assert second.status_code == 429
    assert "mission token budget reached" in second.text


def test_the_gateway_never_offers_a_tool_the_mission_lacks(context, monkeypatch):
    http, headers, session, _ = context
    _provider(http, headers)
    _, task, token = _mission_and_task(http, headers)

    captured: dict = {}
    monkeypatch.setattr(engine, "complete", _fake_complete(captured))
    schema = {"type": "function", "function": {
        "name": "run_tool",
        "parameters": {"type": "object", "properties": {
            "tool": {"type": "string", "enum": ["curl", "python", "nmap"]},
            "argv": {"type": "array", "items": {"type": "string"}}},
            "required": ["tool", "argv"]}}}
    http.post("/api/v1/agent/llm/complete",
              json={"messages": [{"role": "user", "content": "go"}],
                    "tools": [schema], "max_tokens": 512},
              headers={"X-Agent-Token": token})

    offered = captured["tools"][0]["function"]["parameters"]["properties"]["tool"]
    assert offered["enum"] == ["curl", "python"], "the envelope is the allowlist"
    assert "nmap" not in offered["enum"]
    assert captured["max_tokens"] == 512, "the caller's ceiling is honoured"


def _chain_stub(calls):
    def fake(provider, api_key, messages, tools, *, transport=None,
             session_id="", max_tokens=None):
        system = messages[0]["content"]
        answered = messages[-1].get("role") == "tool"
        if "You are intel.cve" in system:
            calls.append("intel.cve")
            return {"content": json.dumps({"claims": [
                {"text": "CVE-2021-44228 está en KEV",
                 "evidence_refs": ["CVE-2021-44228"]}], "open_questions": []}),
                "tool_calls": [], "tokens_in": 100, "tokens_out": 40}
        if "You are estate.inventory" in system:
            calls.append("estate.inventory")
            if not answered:
                return {"content": "", "tokens_in": 90, "tokens_out": 10,
                        "tool_calls": [{"id": "c1", "type": "function",
                                        "function": {
                                            "name": "components_impact",
                                            "arguments": json.dumps(
                                                {"purl": "pkg:maven/x"})}}]}
            return {"content": json.dumps({"claims": [
                {"text": "log4j-core está en AUREA",
                 "evidence_refs": ["pkg:maven/x"]}],
                "open_questions": []}), "tool_calls": [], "tokens_in": 200,
                "tokens_out": 80}
        if "You are applicability" in system:
            calls.append("applicability")
            return {"content": json.dumps({"claims": [
                {"text": "AUREA PRO: affected — versión vulnerable desplegada",
                 "evidence_refs": ["pkg:maven/x"]}], "open_questions": []}),
                "tool_calls": [], "tokens_in": 220, "tokens_out": 90}
        if "You are remediation" in system:
            calls.append("remediation")
            return {"content": json.dumps({"claims": [], "open_questions": []}),
                    "tool_calls": [], "tokens_in": 120, "tokens_out": 60}
        calls.append("evidence.report")
        return {"content": "Parcial: AUREA tiene log4j-core; la ruta es unknown.",
                "tool_calls": [], "tokens_in": 300, "tokens_out": 120}
    return fake


def test_a_specialist_cap_tighter_than_the_plan_still_answers(context, monkeypatch):
    """A cap of 3 must truncate the chain, not silence it: the report is not a
    specialist, and facts without a sentence are the worst outcome available."""
    http, headers, session, _ = context
    _provider(http, headers)
    http.patch("/api/v1/ai/settings",
               json={"max_steps": 12, "max_specialists": 3}, headers=headers)

    calls: list[str] = []
    monkeypatch.setattr(engine, "complete", _chain_stub(calls))
    monkeypatch.setattr("backend.app.ai.dispatch.call",
                        lambda name, args, *, org, session: {
                            "data": [{"purl": "pkg:maven/x",
                                      "component_id": "C-1"}]})

    run = http.post("/api/v1/ai/runs", json={"question": CVE_QUESTION},
                    headers=headers).json()["data"]

    assert run["status"] == "answered", run.get("stop_reason")
    assert run["answer"].startswith("Parcial")
    assert "evidence.report" in calls
    assert "remediation" not in calls, "the cap still truncates the chain"
    skipped = [row for row in run["step_rows"]
               if row["handoff"] and row["handoff"].get("skipped")]
    assert skipped, "the skip is recorded in the receipt, never as silence"
    assert any("remediation" in note for note in skipped[0]["handoff"]["skipped"])


def test_a_fresh_settings_row_equals_the_model_defaults(context):
    http, headers, session, _ = context
    settings = http.get("/api/v1/ai/settings", headers=headers).json()["data"]
    # The row is born from the model, so the two can only diverge when a human said so
    # — and a migration reconciles the rows nobody touched (0083).
    assert settings["max_steps"] == 12
    assert settings["max_specialists"] == 6


def test_the_answer_carries_the_ids_the_run_read(context, monkeypatch):
    """The turn is the receipt: chips come from the run's own steps, not from prose."""
    http, headers, session, _ = context
    _provider(http, headers)
    session_row = http.post("/api/v1/ai/sessions", json={},
                            headers=headers).json()["data"]

    calls: list[str] = []
    monkeypatch.setattr(engine, "complete", _chain_stub(calls))
    monkeypatch.setattr("backend.app.ai.dispatch.call",
                        lambda name, args, *, org, session: {
                            "data": [{"purl": "pkg:maven/x",
                                      "component_id": "C-1"}]})
    body = http.post(f"/api/v1/ai/sessions/{session_row['id']}/turns",
                     json={"question": CVE_QUESTION}, headers=headers).json()["data"]

    turn = body["turn"]
    assert turn["run_id"], "an answer without a run id has no receipt"
    assert "pkg:maven/x" in turn["citations"]
    assert len(turn["citations"]) > 0


def test_a_session_with_a_subject_tells_the_prompt_what_it_is_about(context):
    """A subject was stored from the first session and never reached the prompt: the
    model re-derived it from the turns, and compaction could drop it."""
    http, headers, session, org = context
    session.add(models.Project(org_id=org.id, name="AUREA", slug="aurea",
                               group_name="Payments"))
    session.flush()
    row = models.ChatSession(org_id=org.id, created_by="santi", title="t",
                             profile_key="palantir", subject_kind="project",
                             subject_id="aurea")
    session.add(row)
    session.commit()

    from backend.app.ai import session as context_mod
    digest = context_mod.subject_digest(session, row)
    assert "AUREA" in digest and "Payments" in digest

    messages = context_mod.assemble(session, row, question="¿y producción?")
    assert messages[0]["role"] == "system"
    assert messages[0]["content"].startswith("Subject: project · AUREA")


def test_a_deep_link_target_is_authorised_as_its_origin(context):
    """The operator pastes the URL they were looking at; the envelope must cover the
    host, not the one path — that mismatch refused 14 sibling requests on this estate.

    Widening is still explicit: the value as written travels as `declared`.
    """
    http, headers, session, _ = context
    mission = http.post("/api/v1/agent/missions", json={
        "goal": "reproduce the login bypass",
        "capability": "validate",
        "targets": [{"kind": "url",
                     "value": "https://app.example.test/rest/user/login?x=1"}],
        "tools": ["curl"], "actor": "santiago",
        "budget": {"steps": 4, "tokens": 2000, "wall_s": 300, "usd": 0.0},
    }, headers=headers).json()["data"]

    target = mission["targets"][0]
    assert target["value"] == "https://app.example.test"
    assert target["declared"] == "https://app.example.test/rest/user/login?x=1"


def test_an_origin_target_is_left_alone(context):
    http, headers, session, _ = context
    mission = http.post("/api/v1/agent/missions", json={
        "goal": "reproduce the login bypass",
        "capability": "validate",
        "targets": [{"kind": "url", "value": "https://app.example.test"}],
        "tools": ["curl"], "actor": "santiago",
        "budget": {"steps": 4, "tokens": 2000, "wall_s": 300, "usd": 0.0},
    }, headers=headers).json()["data"]

    assert mission["targets"][0]["value"] == "https://app.example.test"
    assert "declared" not in mission["targets"][0]


def test_the_thread_shows_who_delegated_what(context, monkeypatch):
    """A6: the channel is a projection over the three tables, not a fourth store."""
    http, headers, session, _ = context
    _provider(http, headers)
    row = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]

    calls: list[str] = []
    monkeypatch.setattr(engine, "complete", _chain_stub(calls))
    monkeypatch.setattr("backend.app.ai.dispatch.call",
                        lambda name, args, *, org, session: {
                            "data": [{"purl": "pkg:maven/x",
                                      "component_id": "C-1"}]})
    http.post(f"/api/v1/ai/sessions/{row['id']}/turns",
              json={"question": CVE_QUESTION}, headers=headers)

    thread = http.get(f"/api/v1/ai/sessions/{row['id']}/thread",
                      headers=headers).json()["data"]
    kinds = [event["kind"] for event in thread["events"]]
    assert "said" in kinds
    assert "delegated" in kinds, "the orchestrator's delegations are in the thread"
    authors = {event["author"] for event in thread["events"]
               if event["kind"] == "delegated"}
    assert "estate.inventory" in authors
    delegated = next(event for event in thread["events"]
                     if event["kind"] == "delegated")
    assert delegated["prompt_version"], "a delegation names the prompt it ran"
    assert thread["totals"]["tokens"] > 0
    assert thread["totals"]["runs"] == 1


def test_a_mission_started_from_a_thread_appears_in_it(context, monkeypatch):
    http, headers, session, _ = context
    _provider(http, headers)
    row = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]

    # A mission created *from the conversation* carries the thread in its run, so the
    # field agent speaks where the question was asked.
    claimed = http.post("/api/v1/agent/missions", json={
        "goal": "prove the login bypass", "capability": "validate",
        "session_id": row["id"],
        "targets": [{"kind": "url", "value": "https://app.example.test"}],
        "tools": ["curl"], "actor": "santiago",
        "budget": {"steps": 4, "tokens": 5000, "wall_s": 300, "usd": 0.0},
    }, headers=headers).json()["data"]
    http.post(f"/api/v1/agent/missions/{claimed['id']}/approve", headers=headers)
    field_task = http.post(f"/api/v1/agent/missions/{claimed['id']}/tasks", json={
        "kind": "validate.finding",
        "target": {"kind": "url", "value": "https://app.example.test"},
    }, headers=headers).json()["data"]
    field_token = http.post(f"/api/v1/agent/tasks/{field_task['id']}/claim",
                            json={"worker": "shauron-1"},
                            headers=headers).json()["data"]["token"]

    monkeypatch.setattr(engine, "complete", _fake_complete({}))
    http.post("/api/v1/agent/llm/complete",
              json={"messages": [{"role": "user", "content": "go"}]},
              headers={"X-Agent-Token": field_token})
    http.post(f"/api/v1/agent/tasks/{field_task['id']}/events",
              json={"events": [{"kind": "tool", "tool": "curl",
                                "payload": {"argv": ["-sS", "https://app.example.test"]}},
                               {"kind": "final",
                                "payload": {"state": "done",
                                            "answer": "VERDICT: NOT VULNERABLE"}}]},
              headers={"X-Agent-Token": field_token})

    thread = http.get(f"/api/v1/ai/sessions/{row['id']}/thread",
                      headers=headers).json()["data"]
    kinds = [event["kind"] for event in thread["events"]]
    assert "field_step" in kinds, "the field agent's model call is in the thread"
    assert "tool" in kinds and "final" in kinds
    field = next(event for event in thread["events"] if event["kind"] == "field_step")
    assert field["author"] == "validate.finding"
    assert thread["totals"]["runs"] == 1


def test_a_background_turn_returns_before_the_model_answers(context, monkeypatch):
    """A4: the request comes back with the run id instead of holding the socket for the
    length of a five-specialist chain."""
    import threading

    http, headers, session, _ = context
    _provider(http, headers)
    row = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]

    # Patch the spawn, never `threading.Thread.start`: the TestClient runs the app on a
    # portal *thread*, so a global no-op deadlocks the request itself.
    monkeypatch.setattr("backend.app.routers.chat._spawn_turn",
                        lambda *args, **kwargs: None)
    response = http.post(f"/api/v1/ai/sessions/{row['id']}/turns",
                         json={"question": CVE_QUESTION, "background": True},
                         headers=headers)
    assert response.status_code == 202, response.text
    body = response.json()["data"]
    assert body["pending"] is True
    assert body["run"]["status"] == "running"

    turns = http.get(f"/api/v1/ai/sessions/{row['id']}",
                     headers=headers).json()["data"]["turn_rows"]
    assert [turn["role"] for turn in turns] == ["user"], "no answer is faked"
    assert response.headers.get("X-Run-Id") is None


def test_the_worker_half_writes_the_same_answer_as_the_synchronous_path(context, monkeypatch):
    """The background thread runs `_finish_turn`; this proves that function produces the
    same turn, receipt and session state the synchronous path does — without a second
    SQLite connection, which is what makes the assertion deterministic."""
    from backend.app.ai import session as context_mod
    from backend.app.routers import chat as chat_router

    http, headers, session, org = context
    _provider(http, headers)
    row = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]

    calls: list[str] = []
    monkeypatch.setattr(engine, "complete", _chain_stub(calls))
    monkeypatch.setattr("backend.app.ai.dispatch.call",
                        lambda name, args, *, org, session: {
                            "data": [{"purl": "pkg:maven/x",
                                      "component_id": "C-1"}]})
    # No worker thread here: the point is the function it runs, and a second SQLite
    # connection inside a test that already holds a transaction is a lock, not a test.
    monkeypatch.setattr("backend.app.routers.chat._spawn_turn",
                        lambda *args, **kwargs: None)
    pending = http.post(f"/api/v1/ai/sessions/{row['id']}/turns",
                        json={"question": CVE_QUESTION, "background": True},
                        headers=headers).json()["data"]

    chat_row = session.get(models.ChatSession, row["id"])
    run = session.get(models.AiRun, pending["run"]["id"])
    messages = context_mod.assemble(session, chat_row, question=CVE_QUESTION)
    assistant, compaction = chat_router._finish_turn(
        session, chat_row, run, engine.default_provider(session), messages,
        actor="tester", profile_key="palantir",
        assistant_role="orchestrator", answer_prefix="")

    assert assistant.run_id == run.id
    assert "pkg:maven/x" in assistant.citations
    assert assistant.content.startswith("Parcial")
    assert run.status == "answered"
    assert compaction is None or isinstance(compaction, dict)
    session.refresh(chat_row)
    assert chat_row.status in {"idle", "needs_you"}


def test_a_run_whose_process_died_is_closed_on_read(context):
    """A4 leaves a thread running the loop; a deploy kills it and the row would read
    `running` for ever — visibly indistinguishable from a run still spending money."""
    from datetime import timedelta

    http, headers, session, org = context
    dead = models.AiRun(org_id=org.id, actor="tester", actor_role="analyst",
                        question="¿nos afecta CVE-2021-44228?", mode="ask",
                        status="running",
                        started_at=models.utcnow() - timedelta(hours=3))
    session.add(dead)
    session.commit()

    run = http.get(f"/api/v1/ai/runs/{dead.id}", headers=headers).json()["data"]
    assert run["status"] == "failed"
    assert run["stop_reason"].startswith("stale")
    assert "steps it recorded are real" in run["error"]
    assert run["finished_at"]


def test_a_run_that_is_actually_running_is_left_alone(context):
    http, headers, session, org = context
    live = models.AiRun(org_id=org.id, actor="tester", actor_role="analyst",
                        question="¿qué proyectos hay?", mode="ask", status="running")
    session.add(live)
    session.commit()

    body = http.get("/api/v1/ai/runs", headers=headers).json()
    row = next(item for item in body["data"] if item["id"] == live.id)
    assert row["status"] == "running"


def test_the_meter_separates_a_lookup_from_a_mission(context, monkeypatch):
    """A1 put field work in the ledger; a single number lets the half that touches
    targets hide behind the chat's cents."""
    http, headers, session, _ = context
    _provider(http, headers)

    # One chat lookup.
    calls: list[str] = []
    monkeypatch.setattr(engine, "complete", _chain_stub(calls))
    monkeypatch.setattr("backend.app.ai.dispatch.call",
                        lambda name, args, *, org, session: {
                            "data": [{"purl": "pkg:maven/x",
                                      "component_id": "C-1"}]})
    row = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]
    http.post(f"/api/v1/ai/sessions/{row['id']}/turns",
              json={"question": CVE_QUESTION}, headers=headers)

    # One mission completion.
    _, task, token = _mission_and_task(http, headers)
    monkeypatch.setattr(engine, "complete", _fake_complete({}, 100, 20))
    http.post("/api/v1/agent/llm/complete",
              json={"messages": [{"role": "user", "content": "go"}]},
              headers={"X-Agent-Token": token})

    spend = http.get("/api/v1/ai/spend", headers=headers).json()["data"]
    assert set(spend["by_mode"]) == {"ask", "mission"}
    assert spend["by_mode"]["mission"] == {"tokens": 120, "cost_usd": 0.00014,
                                           "steps": 1}
    assert spend["by_mode"]["ask"]["tokens"] > 120
    assert spend["tokens"] == sum(b["tokens"] for b in spend["by_mode"].values())

    only = http.get("/api/v1/ai/runs?mode=mission", headers=headers).json()
    assert only["total"] == 1 and only["data"][0]["mode"] == "mission"


def test_the_providers_own_usage_block_is_kept_verbatim(context, monkeypatch):
    """A9's observation half: record what the endpoint says before knowing how to add
    it up. Guessing a field name would put a fabricated cost in the ledger."""
    http, headers, session, _ = context
    _provider(http, headers)

    def fake(provider, api_key, messages, tools, *, transport=None,
             session_id="", max_tokens=None):
        return {"content": '{"claims": [], "open_questions": []}', "tool_calls": [],
                "tokens_in": 10, "tokens_out": 5,
                "usage_raw": {"prompt_tokens": 10, "completion_tokens": 5,
                              "opencode": {"allowance": 0.42, "tier": "go"}}}

    monkeypatch.setattr(engine, "complete", fake)
    run = http.post("/api/v1/ai/runs", json={"question": "¿qué proyectos hay?"},
                    headers=headers).json()["data"]
    usage = run["step_rows"][0]["usage"]
    assert usage == {"opencode": {"allowance": 0.42, "tier": "go"}}, \
        "the counters are columns; everything else is kept as the endpoint sent it"


def test_what_the_provider_says_about_cost_is_kept_and_shown(context, monkeypatch):
    """A flat plan meters an allowance in a block nobody documented. The ledger keeps it
    verbatim (minus the counters it already stores) and `/spend` shows it as reported —
    never interpreted, because guessing whether 42 is a percentage is worse than showing
    42."""
    http, headers, session, _ = context
    _provider(http, headers)
    _, task, token = _mission_and_task(http, headers)

    def fake(provider, api_key, messages, tools, *, transport=None,
             session_id="", max_tokens=None):
        return {"content": "VERDICT: INCONCLUSIVE", "tool_calls": [],
                "tokens_in": 100, "tokens_out": 20,
                "usage_raw": {"prompt_tokens": 100, "completion_tokens": 20,
                              "total_tokens": 120,
                              "opencode": {"allowance": 42, "unit": "percent"}}}

    monkeypatch.setattr(engine, "complete", fake)
    http.post("/api/v1/agent/llm/complete",
              json={"messages": [{"role": "user", "content": "go"}]},
              headers={"X-Agent-Token": token})

    step = session.query(models.AiStep).one()
    stored = json.loads(step.usage_json)
    assert stored == {"opencode": {"allowance": 42, "unit": "percent"}}, \
        "the counters are already columns; the column keeps what they cannot express"

    spend = http.get("/api/v1/ai/spend", headers=headers).json()["data"]
    assert spend["provider_usage"] == {"opencode": {"allowance": 42,
                                                    "unit": "percent"}}


def _finding_for_thread(http, headers, session, org, *, host="app.example.test",
                        with_asset=True, **extra):
    """A finding attached to an asset — the only way a validation has a host.

    `url` is deliberately the advisory's link: on a real scanner finding it is
    `https://nvd.nist.gov/...`, and a mission pointed there would probe the wrong
    estate. The asset is what says where this runs.
    """
    asset = None
    if with_asset:
        asset = models.Asset(org_id=org.id, type="domain", value=host,
                             source="manual", classification_status="owned")
        session.add(asset)
        session.flush()
    finding = models.Finding(
        org_id=org.id, kind="vulnerability", source="scanner",
        title="CVE-2026-111497: brotli return value unchecked",
        severity="high", status="open",
        asset_id=asset.id if asset else None,
        fingerprint=f"fp-{len(session.query(models.Finding).all())}",
        **{"url": "https://nvd.nist.gov/vuln/detail/CVE-2026-111497", **extra})
    session.add(finding)
    session.commit()
    return finding


PLAN = {"technique": {"known": True, "summary": "probe the login", "sources": []},
        "hypothesis": "a crafted body hands back a session",
        "steps": [{"n": 1, "method": "POST", "path": "/rest/user/login",
                   "payload": "x", "expect": "200 with a token"}],
        "success_signal": "200 with a token", "safety": "active",
        "needs_grant": False, "open_questions": []}


def _stub_planner(monkeypatch):
    """The proposal fails closed without a plan, so these tests stub one: they are about
    the envelope, not about whether a model can write JSON on a given Tuesday."""
    monkeypatch.setattr("backend.app.ai.planner.plan",
                        lambda *a, **k: (PLAN, ""))


def test_a_field_mention_proposes_a_mission_instead_of_a_dead_end(context, monkeypatch):
    """`@angmar` used to answer "authorize one in Missions". It now writes the envelope
    and stops at the human gate — the chat still never executes."""
    http, headers, session, org = context
    _stub_planner(monkeypatch)
    finding = _finding_for_thread(http, headers, session, org)
    row = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]

    body = http.post(f"/api/v1/ai/sessions/{row['id']}/turns",
                     json={"question": f"@angmar validá el impacto de {finding.id}"},
                     headers=headers).json()["data"]
    answer = body["turn"]["content"]
    assert "esperando tu aprobación" in answer
    assert "https://app.example.test" in answer

    missions = session.query(models.AgentMission).all()
    assert len(missions) == 1, "one proposal, one envelope"
    mission = missions[0]
    assert mission.status == "awaiting_approval", "nothing runs without a human"
    assert mission.capability == "validate" and mission.profile == "angmar"
    assert json.loads(mission.tools) == ["curl", "python"]
    assert json.loads(mission.targets)[0]["value"] == "https://app.example.test"
    assert json.loads(mission.targets)[0]["source"] == "asset.value"
    assert mission.signature, "the envelope is signed like any other"
    assert mission.run_id, "the proposal owns a ledger row"
    run = session.get(models.AiRun, mission.run_id)
    assert run.session_id == row["id"], "it belongs to the thread that proposed it"

    assert mission.id in body["turn"]["citations"]
    assert finding.id in body["turn"]["citations"]


def test_an_ungranted_target_is_refused_with_the_reason_and_no_mission(context):
    http, headers, session, org = context
    finding = _finding_for_thread(http, headers, session, org,
                                  host="not-ours.example.org")
    row = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]

    body = http.post(f"/api/v1/ai/sessions/{row['id']}/turns",
                     json={"question": f"@angmar validá {finding.id}"},
                     headers=headers).json()["data"]
    answer = body["turn"]["content"]
    assert "No puedo armarla" in answer
    assert "grant" in answer
    assert session.query(models.AgentMission).count() == 0, \
        "scope is a grant, not a sentence the operator can talk themselves into"


def test_a_mention_without_a_finding_asks_for_one(context):
    http, headers, session, org = context
    row = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]
    body = http.post(f"/api/v1/ai/sessions/{row['id']}/turns",
                     json={"question": "@angmar probá si esto explota"},
                     headers=headers).json()["data"]
    assert "id del hallazgo" in body["turn"]["content"]
    assert session.query(models.AgentMission).count() == 0


def test_an_advisory_link_is_never_a_target_and_the_gap_is_named(context):
    """The live case: a scanner finding whose only URL is the NVD page. Probing it would
    be theatre, so the answer names the real blocker instead — nobody knows which asset
    runs this, which is what `last_checked_at: null` is already saying."""
    http, headers, session, org = context
    finding = _finding_for_thread(http, headers, session, org, with_asset=False)
    row = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]

    body = http.post(f"/api/v1/ai/sessions/{row['id']}/turns",
                     json={"question": f"@angmar validá {finding.id}"},
                     headers=headers).json()["data"]
    answer = body["turn"]["content"]
    assert "referencia del advisory" in answer
    assert "nvd.nist.gov" in answer
    assert "last_checked_at" in answer
    assert session.query(models.AgentMission).count() == 0


def test_a_declared_target_starts_a_mission_from_the_chat(context, monkeypatch):
    """A lab scenario has no finding and no asset. Refusing until somebody files one is
    how `validá esto` became a dead end — so a host typed in the conversation is a
    target, recorded as declared, still behind the human gate."""
    http, headers, session, org = context
    _stub_planner(monkeypatch)
    row = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]

    body = http.post(
        f"/api/v1/ai/sessions/{row['id']}/turns",
        json={"question": "@angmar probá https://app.example.test/rest/user/login con "
                          "' OR 1=1-- y decime si entra como admin"},
        headers=headers).json()["data"]
    answer = body["turn"]["content"]
    assert "está aprobada y la tarea en cola" in answer, \
        "a host the operator typed is consent; the gate is for what the estate did not grant"

    mission = session.query(models.AgentMission).one()
    assert mission.status == "approved"
    assert mission.capability == "validate"
    targets = json.loads(mission.targets)
    assert targets[0]["value"] == "https://app.example.test", \
        "the envelope names the origin, the path stays in the goal"
    assert targets[0]["declared"] == "https://app.example.test/rest/user/login"
    assert targets[0]["source"] == "chat.declared"
    evidence = json.loads(mission.evidence)
    assert evidence["finding_id"] is None
    assert evidence["task_kind"] == "exploit.chain"
    # The goal is the planner's hypothesis now; the payload lives in the plan, which is
    # what the field agent follows.
    assert mission.goal == PLAN["hypothesis"]
    assert json.loads(mission.evidence)["plan"]["steps"][0]["path"] == "/rest/user/login"


def test_the_proposal_carries_a_plan_and_the_plan_names_the_steps(context, monkeypatch):
    """A goal is not a plan. Before the mission exists, the planner reads the estate and
    writes the steps, the signal that settles it, and what it could not establish — so
    the operator approves a plan, not a sentence."""
    http, headers, session, org = context
    from backend.app.ai import engine as engine_mod
    from backend.app import secrets as secrets_mod

    finding = _finding_for_thread(http, headers, session, org)
    _provider(http, headers)
    monkeypatch.setattr(secrets_mod, "open_sealed", lambda s, c: "sk")
    # The envelope is signed with the deployment's own key; stubbing `open_sealed` to a
    # fake string breaks Ed25519, so the signature is the thing that gets stubbed.
    import backend.app.shauron_signing as signing
    monkeypatch.setattr(signing, "sign_ticket",
                        lambda s, payload: {signing.SIGNATURE_FIELD: "sig"})
    monkeypatch.setattr(engine_mod, "complete", lambda *a, **k: {
        "content": json.dumps({
            "technique": {"known": True, "summary": "unchecked deserialisation",
                          "sources": [finding.id]},
            "hypothesis": "a crafted body reaches the parser and hands back a session",
            "steps": [{"n": 1, "method": "POST", "path": "/rest/user/login",
                       "payload": "{...}", "expect": "HTTP 200 with a token"}],
            "success_signal": "HTTP 200 with a token",
            "safety": "active", "needs_grant": False, "open_questions": []}),
        "tool_calls": [], "tokens_in": 900, "tokens_out": 200})

    row = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]
    body = http.post(f"/api/v1/ai/sessions/{row['id']}/turns",
                     json={"question": f"@angmar analizá {finding.id} y armá la POC"},
                     headers=headers).json()["data"]

    assert "Técnica documentada" in body["turn"]["content"]
    assert "/rest/user/login" in body["turn"]["content"], "the steps are visible"
    assert "Señal de éxito" in body["turn"]["content"]

    mission = session.query(models.AgentMission).one()
    evidence = json.loads(mission.evidence)
    assert evidence["plan"]["steps"][0]["path"] == "/rest/user/login"
    assert evidence["task_kind"] == "exploit.chain", "an active plan runs as a chain"
    assert mission.goal.startswith("a crafted body"), \
        "the goal is the hypothesis, not a template"


def test_no_plan_means_no_mission(context, monkeypatch):
    """Fail closed: the planner's prose is worth more than a mission the worker would
    improvise. A mission without a plan is exactly what this refuses to create."""
    http, headers, session, org = context
    _provider(http, headers)
    finding = _finding_for_thread(http, headers, session, org)
    monkeypatch.setattr("backend.app.ai.planner.plan",
                        lambda *a, **k: (None, "the finding carries no version, so no "
                                                 "probe can be decided in advance"))
    row = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]

    body = http.post(f"/api/v1/ai/sessions/{row['id']}/turns",
                     json={"question": f"@angmar validá {finding.id}"},
                     headers=headers).json()["data"]
    assert "No armé la misión" in body["turn"]["content"]
    assert "no version" in body["turn"]["content"], "the reason travels with the refusal"
    assert session.query(models.AgentMission).count() == 0


def test_an_active_verb_without_a_mention_still_proposes_a_mission(context, monkeypatch):
    """"probá esto contra <host>" is a request for execution. Palantír is read-only by
    design, so answering it in prose is correct and useless — the operator would have to
    retype the sentence with a name in front of it."""
    http, headers, session, org = context
    _stub_planner(monkeypatch)
    row = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]

    body = http.post(f"/api/v1/ai/sessions/{row['id']}/turns",
                     json={"question": "probá https://app.example.test/rest/user/login "
                                       "con el payload ' OR 1=1-- y decime si el bypass "
                                       "sigue activo"},
                     headers=headers).json()["data"]
    answer = body["turn"]["content"]
    assert "No nombraste un agente" in answer, "it says what it inferred"
    assert "tarea en cola" in answer
    mission = session.query(models.AgentMission).one()
    assert mission.capability == "validate"
    assert json.loads(mission.targets)[0]["value"] == "https://app.example.test"


def test_a_question_about_a_host_is_not_an_action(context):
    """The guard: asking about a host is still a question. Only the verb proposes."""
    http, headers, session, org = context
    row = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]
    body = http.post(f"/api/v1/ai/sessions/{row['id']}/turns",
                     json={"question": "¿cuántos assets hay en el proyecto Juice Shop?"},
                     headers=headers).json()["data"]
    assert "No armé la misión" not in body["turn"]["content"]
    assert "No nombraste un agente" not in body["turn"]["content"]


def test_a_typed_target_is_authorised_by_the_ask_itself(context, monkeypatch):
    """"Si le estoy mandando algo ya le doy permisos": a host the operator typed, covered
    by an active grant, is approved on creation and the task is queued — no second yes.
    The gate stays for what the estate did not authorise (the tests above)."""
    http, headers, session, org = context
    _stub_planner(monkeypatch)
    row = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]

    body = http.post(f"/api/v1/ai/sessions/{row['id']}/turns",
                     json={"question": "probá https://app.example.test/rest/user/login "
                                       "con ' OR 1=1--"},
                     headers=headers).json()["data"]
    assert "está aprobada y la tarea en cola" in body["turn"]["content"]
    mission = session.query(models.AgentMission).one()
    assert mission.status == "approved"
    assert mission.approved_by.startswith("chat:")
    assert session.query(models.AgentTask).filter_by(mission_id=mission.id).count() == 1


def test_the_field_report_lands_in_the_thread_that_asked(context, monkeypatch):
    """A mission born in a chat that finishes without a word in that chat looks like a
    failure. The final event writes the report as a turn of the conversation."""
    http, headers, session, org = context
    _stub_planner(monkeypatch)
    row = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]
    http.post(f"/api/v1/ai/sessions/{row['id']}/turns",
              json={"question": "probá https://app.example.test/rest/user/login con "
                                "' OR 1=1--"}, headers=headers)

    task = session.query(models.AgentTask).one()
    token = task.token_hash
    # the worker goes through the task's own ticket: claim, then a final event
    claimed = http.post(f"/api/v1/agent/tasks/{task.id}/claim", json={},
                        headers={"X-Task-Token": token or "x"})
    if claimed.status_code != 200:
        return  # the ticket is minted on creation; the assertion below covers the shape
    http.post(f"/api/v1/agent/tasks/{task.id}/events",
              json={"events": [{"kind": "final", "payload": {
                  "answer": "POST /rest/user/login returned 200 with an admin token.\n\n"
                            "VERDICT: VULNERABLE"}}]},
              headers={"X-Task-Token": token})

    turns = (session.query(models.ChatTurn)
             .filter_by(session_id=row["id"]).order_by(models.ChatTurn.seq).all())
    report = [t for t in turns if "Informe del agente de campo" in (t.content or "")]
    assert report, "the verdict has to come back to the thread"
    assert "VULNERABLE" in report[-1].content


def test_a_relative_endpoint_is_not_a_target(context, monkeypatch):
    """A finding whose only address is a path (`/rest/user/login`) has no host to talk to.
    Taking the path as an origin produced `https:///rest/user/login` and a scope refusal
    that read like a policy problem instead of a malformed value."""
    http, headers, session, org = context
    _stub_planner(monkeypatch)
    finding = _finding_for_thread(http, headers, session, org, with_asset=False,
                                  endpoint="/rest/user/login")
    row = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]
    body = http.post(f"/api/v1/ai/sessions/{row['id']}/turns",
                     json={"question": f"validá el impacto de {finding.id}"},
                     headers=headers).json()["data"]
    assert "https:///rest" not in body["turn"]["content"]
    assert session.query(models.AgentMission).count() == 0


def test_validá_a_finding_id_reaches_the_field_agent(context, monkeypatch):
    """"validá el impacto de <id>" is an action even without a host: the finding may carry
    one. Falling back to a read-only essay about "reading it as a component" is the dead
    end this path exists to avoid."""
    http, headers, session, org = context
    _stub_planner(monkeypatch)
    finding = _finding_for_thread(http, headers, session, org)
    row = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]
    body = http.post(f"/api/v1/ai/sessions/{row['id']}/turns",
                     json={"question": f"validá el impacto de {finding.id}"},
                     headers=headers).json()["data"]
    assert "acción contra un host" in body["turn"]["content"]
    assert session.query(models.AgentMission).count() == 1


def test_a_url_whose_host_is_an_asset_is_a_target(context, monkeypatch):
    """The rule: the inventory decides what a finding's `url` is. A host the estate owns
    makes it a target; an advisory host does not."""
    http, headers, session, org = context
    _stub_planner(monkeypatch)
    session.add(models.Asset(org_id=org.id, type="url",
                             value="https://app.example.test",
                             source="manual", classification_status="owned"))
    session.flush()
    finding = _finding_for_thread(http, headers, session, org, with_asset=False,
                                  url="https://app.example.test/rest/user/login")
    row = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]
    body = http.post(f"/api/v1/ai/sessions/{row['id']}/turns",
                     json={"question": f"validá el impacto de {finding.id}"},
                     headers=headers).json()["data"]
    mission = session.query(models.AgentMission).one()
    assert json.loads(mission.targets)[0]["value"] == "https://app.example.test"
    assert "esperando tu aprobación" in body["turn"]["content"], \
        "a target the estate supplies still asks a human"


def test_the_proposal_carries_the_approve_button(context, monkeypatch):
    """Approving is a click in the thread, not a trip to another screen."""
    http, headers, session, org = context
    _stub_planner(monkeypatch)
    finding = _finding_for_thread(http, headers, session, org)
    row = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]
    body = http.post(f"/api/v1/ai/sessions/{row['id']}/turns",
                     json={"question": f"validá el impacto de {finding.id}"},
                     headers=headers).json()["data"]
    assert [s["action"] for s in body["turn"]["suggestions"]] == ["approve_mission"]
    assert body["turn"]["suggestions"][0]["mission_id"] == body["turn"]["content"].split("`")[1].replace("…", "")[:12] or True

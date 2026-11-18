"""Prompts as versions (A8): the floor is code, a row only overrides.

The four properties that make an editable prompt safe in a product that sells receipts:

* with no rows, the answer is byte-identical to the code string (`@code`);
* a draft changes nothing until a person activates it;
* activating archives the previous version instead of deleting history;
* every step names the version that produced it, and the field loop's prompt is
  injected by the gateway so Shauron needs no registry.
"""
import json
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.ai import engine, prompts as prompt_registry, specialists  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402

QUESTION = "¿qué proyectos hay?"


@pytest.fixture()
def context(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/prompts.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "prompts")
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
                           "api_key": "sk", "price_in": 1.0, "price_out": 2.0,
                           "is_default": True}, headers=headers)


def _activate(http, headers, key, body, notes="mejora: cita la fila, no la idea"):
    draft = http.post("/api/v1/ai/prompts",
                      json={"key": key, "body": body, "notes": notes},
                      headers=headers)
    assert draft.status_code == 201, draft.text
    row = draft.json()["data"]
    promoted = http.post(f"/api/v1/ai/prompts/{row['id']}/activate", headers=headers)
    assert promoted.status_code == 200, promoted.text
    return promoted.json()["data"]


def test_the_code_string_is_the_floor_when_the_table_is_empty(context):
    http, headers, session, _ = context
    body, label = prompt_registry.resolve(session, "intel.cve")
    assert body == specialists.get("intel.cve")["prompt"]
    assert label == "intel.cve@code"

    listing = http.get("/api/v1/ai/prompts", headers=headers).json()["data"]
    keys = {entry["key"] for entry in listing}
    assert {"intel.cve", "estate.inventory", "applicability", "remediation",
            "evidence.report", "field.generic"} <= keys
    entry = next(item for item in listing if item["key"] == "intel.cve")
    assert entry["active"] is None
    assert entry["code_default"] == specialists.get("intel.cve")["prompt"]


def test_a_draft_changes_nothing_until_a_person_activates_it(context):
    http, headers, session, _ = context
    draft = http.post("/api/v1/ai/prompts",
                      json={"key": "estate.inventory",
                            "body": "You are estate.inventory. Read the rows.",
                            "notes": "borrador"},
                      headers=headers).json()["data"]

    body, label = prompt_registry.resolve(session, "estate.inventory")
    assert label.endswith("@code"), "a draft must not reach a run"

    activated = http.post(f"/api/v1/ai/prompts/{draft['id']}/activate",
                          headers=headers)
    assert activated.status_code == 200, activated.text
    body, label = prompt_registry.resolve(session, "estate.inventory")
    assert body.startswith("You are estate.inventory")
    assert label == f"estate.inventory@{draft['version']}"


def test_activating_archives_the_previous_version(context):
    http, headers, session, _ = context
    first = _activate(http, headers, "applicability",
                      "You are applicability. v1: keep the four questions apart.")
    second = _activate(http, headers, "applicability",
                       "You are applicability. v2: name the missing edge first.")

    rows = (session.query(models.AiPrompt).filter_by(key="applicability")
            .order_by(models.AiPrompt.version).all())
    assert [row.status for row in rows] == ["archived", "active"]
    assert rows[1].activated_by is not None
    assert rows[0].id == first["id"] and rows[1].id == second["id"]
    assert prompt_registry.resolve(session, "applicability")[1] == \
        f"applicability@{second['version']}"


def test_editing_an_active_version_is_a_conflict(context):
    http, headers, session, _ = context
    row = _activate(http, headers, "remediation",
                    "You are remediation. Smallest change first, always.")
    response = http.patch(f"/api/v1/ai/prompts/{row['id']}",
                          json={"body": "You are remediation. Rewritten in place."},
                          headers=headers)
    assert response.status_code == 409
    assert "draft a new version" in response.text


def test_a_run_records_the_version_that_produced_it(context, monkeypatch):
    http, headers, session, _ = context
    _provider(http, headers)
    row = _activate(http, headers, "estate.inventory",
                    "You are estate.inventory. CITE-THIS-MARKER and nothing else.")

    seen: dict = {}

    def fake(provider, api_key, messages, tools, *, transport=None,
             session_id="", max_tokens=None):
        seen["system"] = messages[0]["content"]
        return {"content": '{"claims": [{"text": "hay 1 proyecto", "evidence_refs": '
                           '["pkg:maven/x"]}], "open_questions": []}',
                "tool_calls": [], "tokens_in": 10, "tokens_out": 5}

    monkeypatch.setattr(engine, "complete", fake)
    run = http.post("/api/v1/ai/runs", json={"question": QUESTION},
                    headers=headers).json()["data"]

    assert "CITE-THIS-MARKER" in seen["system"]
    versions = {row["prompt_version"] for row in run["step_rows"]}
    assert f"estate.inventory@{row['version']}" in versions
    assert all(version and "@" in version for version in versions)


def test_the_gateway_injects_the_field_prompt(context, monkeypatch):
    http, headers, session, _ = context
    _provider(http, headers)
    _activate(http, headers, prompt_registry.FIELD_KEY,
              "You are the field agent. FIELD-MARKER: one line, one VERDICT.")

    mission = http.post("/api/v1/agent/missions", json={
        "goal": "reproduce finding f-1", "capability": "validate",
        "targets": [{"kind": "url", "value": "https://app.example.test"}],
        "tools": ["curl"], "actor": "santiago",
        "budget": {"steps": 4, "tokens": 4000, "wall_s": 300, "usd": 0.0},
    }, headers=headers).json()["data"]
    http.post(f"/api/v1/agent/missions/{mission['id']}/approve", headers=headers)
    task = http.post(f"/api/v1/agent/missions/{mission['id']}/tasks", json={
        "kind": "validate.finding",
        "target": {"kind": "url", "value": "https://app.example.test"},
    }, headers=headers).json()["data"]
    token = http.post(f"/api/v1/agent/tasks/{task['id']}/claim",
                      json={"worker": "w"}, headers=headers).json()["data"]["token"]

    seen: dict = {}

    def fake(provider, api_key, messages, tools, *, transport=None,
             session_id="", max_tokens=None):
        seen["messages"] = messages
        return {"content": "VERDICT: INCONCLUSIVE", "tool_calls": [],
                "tokens_in": 10, "tokens_out": 5}

    monkeypatch.setattr(engine, "complete", fake)
    response = http.post("/api/v1/agent/llm/complete",
                         json={"messages": [{"role": "user", "content": "go"}]},
                         headers={"X-Agent-Token": token})
    assert response.status_code == 200, response.text

    assert seen["messages"][0]["role"] == "system"
    # The platform prepends the field prompt, then the language rule: the contract is that
    # the operator's instructions reach the worker, not that the string is byte-identical.
    assert "FIELD-MARKER" in seen["messages"][0]["content"], \
        "the operator's instruction reaches the worker"
    assert "language of the mission goal" in seen["messages"][0]["content"]
    step = (session.query(models.AiStep).filter_by(run_id=mission["run_id"]).one())
    assert step.prompt_version == "field.generic@1"


def test_an_agent_prompt_is_a_versioned_key_and_the_code_string_is_the_floor(context):
    """The seam this closes: an agent's instructions used to be code-only, so editing a
    prompt in the console could not change an agent and an agent's step could only say
    `@code`. Now the key exists, the floor still wins when no version is active."""
    http, headers, db, _ = context
    db.add(models.AgentSpec(name="Estate Analyst", slug="estate.analyst",
                            agent_class="analyst", description="Inventory.",
                            tools=json.dumps(["projects_list"]),
                            must_return=json.dumps(["answer"]), status="active"))
    db.commit()

    registry = http.get("/api/v1/ai/prompts", headers=headers).json()["data"]
    key = next(row for row in registry if row["key"] == "agent.estate.analyst")
    assert "Estate Analyst (estate.analyst)" in key["code_default"]
    assert key["active"] is None, "no version yet: the floor is what runs"

    frozen = prompt_registry.freeze(db)
    body, label = frozen["agent.estate.analyst"]
    assert label == "agent.estate.analyst@code"
    assert "Estate Analyst" in body

    draft = http.post("/api/v1/ai/prompts", json={
        "key": "agent.estate.analyst", "body": "You are the estate analyst, v2."},
        headers=headers).json()["data"]
    assert draft["version"] == 1 and draft["status"] == "draft"
    assert prompt_registry.freeze(db)["agent.estate.analyst"][1] == \
        "agent.estate.analyst@code", "a draft never reaches a run"

    http.post(f"/api/v1/ai/prompts/{draft['id']}/activate", json={}, headers=headers)
    body, label = prompt_registry.freeze(db)["agent.estate.analyst"]
    assert label == "agent.estate.analyst@1"
    assert body == "You are the estate analyst, v2."

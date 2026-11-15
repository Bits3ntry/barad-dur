"""A catalogue agent runs — and is refused when it cannot see anything.

The console listed four agents and every mention fell into "no specialist is called".
A row that nothing can execute is a card, not an agent: these two tests hold the line
between the two, in the same ledger Palantír already uses.
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
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/agents.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "agents")
    session.commit()

    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, session


def _provider(db):
    row = models.AiProvider(name="stub", kind="openai-compatible",
                            base_url="http://llm.test/v1", model="small",
                            secret_cipher="sealed", price_in=1.0, price_out=1.0,
                            is_default=True)
    db.add(row)
    db.commit()
    return row


def _spec(db, slug, tools, status="active"):
    db.add(models.AgentSpec(
        name=slug.replace(".", " ").title(), slug=slug, agent_class="analyst",
        description=f"Answers {slug} questions.",
        tools=json.dumps(tools), must_return=json.dumps(["claims", "open_questions"]),
        status=status))
    db.commit()


def test_a_catalogue_agent_answers_in_the_same_ledger(client, monkeypatch):
    http, headers, db = client
    _spec(db, "change.impact", ["findings_search"])
    _provider(db)
    monkeypatch.setattr("backend.app.secrets.open_sealed", lambda s, c: "sk")
    seen = {}

    def fake(provider, key, messages, tools, transport=None, session_id=None, **kwargs):
        seen["system"] = messages[0]["content"]
        seen["tools"] = [row["function"]["name"] for row in (tools or [])]
        return {"content": "Ningún claim dice que el cambio rompa algo.",
                "tool_calls": [], "tokens_in": 40, "tokens_out": 12}

    monkeypatch.setattr(engine, "complete", fake)
    session = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]

    body = http.post(f"/api/v1/ai/sessions/{session['id']}/turns",
                     json={"question": "@change.impact ¿rompe algo?"},
                     headers=headers).json()["data"]

    assert body["turn"]["role"] == "specialist"
    assert body["turn"]["profile"] == "change.impact"
    assert body["run"]["status"] == "answered"
    assert "change.impact" in seen["system"], "the agent's own identity is the prompt"
    assert "Ningún claim" in seen["system"] or "must return" in seen["system"]
    assert seen["tools"] == ["findings_search"], "a spec's tools are its ceiling"

    step = db.query(models.AiStep).filter_by(run_id=body["run"]["id"]).one()
    assert step.role == "change.impact"
    assert step.prompt_version == "agent.change.impact@code"


def test_a_spec_that_cannot_read_the_estate_is_refused(client, monkeypatch):
    http, headers, db = client
    _spec(db, "prose.only", [])
    _provider(db)
    session = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]

    body = http.post(f"/api/v1/ai/sessions/{session['id']}/turns",
                     json={"question": "@prose.only ¿estamos expuestos?"},
                     headers=headers).json()["data"]
    assert body["run"] is None, "no tokens spent on an agent that cannot see anything"
    assert "no puede correr" in body["turn"]["content"]


def test_a_draft_spec_is_not_addressable(client, monkeypatch):
    http, headers, db = client
    _spec(db, "validate.finding", ["curl"], status="draft")
    _provider(db)
    monkeypatch.setattr("backend.app.secrets.open_sealed", lambda s, c: "sk")
    # A draft falls back to the orchestrator, which needs a model to answer at all.
    monkeypatch.setattr(engine, "complete",
                        lambda *a, **k: {"content": "No tengo datos.",
                                         "tool_calls": [], "tokens_in": 5,
                                         "tokens_out": 3})
    session = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]
    body = http.post(f"/api/v1/ai/sessions/{session['id']}/turns",
                     json={"question": "@validate.finding probá esto"},
                     headers=headers).json()["data"]
    assert "No specialist is called" in body["turn"]["content"]
    assert body["turn"]["profile"] != "validate.finding", \
        "a draft names itself in the catalogue, not in an answer"

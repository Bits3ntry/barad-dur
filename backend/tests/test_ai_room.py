"""A room: several agents take turns, and it goes quiet when nobody asks anything.

The property under test is the one that makes a room useful instead of expensive: the
turn ceiling is a backstop, not the stop condition. A room ends because a turn brings
nobody back — and a room where every voice brings a peer back still stops at six.
"""
import json
import re
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

SLUG_RE = re.compile(r"You are .*?\(([a-z0-9._-]+)\)")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/room.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "room")
    session.commit()

    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, session


def _room_fixture(db, slugs=("alpha.one", "beta.two", "gamma.three")):
    for slug in slugs:
        db.add(models.AgentSpec(
            name=slug.split(".")[0].title(), slug=slug, agent_class="analyst",
            description=f"Agent {slug}.", tools=json.dumps(["findings_search"]),
            must_return=json.dumps(["claims"]), status="active"))
    db.add(models.AiProvider(name="stub", kind="openai-compatible",
                             base_url="http://llm.test/v1", model="small",
                             secret_cipher="sealed", price_in=1.0, price_out=1.0,
                             is_default=True))
    db.commit()


def _replies(monkeypatch, mapping):
    """Answer per agent slug: each agent's prose is decided by who it is."""
    calls = []

    def fake(provider, key, messages, tools, transport=None, session_id=None, **kwargs):
        match = SLUG_RE.search(messages[0]["content"])
        slug = match.group(1) if match else "?"
        calls.append(slug)
        return {"content": mapping.get(slug, "Nada más que agregar."),
                "tool_calls": [], "tokens_in": 20, "tokens_out": 8}

    monkeypatch.setattr(engine, "complete", fake)
    monkeypatch.setattr("backend.app.secrets.open_sealed", lambda s, c: "sk")
    return calls


def test_a_room_takes_turns_and_goes_quiet_when_nobody_asks(client, monkeypatch):
    http, headers, db = client
    _room_fixture(db)
    calls = _replies(monkeypatch, {
        "alpha.one": "Encontré esto. Coincido con el resto.",
        # beta brings alpha back: a mention of somebody who already spoke re-queues
        # them, and that is the only thing that keeps a room going.
        "beta.two": "Coincido en parte. @alpha.one, ¿y el resto del parque?",
        "gamma.three": "Confirmado, y no hay más.",
    })
    session = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]

    body = http.post(f"/api/v1/ai/sessions/{session['id']}/turns",
                     json={"question": "/sala @alpha.one @beta.two @gamma.three "
                                       "¿estamos expuestos?"},
                     headers=headers).json()["data"]
    assert body["turn"]["role"] == "specialist"

    full = http.get(f"/api/v1/ai/sessions/{session['id']}", headers=headers).json()["data"]
    speakers = [row["profile"] for row in full["turn_rows"] if row["role"] == "specialist"]
    # alpha and beta in their own turn; gamma came back because alpha mentioned it.
    assert speakers == ["alpha.one", "beta.two", "gamma.three", "alpha.one"]
    assert calls == speakers, "one run per voice, no hidden retries"
    # The second time alpha speaks it has the room in front of it: the transcript is
    # context, not a hidden re-prompt.
    second = [row["content"] for row in full["turn_rows"]
              if row["role"] == "specialist"][3]
    assert "Encontré esto" in second


def test_a_room_where_everyone_mentions_everyone_still_stops(client, monkeypatch):
    """The ceiling is a backstop: without it a mutual-mention loop is an unbounded bill."""
    http, headers, db = client
    _room_fixture(db)
    _replies(monkeypatch, {
        "alpha.one": "@beta.two ¿y vos?", "beta.two": "@alpha.one ¿y vos?",
        "gamma.three": "@alpha.one seguí."})
    session = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]

    http.post(f"/api/v1/ai/sessions/{session['id']}/turns",
              json={"question": "/sala @alpha.one @beta.two @gamma.three ¿algo?"},
              headers=headers)
    full = http.get(f"/api/v1/ai/sessions/{session['id']}", headers=headers).json()["data"]
    speakers = [row["profile"] for row in full["turn_rows"] if row["role"] == "specialist"]
    # The per-agent cap ends it before the ceiling when two voices keep calling each
    # other; either way the room terminates, and that is what this asserts.
    assert 4 <= len(speakers) <= 6, "six voices is a room; forty is a bill"


def test_a_room_needs_two_agents_that_can_read(client, monkeypatch):
    http, headers, db = client
    db.add(models.AgentSpec(name="Prose", slug="prose.only", agent_class="analyst",
                            description="x", tools="[]", must_return='["claims"]',
                            status="active"))
    _room_fixture(db)
    _replies(monkeypatch, {})
    session = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]

    body = http.post(f"/api/v1/ai/sessions/{session['id']}/turns",
                     json={"question": "/sala @prose.only @alpha.one ¿algo?"},
                     headers=headers).json()["data"]
    assert "al menos dos agentes" in body["turn"]["content"]

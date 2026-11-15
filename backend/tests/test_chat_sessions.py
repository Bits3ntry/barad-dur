"""Chat sessions: the record, the assembled prompt, and compaction (F1, §4c).

Three invariants, one test each:

* the record keeps every turn even after compression (`chat_turns` is never pruned);
* the prompt is `brief + pins + last K`, so it stops growing;
* a compaction is visible as a divider turn, and a pinned turn survives it.
"""
import sys
from datetime import timedelta
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import auth_local, models  # noqa: E402
from backend.app.ai import engine  # noqa: E402
from backend.app.ai import session as ctx  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/chat.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "chat")
    viewer = models.User(org_id=org.id, email="viewer@example.test", role="viewer")
    session.add(viewer)
    session.flush()
    raw = "viewer-token"
    session.add(models.UserSession(org_id=org.id, user_id=viewer.id,
                                   token_hash=auth_local.token_hash(raw),
                                   expires_at=models.utcnow() + timedelta(hours=2)))
    session.commit()

    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, {"Authorization": f"Bearer {raw}"}, session


def _provider(db):
    row = models.AiProvider(name="stub", kind="openai-compatible",
                            base_url="http://llm.test/v1", model="small",
                            secret_cipher="sealed", price_in=1.0, price_out=1.0,
                            is_default=True)
    db.add(row)
    db.commit()
    return row


def test_a_turn_is_recorded_with_its_run(client, monkeypatch):
    http, headers, _, db = client
    session = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]
    assert session["title"] == "" and session["turns"] == 0

    _provider(db)
    monkeypatch.setattr("backend.app.secrets.open_sealed", lambda s, c: "sk")
    monkeypatch.setattr(engine, "complete",
                        lambda provider, key, messages, tools, transport=None, session_id=None: {
                            "content": "Tenés 571 findings abiertos.",
                            "tool_calls": [], "tokens_in": 90, "tokens_out": 30})

    turn = http.post(f"/api/v1/ai/sessions/{session['id']}/turns",
                     json={"question": "¿cuántos findings abiertos tengo?"},
                     headers=headers)
    assert turn.status_code == 201, turn.text
    data = turn.json()["data"]
    assert data["turn"]["role"] == "orchestrator"
    assert data["turn"]["content"].startswith("Tenés")
    assert data["turn"]["run_id"]
    assert data["run"]["status"] == "answered"
    assert data["session"]["title"].startswith("¿cuántos findings")
    assert data["session"]["turns"] == 2          # the question and the answer

    full = http.get(f"/api/v1/ai/sessions/{session['id']}", headers=headers).json()["data"]
    assert [row["role"] for row in full["turn_rows"]] == ["user", "orchestrator"]
    listed = http.get("/api/v1/ai/sessions", headers=headers).json()["data"]
    assert listed[0]["turns"] == 2
    assert listed[0]["cost_usd"] == pytest.approx((90 + 30) / 1e6)


def test_no_provider_leaves_the_session_waiting_on_a_human(client, monkeypatch):
    http, headers, _, _ = client
    session = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]
    turn = http.post(f"/api/v1/ai/sessions/{session['id']}/turns",
                     json={"question": "¿nos afecta esto?"}, headers=headers)
    data = turn.json()["data"]
    assert data["run"]["status"] == "stopped_no_provider"
    assert "Settings" in data["turn"]["content"]
    assert data["session"]["status"] == "needs_you"


def test_assembly_is_brief_plus_pins_plus_last_k(client):
    _, _, _, db = client
    org = db.query(models.Organization).one()
    row = models.ChatSession(org_id=org.id, title="x", brief="DECISION: solo DEV.")
    db.add(row)
    db.flush()
    turns = []
    for index in range(1, 21):
        turn = models.ChatTurn(org_id=org.id, session_id=row.id, seq=index,
                               role="user" if index % 2 else "orchestrator",
                               content=f"turno {index}")
        db.add(turn)
        turns.append(turn)
    db.commit()
    db.add(models.ChatPin(org_id=org.id, session_id=row.id,
                          turn_id=turns[0].id, note="el scope"))
    db.commit()

    messages = ctx.assemble(db, row, question="¿y ahora?")
    text = "\n".join(m["content"] for m in messages)
    assert "DECISION: solo DEV." in text          # the brief
    assert "turno 1" in text                      # the pinned turn, long out of window
    assert "turno 20" in text                     # the newest turn
    assert "turno 10" not in text                 # the window is K, not everything
    assert messages[-1]["content"] == "¿y ahora?"
    assert len(messages) <= ctx.K_TURNS + 3


def test_compaction_keeps_the_record_and_shows_the_seam(client, monkeypatch):
    http, headers, _, db = client
    _provider(db)
    session = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]
    org = db.query(models.Organization).one()
    row = db.get(models.ChatSession, session["id"])
    for index in range(1, 15):
        db.add(models.ChatTurn(org_id=org.id, session_id=row.id, seq=index,
                               role="user" if index % 2 else "orchestrator",
                               content=f"pregunta {index}"))
    db.commit()

    monkeypatch.setattr("backend.app.secrets.open_sealed", lambda s, c: "sk")
    monkeypatch.setattr(engine, "complete",
                        lambda provider, key, messages, tools, transport=None, session_id=None: {
                            "content": "DECISION: el CVE no aplica a PRO.",
                            "tool_calls": [], "tokens_in": 200, "tokens_out": 60})

    response = http.post(f"/api/v1/ai/sessions/{session['id']}/compact",
                         headers=headers)
    assert response.status_code == 200, response.text
    result = response.json()["data"]
    assert result["compacted"] is True
    assert result["brief_version"] == 1

    full = http.get(f"/api/v1/ai/sessions/{session['id']}", headers=headers).json()["data"]
    roles = [row["role"] for row in full["turn_rows"]]
    assert roles.count("compaction") == 1
    assert full["brief"].startswith("DECISION")
    # The record is intact: fourteen turns plus the divider.
    assert len([role for role in roles if role != "compaction"]) == 14
    divider = next(row for row in full["turn_rows"] if row["role"] == "compaction")
    assert "context compacted" in divider["content"]


def test_a_turn_compacts_by_itself_when_the_window_is_full(client, monkeypatch):
    http, headers, _, db = client
    _provider(db)
    session = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]
    org = db.query(models.Organization).one()
    row = db.get(models.ChatSession, session["id"])
    for index in range(1, 15):
        db.add(models.ChatTurn(org_id=org.id, session_id=row.id, seq=index,
                               role="user" if index % 2 else "orchestrator",
                               content=f"pregunta {index}"))
    db.commit()

    monkeypatch.setattr("backend.app.secrets.open_sealed", lambda s, c: "sk")
    monkeypatch.setattr(engine, "complete",
                        lambda provider, key, messages, tools, transport=None, session_id=None: {
                            "content": "respuesta compactada", "tool_calls": [],
                            "tokens_in": 50, "tokens_out": 20})
    response = http.post(f"/api/v1/ai/sessions/{session['id']}/turns",
                         json={"question": "¿seguimos?"}, headers=headers)
    compaction = response.json()["data"]["compaction"]
    assert compaction and compaction["compacted"] is True
    assert response.json()["data"]["session"]["brief_version"] == 1


def test_pins_and_archive(client):
    http, headers, _, _ = client
    session = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]
    http.post(f"/api/v1/ai/sessions/{session['id']}/turns",
              json={"question": "pregunta sin proveedor"}, headers=headers)
    full = http.get(f"/api/v1/ai/sessions/{session['id']}", headers=headers).json()["data"]
    turn_id = full["turn_rows"][0]["id"]
    pin = http.post(f"/api/v1/ai/sessions/{session['id']}/pins",
                    json={"turn_id": turn_id, "note": "scope"}, headers=headers)
    assert pin.status_code == 201
    pinned = http.get(f"/api/v1/ai/sessions/{session['id']}",
                      headers=headers).json()["data"]["pins"]
    assert pinned[0]["turn_id"] == turn_id

    archived = http.patch(f"/api/v1/ai/sessions/{session['id']}",
                          json={"archive": True}, headers=headers)
    assert archived.json()["data"]["status"] == "archived"
    assert http.get("/api/v1/ai/sessions", headers=headers).json()["total"] == 0
    assert http.get("/api/v1/ai/sessions?include_archived=true",
                    headers=headers).json()["total"] == 1
    blocked = http.post(f"/api/v1/ai/sessions/{session['id']}/turns",
                        json={"question": "hola?"}, headers=headers)
    assert blocked.status_code == 409


def test_viewer_cannot_create_sessions(client):
    http, _, viewer_headers, _ = client
    assert http.post("/api/v1/ai/sessions", json={},
                     headers=viewer_headers).status_code == 403


def test_mention_routes_to_a_profile_or_says_so(client, monkeypatch):
    http, headers, _, db = client
    _provider(db)
    seen: list[str] = []
    monkeypatch.setattr("backend.app.secrets.open_sealed", lambda s, c: "sk")

    def fake_complete(provider, key, messages, tools, transport=None, session_id=None):
        seen.append(messages[-1]["content"])
        return {"content": "respuesta", "tool_calls": [],
                "tokens_in": 30, "tokens_out": 10}

    monkeypatch.setattr(engine, "complete", fake_complete)
    session = http.post("/api/v1/ai/sessions", json={}, headers=headers).json()["data"]

    # @palantir is addressed directly: the turn is attributed to the specialist and
    # the mention is not part of the question.
    turn = http.post(f"/api/v1/ai/sessions/{session['id']}/turns",
                     json={"question": "@palantir ¿cuántos findings abiertos tengo?"},
                     headers=headers).json()["data"]
    assert turn["turn"]["role"] == "specialist"
    assert turn["turn"]["profile"] == "palantir"
    assert "@palantir" not in seen[-1]
    assert "findings abiertos" in seen[-1]

    # A profile that runs in the field answers with where it runs, not with a fake run.
    angmar = http.post(f"/api/v1/ai/sessions/{session['id']}/turns",
                       json={"question": "@angmar reproducí el finding F-1"},
                       headers=headers).json()["data"]
    assert angmar["run"] is None, "a proposal spends no model tokens"
    # `@angmar` used to explain its own phase. It now asks for the one thing a mission
    # needs: the finding it would prove.
    assert "id del hallazgo" in angmar["turn"]["content"]
    # ...and says what a mission is, so the word is not a dead reference.
    assert "misión" in angmar["turn"]["content"]

    # An unknown handle falls back to the orchestrator and says which name was wrong.
    unknown = http.post(f"/api/v1/ai/sessions/{session['id']}/turns",
                        json={"question": "@nobody hola"}, headers=headers).json()["data"]
    assert unknown["turn"]["role"] == "orchestrator"
    assert "No specialist is called" in unknown["turn"]["content"]
    assert "nobody" in unknown["turn"]["content"]

"""Settings → AI, budget and the read-only analyst (F1).

The four properties under test are the ones that make an assistant trustworthy:

* the provider key never leaves the server (`key_set`, never the cipher);
* a run executes as the caller and a `viewer` cannot start one (D44);
* the budget stops the run *before* the call and names the cap (D10);
* every run is a row with its steps, so the answer has a receipt.
"""
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


@pytest.fixture()
def app_client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/ai.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "ai")

    viewer = models.User(org_id=org.id, email="viewer@example.test", role="viewer")
    session.add(viewer)
    session.flush()
    raw_session = "session-raw-token"
    session.add(models.UserSession(
        org_id=org.id, user_id=viewer.id,
        token_hash=auth_local.token_hash(raw_session),
        expires_at=models.utcnow() + timedelta(hours=2)))
    session.commit()

    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, \
        {"Authorization": f"Bearer {raw_session}"}, session


def _provider(http, headers, **extra):
    payload = {"name": "stub", "kind": "openai-compatible",
               "base_url": "http://llm.test/v1", "model": "small",
               "api_key": "sk-secret", "price_in": 1.0, "price_out": 2.0,
               "is_default": True, **extra}
    return http.post("/api/v1/ai/providers", json=payload, headers=headers)


def test_provider_is_stored_sealed_and_never_returned(app_client):
    http, headers, _, session = app_client
    created = _provider(http, headers)
    assert created.status_code == 201, created.text
    body = created.json()["data"]
    assert body["key_set"] is True
    assert "api_key" not in body and "secret_cipher" not in body
    assert "sk-secret" not in created.text

    row = session.query(models.AiProvider).one()
    assert row.secret_cipher and "sk-secret" not in row.secret_cipher

    listed = http.get("/api/v1/ai/providers", headers=headers).json()["data"]
    assert [row["name"] for row in listed] == ["stub"]

    cleared = http.patch(f"/api/v1/ai/providers/{body['id']}",
                         json={"api_key": ""}, headers=headers)
    assert cleared.status_code == 200
    assert cleared.json()["data"]["key_set"] is False


def test_settings_and_spend_report_the_ceiling(app_client):
    http, headers, _, _ = app_client
    patched = http.patch("/api/v1/ai/settings",
                         json={"monthly_token_cap": 1000, "monthly_cost_cap": 1.5,
                               "max_steps": 4}, headers=headers)
    assert patched.status_code == 200, patched.text
    settings = http.get("/api/v1/ai/settings", headers=headers).json()["data"]
    assert settings["monthly_token_cap"] == 1000
    assert settings["max_steps"] == 4
    spend = http.get("/api/v1/ai/spend", headers=headers).json()["data"]
    assert spend["tokens"] == 0
    assert spend["token_cap"] == 1000


def test_run_without_provider_says_exactly_that(app_client):
    http, headers, _, _ = app_client
    response = http.post("/api/v1/ai/runs", json={"question": "¿qué tenemos?"},
                         headers=headers)
    assert response.status_code == 201, response.text
    run = response.json()["data"]
    assert run["status"] == "stopped_no_provider"
    assert "Settings" in run["error"]


def test_run_answers_with_steps_recorded(app_client, monkeypatch):
    http, headers, _, session = app_client
    _provider(http, headers)

    monkeypatch.setattr(engine, "complete",
                        lambda provider, key, messages, tools, transport=None, session_id=None: {
                            "content": "Tenés 571 findings abiertos.",
                            "tool_calls": [], "tokens_in": 120, "tokens_out": 40})
    response = http.post("/api/v1/ai/runs",
                         json={"question": "¿cuántos findings abiertos tengo?"},
                         headers=headers)
    assert response.status_code == 201, response.text
    run = response.json()["data"]
    assert run["status"] == "answered"
    assert run["answer"].startswith("Tenés")
    assert run["steps"] == 1 and run["tool_calls"] == 0
    assert run["tokens_in"] == 120 and run["tokens_out"] == 40
    # 120 * 1.0 / 1M + 40 * 2.0 / 1M
    assert run["cost_usd"] == pytest.approx(120 / 1e6 + 80 / 1e6)
    assert run["price_known"] is True
    # A8: the step names the prompt version that produced it, never a global era
    label = run["step_rows"][0]["prompt_version"]
    assert label.startswith(run["step_rows"][0]["role"] + "@"), label

    stored = session.query(models.AiStep).one()
    assert stored.tokens_in == 120


def test_run_executes_a_tool_call_then_answers(app_client, monkeypatch):
    http, headers, _, _ = app_client
    _provider(http, headers)
    calls = []

    def fake_complete(provider, key, messages, tools, transport=None, session_id=None):
        if len(calls) == 0:
            calls.append("tool")
            return {"content": "", "tokens_in": 100, "tokens_out": 20,
                    "tool_calls": [{"id": "c1", "type": "function",
                                    "function": {"name": "projects_list",
                                                 "arguments": "{}"}}]}
        calls.append("answer")
        return {"content": "Hay 1 proyecto.", "tool_calls": [],
                "tokens_in": 150, "tokens_out": 30}

    monkeypatch.setattr(engine, "complete", fake_complete)
    monkeypatch.setattr("backend.app.ai.dispatch.call",
                        lambda name, args, *, org, session: {"data": [{"slug": "aurea"}]})

    response = http.post("/api/v1/ai/runs", json={"question": "¿qué proyectos hay?"},
                         headers=headers)
    run = response.json()["data"]
    assert run["status"] == "answered"
    assert run["steps"] == 2
    assert run["tool_calls"] == 1
    assert run["answer"] == "Hay 1 proyecto."
    tools_used = [call["tool"] for row in run["step_rows"]
                  for call in row["tool_calls"] if call["tool"]]
    assert tools_used == ["projects_list"]


def test_budget_stops_the_run_before_any_call(app_client, monkeypatch):
    http, headers, _, _ = app_client
    _provider(http, headers)
    http.patch("/api/v1/ai/settings", json={"monthly_token_cap": 0}, headers=headers)
    called = []
    monkeypatch.setattr(engine, "complete",
                        lambda *a, **k: called.append(1) or {})

    response = http.post("/api/v1/ai/runs", json={"question": "¿nos afecta?"},
                         headers=headers)
    run = response.json()["data"]
    assert run["status"] == "stopped_budget"
    assert "token cap reached" in run["stop_reason"]
    assert called == [], "the cap must stop the run before the provider is called"


def test_viewer_cannot_start_a_run(app_client):
    http, _, viewer_headers, session = app_client
    response = http.post("/api/v1/ai/runs", json={"question": "¿nos afecta?"},
                         headers=viewer_headers)
    assert response.status_code == 403
    assert "viewer" in response.json()["detail"]
    # Nothing ran, nothing was recorded: a refused request leaves no half-run.
    assert session.query(models.AiRun).count() == 0


def test_profiles_are_listed_and_act_mode_is_not_available_yet(app_client):
    http, headers, _, _ = app_client
    keys = [row["key"] for row in http.get("/api/v1/ai/profiles",
                                           headers=headers).json()["data"]]
    assert keys == ["palantir", "angmar", "morgoth"]
    response = http.post("/api/v1/ai/runs",
                         json={"question": "buscá algo", "mode": "act"},
                         headers=headers)
    assert response.status_code == 501
    assert "F4" in response.json()["detail"]

"""Providers: presets make the form one field, and a local runtime has no key.

Two failures these tests exist to prevent:

* the operator has to know a base URL, a kind and a model name before the first
  question — which is where most local-model setups die;
* a keyless provider (Ollama, vLLM, LM Studio) is rejected by a form or an
  `Authorization` header it never needed.
"""
import json
import sys
from pathlib import Path

import httpx
import pytest

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app import models  # noqa: E402
from backend.app.ai import engine, presets  # noqa: E402
from backend.app.auth import create_key  # noqa: E402
from backend.app.db import session_factory  # noqa: E402
from backend.app.main import create_app  # noqa: E402


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("PLATFORM_DATABASE_URL", f"sqlite:///{tmp_path}/providers.db")
    monkeypatch.setenv("BOOTSTRAP_TOKEN", "boot")
    app = create_app()
    session = session_factory()()
    models.Base.metadata.create_all(session.get_bind())
    org = models.Organization(slug="poc", name="POC")
    session.add(org)
    session.flush()
    key = create_key(session, org.id, "p")
    session.commit()
    from fastapi.testclient import TestClient
    return TestClient(app), {"X-API-Key": key}, session


def test_every_vendor_the_operator_cares_about_has_a_shape():
    shapes = {preset["key"]: preset for preset in presets.PRESETS}
    assert {"deepseek", "openai", "openrouter", "opencode-go", "ollama",
            "custom"} <= set(shapes)
    assert shapes["deepseek"]["base_url"] == "https://api.deepseek.com/v1"
    assert shapes["deepseek"]["default_model"] == "deepseek-chat"
    assert shapes["openrouter"]["base_url"] == "https://openrouter.ai/api/v1"
    assert shapes["ollama"]["needs_key"] is False
    assert shapes["ollama"]["base_url"].startswith("http://host.docker.internal")
    assert shapes["ollama"]["price_in"] == 0.0
    # No invented prices: unknown stays null and the ledger says so.
    assert shapes["deepseek"]["price_in"] is None
    for shape in shapes.values():
        assert "api_key" not in shape, "a preset must never carry a secret"


def test_the_opencode_go_preset_is_the_subscription_endpoint():
    """Go is a flat plan behind one base URL: the operator's only input is the key.

    The model list stays inside the family Go serves on /chat/completions — its GPT
    and Grok rows answer on /responses and Claude/Qwen/MiniMax on /v1/messages.
    """
    shape = presets.get("opencode-go")
    assert shape is not None, "the subscription shape must exist, not just a blank gateway"
    assert shape["base_url"] == "https://opencode.ai/zen/go/v1"
    assert shape["default_model"] == "deepseek-v4.1-flash"
    assert shape["needs_key"] is True
    # A flat monthly plan has no price per call: a number here would be invented.
    assert shape["price_in"] is None and shape["price_out"] is None
    for model in shape["models"]:
        assert not model.startswith(("gpt-", "grok-", "claude-", "qwen", "minimax-")), \
            f"{model} is not served on chat/completions"


def test_the_client_identifies_itself_only_where_the_endpoint_asks():
    """OpenCode Go meters by user agent and per-conversation id; other hosts get none."""
    go = presets.client_headers("https://opencode.ai/zen/go/v1", "run-7")
    assert go["User-Agent"].startswith("barad-dur")
    assert go["x-opencode-session"] == "run-7"
    assert presets.client_headers("https://opencode.ai/zen/go/v1")["x-opencode-session"]
    assert presets.client_headers("https://api.deepseek.com/v1", "run-7") == {}


def test_the_presets_endpoint_is_public_data(client):
    http, headers, _ = client
    body = http.get("/api/v1/ai/providers/presets", headers=headers)
    assert body.status_code == 200, body.text
    keys = [row["key"] for row in body.json()["data"]]
    assert "ollama" in keys and "deepseek" in keys


def test_a_keyless_provider_is_created_and_tested_without_a_key(client, monkeypatch):
    http, headers, session = client
    created = http.post("/api/v1/ai/providers", json={
        "name": "ollama", "kind": "openai-compatible",
        "base_url": "http://host.docker.internal:11434/v1",
        "model": "qwen2.5:1.5b", "price_in": 0, "price_out": 0,
        "is_default": True}, headers=headers)
    assert created.status_code == 201, created.text
    data = created.json()["data"]
    assert data["key_set"] is False
    assert data["price_known"] is True

    monkeypatch.setattr(engine, "complete",
                        lambda provider, key, messages, tools, transport=None: {
                            "content": "pong", "tool_calls": [], "tokens_in": 3,
                            "tokens_out": 1})
    tested = http.post(f"/api/v1/ai/providers/{data['id']}/test", json={},
                       headers=headers).json()
    assert tested["ok"] is True, tested
    assert tested["keyless"] is True


def test_a_local_runtime_is_called_with_no_authorization_header():
    """An empty key means no header at all — not `Bearer `."""
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update({k.lower(): v for k, v in request.headers.items()})
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1}})

    provider = models.AiProvider(name="ollama", kind="openai-compatible",
                                 base_url="http://127.0.0.1:11434/v1", model="m")
    result = engine.complete(provider, "", [{"role": "user", "content": "ping"}], [],
                             transport=httpx.MockTransport(handler))
    assert result["content"] == "ok"
    assert "authorization" not in seen


def test_a_cloud_provider_still_sends_its_key():
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update({k.lower(): v for k, v in request.headers.items()})
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1}})

    provider = models.AiProvider(name="deepseek", kind="openai-compatible",
                                 base_url="https://api.deepseek.com/v1",
                                 model="deepseek-chat")
    engine.complete(provider, "sk-test", [{"role": "user", "content": "ping"}], [],
                    transport=httpx.MockTransport(handler))
    assert seen["authorization"] == "Bearer sk-test"


def test_the_go_endpoint_gets_a_client_name_and_the_conversation_id():
    """Without these two headers Go sees an anonymous SDK and meters the traffic as
    abuse; the run id is what its prompt-cache routing keys on."""
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update({k.lower(): v for k, v in request.headers.items()})
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1}})

    provider = models.AiProvider(id="prov-1", name="opencode-go",
                                 kind="openai-compatible",
                                 base_url="https://opencode.ai/zen/go/v1",
                                 model="deepseek-v4.1-flash")
    engine.complete(provider, "sk-go", [{"role": "user", "content": "ping"}], [],
                    transport=httpx.MockTransport(handler), session_id="run-42")
    assert seen["authorization"] == "Bearer sk-go"
    assert seen["user-agent"].startswith("barad-dur")
    assert seen["x-opencode-session"] == "run-42"

    # A provider named like the vendor but pointed elsewhere gets nothing extra.
    custom = models.AiProvider(id="prov-2", name="opencode-go",
                               kind="openai-compatible",
                               base_url="http://127.0.0.1:8080/v1",
                               model="deepseek-v4.1-flash")
    seen.clear()
    engine.complete(custom, "sk-go", [{"role": "user", "content": "ping"}], [],
                    transport=httpx.MockTransport(handler), session_id="run-42")
    assert "x-opencode-session" not in seen


def test_a_reasoning_model_that_spent_its_budget_is_named_not_silent():
    """An empty message with `finish_reason=length` is a setting, not an answer.

    A thinking model burns `max_tokens` on reasoning; the run then ends "the plan
    produced no answer text", which reads as a cut-off assistant.
    """
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "choices": [{"finish_reason": "length", "message": {"content": ""}}],
            "usage": {"prompt_tokens": 100, "completion_tokens": 1024}})

    provider = models.AiProvider(name="go", kind="openai-compatible",
                                 base_url="https://opencode.ai/zen/go/v1",
                                 model="deepseek-v4.1-flash", max_output_tokens=1024)
    with pytest.raises(engine.ProviderError) as caught:
        engine.complete(provider, "sk", [{"role": "user", "content": "q"}], [],
                        transport=httpx.MockTransport(handler))
    assert "max_tokens (1024)" in str(caught.value)

    # A truncated *tool call* is still a call: the loop can act on it.
    def with_tools(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "choices": [{"finish_reason": "length", "message": {
                "content": "", "tool_calls": [{"id": "c1", "type": "function",
                                               "function": {"name": "x",
                                                            "arguments": "{}"}}]}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1}})

    result = engine.complete(provider, "sk", [{"role": "user", "content": "q"}], [],
                             transport=httpx.MockTransport(with_tools))
    assert result["tool_calls"]


def test_a_provider_with_runs_cannot_be_deleted(client):
    """Deleting would leave a cost with no provider behind it: disable instead."""
    http, headers, session = client
    created = http.post("/api/v1/ai/providers", json={
        "name": "openai", "kind": "openai-compatible",
        "base_url": "https://api.openai.com/v1", "model": "gpt-4o-mini",
        "api_key": "sk"}, headers=headers).json()["data"]
    org = session.query(models.Organization).one()
    session.add(models.AiRun(org_id=org.id, actor="a", actor_role="analyst",
                             question="q", mode="ask", status="failed",
                             provider_id=created["id"], model="gpt-4o-mini"))
    session.commit()

    blocked = http.delete(f"/api/v1/ai/providers/{created['id']}", headers=headers)
    assert blocked.status_code == 409
    assert "disable it instead" in blocked.json()["detail"]

    disabled = http.patch(f"/api/v1/ai/providers/{created['id']}",
                          json={"enabled": False}, headers=headers)
    assert disabled.status_code == 200
    assert disabled.json()["data"]["enabled"] is False


def test_a_preset_can_be_saved_as_a_provider_verbatim(client):
    """The UI sends exactly what the preset gave it."""
    http, headers, _ = client
    shape = presets.get("deepseek")
    payload = {
        "name": shape["key"], "kind": shape["kind"],
        "base_url": shape["base_url"], "model": shape["default_model"],
        "api_key": "sk-from-the-vendor",
        "price_in": shape["price_in"], "price_out": shape["price_out"],
        "is_default": True,
    }
    created = http.post("/api/v1/ai/providers", json=payload, headers=headers)
    assert created.status_code == 201, created.text
    data = created.json()["data"]
    assert data["base_url"] == "https://api.deepseek.com/v1"
    assert data["key_set"] is True
    assert data["price_known"] is False, "no price entered means unknown, not free"
    assert "sk-from-the-vendor" not in json.dumps(data)


def test_cached_prompt_tokens_are_recorded_not_ignored():
    """A provider that reports cache hits must show them; silence hides the saving."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"prompt_tokens": 1000, "completion_tokens": 10,
                      "prompt_tokens_details": {"cached_tokens": 800}}})

    provider = models.AiProvider(name="go", kind="openai-compatible",
                                 base_url="https://opencode.ai/zen/go/v1", model="m")
    result = engine.complete(provider, "k", [{"role": "user", "content": "hi"}], [],
                             transport=httpx.MockTransport(handler))
    assert result["cached_tokens"] == 800


def test_a_provider_without_cache_metadata_reports_zero():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={
            "choices": [{"message": {"content": "ok"}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 2}})

    provider = models.AiProvider(name="go", kind="openai-compatible",
                                 base_url="https://opencode.ai/zen/go/v1", model="m")
    result = engine.complete(provider, "k", [{"role": "user", "content": "hi"}], [],
                             transport=httpx.MockTransport(handler))
    assert result["cached_tokens"] == 0

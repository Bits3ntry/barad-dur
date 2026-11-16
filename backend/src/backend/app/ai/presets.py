"""Provider presets: the shape of a provider, so the operator only pastes a key.

A preset is not a provider. It is the four fields that are the same for everyone
using a vendor — base URL, kind, a short model list, and whether a key exists at
all — plus the documentation URL so the guess is checkable.

Two rules this file follows, because guessing either one would be worse than asking:

* **No invented prices.** Where the price is not certain, it is `None` and the ledger
  says "price unknown" while still counting tokens exactly (D10). A wrong number in a
  cost column is the one error nobody catches.
* **No invented model names.** The list is a starting point, not an enum: the UI
  keeps the field editable, because vendors rename models faster than this file can
  be updated.

`ollama` carries `needs_key: false`. A local runtime has no key, and a provider form
that demands one is the reason people give up on local models.
"""

PRESETS: list[dict] = [
    {
        "key": "deepseek",
        "label": "DeepSeek",
        "kind": "openai-compatible",
        "base_url": "https://api.deepseek.com/v1",
        "models": ["deepseek-chat", "deepseek-reasoner"],
        "default_model": "deepseek-chat",
        "needs_key": True,
        "price_in": None,
        "price_out": None,
        "docs": "https://platform.deepseek.com/api_keys",
        "note": "Cheap and good at code. Prices move: fill them from the vendor page "
                "and the cost ledger stops saying 'price unknown'.",
    },
    {
        "key": "openai",
        "label": "OpenAI",
        "kind": "openai-compatible",
        "base_url": "https://api.openai.com/v1",
        "models": ["gpt-4o-mini", "gpt-4.1-mini"],
        "default_model": "gpt-4o-mini",
        "needs_key": True,
        "price_in": None,
        "price_out": None,
        "docs": "https://platform.openai.com/api-keys",
        "note": "The same key the Codex CLI uses; the model name is whatever your "
                "Codex config declares.",
    },
    {
        "key": "openrouter",
        "label": "OpenRouter",
        "kind": "openai-compatible",
        "base_url": "https://openrouter.ai/api/v1",
        "models": [],
        "default_model": "",
        "needs_key": True,
        "price_in": None,
        "price_out": None,
        "docs": "https://openrouter.ai/keys",
        "note": "One key, many vendors. The model is `vendor/model`, e.g. "
                "`deepseek/deepseek-chat`.",
    },
    {
        "key": "opencode-go",
        "label": "opencode Go",
        "kind": "openai-compatible",
        "base_url": "https://opencode.ai/zen/go/v1",
        # Only the models Go serves on /chat/completions: its GPT/Grok rows answer on
        # /responses and Claude/Qwen/MiniMax on /v1/messages, and the harness speaks
        # one wire format today (O2). A name outside this list still works if the
        # vendor serves it here — the field stays editable.
        "models": ["deepseek-v4.1-flash", "kimi-k2.7-code", "kimi-k3",
                   "glm-5.3-flash", "glm-5.3", "longcat-2.0",
                   "mimo-v2.6-flash", "gemini-4-argon", "step-5-preview"],
        "default_model": "deepseek-v4.1-flash",
        "needs_key": True,
        # A reasoning model spends output tokens thinking before it writes, so a
        # 1024-token cap ends the answer as `finish_reason=length` with no text at all.
        "max_output_tokens": 4096,
        # Flat monthly plan, so there is no price per call to fill in: Go meters a
        # per-model dollar allowance and DeepSeek halves its rate off-peak, which
        # makes any single pair a wrong number half the day (D10). Leave it empty and
        # cap tokens.
        "price_in": None,
        "price_out": None,
        "docs": "https://opencode.ai/console/go",
        "note": "The $10/month subscription ($40 Go Plus), not a pay-as-you-go key: "
                "subscribe in the Console, copy the API key and paste it here. Model "
                "ids carry no vendor prefix (`deepseek-v4.1-flash`). Leave the prices "
                "empty — the plan is flat, so the ledger counts tokens and the cap "
                "that matters is the token cap.",
    },
    {
        "key": "ollama",
        "label": "Ollama (local)",
        "kind": "openai-compatible",
        "base_url": "http://host.docker.internal:11434/v1",
        "models": [],
        "default_model": "",
        "needs_key": False,
        "price_in": 0.0,
        "price_out": 0.0,
        "docs": "https://ollama.com/library",
        "note": "No key: a local runtime is free and offline. Pull a model first "
                "(`ollama pull qwen2.5:1.5b`) and put its name below — the list here "
                "is whatever `ollama list` says.",
    },
    {
        "key": "custom",
        "label": "Other OpenAI-compatible",
        "kind": "openai-compatible",
        "base_url": "",
        "models": [],
        "default_model": "",
        "needs_key": True,
        "price_in": None,
        "price_out": None,
        "docs": "",
        "note": "Anything that speaks /chat/completions: vLLM, LM Studio, a proxy.",
    },
]

BY_KEY = {preset["key"]: preset for preset in PRESETS}


def get(key: str) -> dict | None:
    return BY_KEY.get(key)


#: Headers an endpoint demands beyond `Authorization`, and that the operator cannot
#: infer from the key. OpenCode Go asks every client to identify itself with its own
#: user agent and to carry a stable session id per conversation — it routes prompt
#: caching by that id and treats a generic HTTP-library user agent as the traffic it
#: filters. Keyed by a fragment of the base URL because this is a property of the
#: endpoint, not of the row the operator edits; `{session}` is filled per run.
CLIENT_HEADERS: dict[str, dict[str, str]] = {
    "opencode.ai": {"User-Agent": "barad-dur-console/1.0",
                    "x-opencode-session": "{session}"},
}


def client_headers(base_url: str, session: str = "") -> dict[str, str]:
    """The vendor's own headers for this endpoint, with `{session}` filled in.

    An unknown host gets nothing, so a provider that would reject an unexpected
    header never sees one. `session` is the run id: one conversation, one id.
    """
    host = (base_url or "").lower()
    for fragment, headers in CLIENT_HEADERS.items():
        if fragment in host:
            return {name: value.replace("{session}", session or "none")
                    for name, value in headers.items()}
    return {}

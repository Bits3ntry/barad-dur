"""The read-only analyst: one question, tools, one answer (F1).

What this engine is: a bounded tool-calling loop over the *platform's* catalog. It
answers from rows, cites nothing it did not read, and stops when the budget says so.

What it is not: a chat that improvises. Three rules are structural, not stylistic:

* **Every number comes from a tool.** The system prompt says it, and the run records
  the tool calls that produced the answer, so a claim without a call is visible.
* **Budget before the call, usage after it.** The ceiling is checked before each
  completion (the gateway's job, D10) and the provider's reported usage is what gets
  written — never an estimate.
* **No provider, no answer.** A run with no configured provider ends
  `stopped_no_provider` with that sentence, instead of a helpful guess.

Runs execute inside the request that asked for them: F1 questions are short, and the
caller's credential must stay in scope so tool calls run as that person (D44). The
async mission runner (F4) is the phase where a run outlives its request, and it
carries a task token instead.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timedelta, timezone

import httpx
from fastapi import HTTPException
from sqlalchemy.orm import Session

from backend.app import models, secrets
from backend.app.ai import dispatch
from backend.app.ai import presets
from backend.app.ai import tools as catalog
from backend.app.ai.state import projection

PROMPT_VERSION = "f1.0"

SYSTEM_PROMPT = """You are the read-only analyst of Barad-dûr, a threat-exposure \
platform. Answer the operator's question using the tools provided.

Rules that matter more than being helpful:
- Every number, version, host and identifier must come from a tool result. If you \
did not read it, do not state it.
- `deployment.chain` describes facts and carries no severity. \
`exposure.verdict` interprets them for one vulnerability.
- "unknown" is a real answer. When the data does not settle it, say unknown and \
name the missing edge that would settle it.
- An error or a 404 from a tool is NEVER "not affected" and never "clean".
- A nickname (node2shell, log4shell) is not a row in any table. Resolve it with \
`advisory_resolve` before answering, and treat 'no row matches that word' as an \
unresolved name, not as a clean estate.
- Be brief. Lead with the answer, then the evidence (ids) behind it."""

_JSON_TYPES = {"string": "string", "int": "integer", "bool": "boolean"}


class BudgetExceeded(RuntimeError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ProviderError(RuntimeError):
    pass


def settings_row(session: Session) -> models.AiSettings:
    row = session.get(models.AiSettings, "default")
    if row is None:
        row = models.AiSettings(id="default")
        session.add(row)
        session.commit()
    return row


def default_provider(session: Session) -> models.AiProvider | None:
    rows = (session.query(models.AiProvider)
            .filter_by(enabled=True)
            .order_by(models.AiProvider.is_default.desc(),
                      models.AiProvider.name)
            .all())
    return rows[0] if rows else None


def month_start(now: datetime | None = None) -> datetime:
    now = now or models.utcnow()
    return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)


def month_spend(session: Session, now: datetime | None = None) -> dict:
    """Tokens and cost for the current period, deployment-wide (D17).

    Split by `mode` because one ledger now carries three different spends: a lookup
    (`ask`), a mission's field work, and the compaction that keeps a session cheap.
    A single number let the half that touches targets hide behind the chat's cents.
    """
    since = month_start(now)
    tokens = 0
    cost = 0.0
    price_known = True
    by_mode: dict[str, dict] = {}
    rows = (session.query(models.AiStep, models.AiRun.mode)
            .join(models.AiRun, models.AiStep.run_id == models.AiRun.id)
            .filter(models.AiRun.started_at >= since)
            .all())
    for row, mode in rows:
        step_tokens = (row.tokens_in or 0) + (row.tokens_out or 0)
        tokens += step_tokens
        bucket = by_mode.setdefault(mode or "ask", {"tokens": 0, "cost_usd": 0.0,
                                                    "steps": 0})
        bucket["tokens"] += step_tokens
        bucket["steps"] += 1
        if row.cost_usd is None:
            price_known = False
        else:
            cost += row.cost_usd
            bucket["cost_usd"] += row.cost_usd
    for bucket in by_mode.values():
        bucket["cost_usd"] = round(bucket["cost_usd"], 6)
    return {"period_start": since.isoformat(), "tokens": tokens,
            "cost_usd": round(cost, 6), "price_known": price_known,
            "by_mode": by_mode}


def budget_check(session: Session, settings: models.AiSettings,
                 estimate_tokens: int) -> None:
    """Refuse the *next* completion when the ceiling is already reached."""
    spend = month_spend(session)
    if settings.monthly_token_cap is not None:
        if spend["tokens"] + estimate_tokens > settings.monthly_token_cap:
            raise BudgetExceeded(
                f"monthly token cap reached ({spend['tokens']} of "
                f"{settings.monthly_token_cap} tokens since {spend['period_start']})")
    if settings.monthly_cost_cap is not None and spend["price_known"]:
        if spend["cost_usd"] > settings.monthly_cost_cap:
            raise BudgetExceeded(
                f"monthly cost cap reached (${spend['cost_usd']:.4f} of "
                f"${settings.monthly_cost_cap:.2f} since {spend['period_start']})")


#: A run that has not closed in this long had its process go away (a deploy, a crash,
#: a killed container). The number is a ceiling on "still working", not a timeout: a
#: five-specialist chain with a slow provider is minutes, never an hour.
STALE_AFTER_MINUTES = 60


def sweep_stale_runs(session: Session, *, minutes: int = STALE_AFTER_MINUTES) -> int:
    """Close the runs whose process is gone, and say so.

    An async turn runs in a thread of the API process (A4). If that process is replaced
    mid-run — and a deploy does exactly that — the row keeps reading `running`, which is
    indistinguishable from a run that is still spending money. Closing it with a reason
    keeps the ledger honest; the steps it already recorded are real and stay.
    """
    cutoff = models.utcnow() - timedelta(minutes=minutes)
    rows = (session.query(models.AiRun)
            .filter(models.AiRun.status == "running",
                    models.AiRun.started_at < cutoff).all())
    for run in rows:
        run.status = "failed"
        run.stop_reason = f"stale: no progress for {minutes} min"
        run.error = ("the process running it is gone (deploy, crash or a killed "
                     "worker); the steps it recorded are real")
        run.finished_at = models.utcnow()
    if rows:
        session.commit()
    return len(rows)


def openai_tools(selected: list[str] | None = None) -> list[dict]:
    """The tool list the model sees, generated from the catalog (D56).

    `selected` scopes it to one specialist's tools: a specialist that cannot call a
    tool cannot be talked into using it.
    """
    allowed = set(selected) if selected is not None else None
    out = []
    for tool in catalog.TOOLS:
        if tool["method"] != "GET":
            continue
        if allowed is not None and tool["name"] not in allowed:
            continue
        properties = {}
        required = []
        for name, spec in tool["params"].items():
            properties[name] = {"type": _JSON_TYPES.get(spec.get("type", "string"),
                                                        "string")}
            if spec.get("required"):
                required.append(name)
        schema = {"type": "object", "properties": properties,
                  "additionalProperties": False}
        if required:
            schema["required"] = required
        out.append({"type": "function",
                    "function": {"name": tool["name"],
                                 "description": tool["summary"],
                                 "parameters": schema}})
    return out


def price(provider: models.AiProvider, tokens_in: int, tokens_out: int
          ) -> tuple[float | None, bool]:
    """Cost in USD for a call, or `(None, False)` when a price is missing (D10)."""
    if provider.price_in is None or provider.price_out is None:
        return None, False
    return (tokens_in * provider.price_in + tokens_out * provider.price_out) / 1_000_000, True


def complete(provider: models.AiProvider, api_key: str, messages: list[dict],
             tools: list[dict], *, transport: httpx.BaseTransport | None = None,
             session_id: str = "", max_tokens: int | None = None
             ) -> dict:
    """One chat completion. Returns `{content, tool_calls, tokens_in, tokens_out}`.

    `session_id` is the conversation this call belongs to (the run id). Some
    endpoints refuse to route without one — OpenCode Go asks for a stable
    per-conversation id and for the client to name itself — so it is passed to the
    endpoint's own headers (see `presets.client_headers`).

    `max_tokens` is the caller's ceiling for this one answer (a field task knows how
    long its verdict may be); `None` means the provider row's setting, which is the
    value the operator configured and the one a reasoning model needs.
    """
    if provider.kind != "openai-compatible":
        raise ProviderError(
            f"provider kind '{provider.kind}' is not implemented yet (O2): the "
            "harness speaks the OpenAI wire format today")
    if not provider.base_url:
        raise ProviderError(f"provider '{provider.name}' has no base_url")
    if not provider.model:
        raise ProviderError(f"provider '{provider.name}' has no model")

    body = {"model": provider.model, "messages": messages,
            "max_tokens": max_tokens or provider.max_output_tokens,
            "temperature": 0.2}
    if tools:
        body["tools"] = tools
        body["tool_choice"] = "auto"

    url = provider.base_url.rstrip("/") + "/chat/completions"
    # A conversation turn with tools reaches 15–20k input tokens, and a 60 s ceiling
    # made the planner die as "provider unreachable … read operation timed out" on the
    # round that had everything it needed. 120 s is still a ceiling, not a wait.
    client = httpx.Client(timeout=120.0, transport=transport) if transport else \
        httpx.Client(timeout=120.0)
    # A local runtime (Ollama, vLLM, LM Studio) has no key, and asking it for one is
    # the reason people give up on local models: an empty key means "no header".
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    # The endpoint's own headers (an OpenCode Go subscription wants a client name and
    # a per-conversation id). Absent for every host that does not ask for them.
    headers.update(presets.client_headers(provider.base_url,
                                          session_id or provider.id))
    try:
        response = client.post(url, json=body, headers=headers)
    except httpx.HTTPError as error:
        raise ProviderError(f"provider unreachable at {url}: {error}") from error
    finally:
        client.close()

    if response.status_code >= 400:
        raise ProviderError(f"provider answered {response.status_code} at {url}: "
                            f"{response.text[:300]}")
    payload = response.json()
    choices = payload.get("choices") or []
    if not choices:
        raise ProviderError("provider returned no choices")
    choice = choices[0]
    message = choice.get("message") or {}
    usage = payload.get("usage") or {}
    content = message.get("content") or ""
    calls = message.get("tool_calls") or []
    if not content and not calls and choice.get("finish_reason") == "length":
        # A thinking model spends the output budget on reasoning and never writes the
        # sentence: the run then ends `the plan produced no answer text`, which reads as
        # a cut-off assistant rather than as a setting. Name the budget instead.
        raise ProviderError(
            f"provider exhausted max_tokens ({provider.max_output_tokens}) before "
            "writing any text — a reasoning model needs a larger max output tokens "
            "on the provider row")
    return {
        "content": content,
        "tool_calls": calls,
        "tokens_in": int(usage.get("prompt_tokens") or 0),
        "tokens_out": int(usage.get("completion_tokens") or 0),
        # Providers that cache the prompt report it here; the rest stay at zero, and
        # that zero is honest: nothing was saved.
        "cached_tokens": int((usage.get("prompt_tokens_details") or {})
                             .get("cached_tokens") or 0),
        # Verbatim, and read by nobody yet: a plan that meters instead of billing
        # reports it here, and a run has to be able to prove what it was told even
        # before we know how to add it up.
        "usage_raw": usage,
        "finish_reason": choice.get("finish_reason"),
    }


def execute(session: Session, run: models.AiRun, *, transport: httpx.BaseTransport
            | None = None, context: list[dict] | None = None) -> models.AiRun:
    """Run the loop for an existing `running` row. Closes the row in every path.

    `context` is a pre-assembled message list (the session assembler's output). When
    it is given, its last entry is the question — the caller already appended it.
    """
    settings = settings_row(session)
    provider = session.get(models.AiProvider, run.provider_id) if run.provider_id else None
    if provider is None:
        run.status = "stopped_no_provider"
        run.stop_reason = "no provider configured"
        run.error = "configure a provider in Settings → AI"
        _close(session, run)
        return run

    try:
        api_key = (secrets.open_sealed(session, provider.secret_cipher)
                   if provider.secret_cipher else "")
    except Exception as error:  # a sealed row with no platform key is a real state
        run.status = "failed"
        run.error = f"provider key cannot be decrypted: {error}"
        _close(session, run)
        return run

    tools = openai_tools()
    messages = [{"role": "system", "content": SYSTEM_PROMPT}]
    if context is not None:
        messages.extend(context)
    else:
        messages.append({"role": "user", "content": run.question})
    seq = 0
    while seq < settings.max_steps:
        try:
            budget_check(session, settings, estimate_tokens=1200)
        except BudgetExceeded as error:
            run.status = "stopped_budget"
            run.stop_reason = error.reason
            break

        started = time.monotonic()
        try:
            result = complete(provider, api_key, messages, tools, transport=transport,
                              session_id=run.id)
        except ProviderError as error:
            run.status = "failed"
            run.error = str(error)
            break

        seq += 1
        step = models.AiStep(
            org_id=run.org_id, run_id=run.id, seq=seq, role="orchestrator",
            prompt_version=PROMPT_VERSION,
            tokens_in=result["tokens_in"], tokens_out=result["tokens_out"],
            duration_ms=int((time.monotonic() - started) * 1000))
        cost, known = price(provider, result["tokens_in"], result["tokens_out"])
        step.cost_usd = cost
        run.tokens_in += result["tokens_in"]
        run.tokens_out += result["tokens_out"]
        run.price_known = run.price_known and known
        if cost is not None:
            run.cost_usd = (run.cost_usd or 0.0) + cost

        calls = result["tool_calls"]
        recorded = []
        if calls:
            messages.append({"role": "assistant", "content": result["content"] or None,
                             "tool_calls": calls})
            for call in calls[:4]:
                name = (call.get("function") or {}).get("name") or ""
                raw_args = (call.get("function") or {}).get("arguments") or "{}"
                try:
                    args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args
                except ValueError:
                    args = {}
                try:
                    payload = dispatch.call(name, args, org=_org(session, run),
                                            session=session)
                    status = 200
                except HTTPException as error:
                    # A route's own refusal (400 "provide purl", 404 "not found") is
                    # data with a real status; recording it as 500 teaches the operator
                    # that their own tool call is a server fault.
                    payload = {"error": error.detail, "status": error.status_code,
                               "hint": "a failed tool is not an empty answer"}
                    status = error.status_code
                except Exception as error:  # a tool failure is data, not a crash
                    payload = {"error": str(error),
                               "hint": "a failed tool is not an empty answer"}
                    status = 500
                recorded.append({"tool": name, "args": args, "status": status,
                                 "result_digest": _digest(payload)})
                run.tool_calls += 1
                messages.append({"role": "tool", "tool_call_id": call.get("id", ""),
                                 "name": name,
                                 "content": projection(payload)})
        else:
            run.answer = result["content"]
            recorded.append({"tool": None, "args": {},
                             "status": 200, "result_digest": None})

        step.tool_calls = json.dumps(recorded)
        session.add(step)
        run.steps = seq
        session.commit()
        if not calls:
            run.status = "answered"
            break
    else:
        run.status = "stopped_max_steps"
        run.stop_reason = f"max_steps reached ({settings.max_steps})"

    _close(session, run)
    return run


def _org(session: Session, run: models.AiRun) -> models.Organization:
    org = session.get(models.Organization, run.org_id)
    if org is None:
        raise RuntimeError("run refers to a missing organization")
    return org


def _digest(payload) -> str:
    """A fingerprint of what a tool returned: enough to audit, too small to replay."""
    import hashlib

    blob = json.dumps(payload, sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


def _close(session: Session, run: models.AiRun) -> None:
    run.finished_at = datetime.now(timezone.utc)
    session.commit()

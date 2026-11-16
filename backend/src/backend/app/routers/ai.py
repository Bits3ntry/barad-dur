"""Settings → AI, spend, and the read-only analyst (F1).

Three things this router refuses to do, and they are the point of the phase:

* **It never returns a provider key.** `key_set` is the only truth the API exposes;
  the cipher stays in the row and the plaintext never leaves `secrets.open_sealed`.
* **It never runs a question as a service identity.** The run carries the caller's
  actor and role (D44); a `viewer` cannot start one, because a run spends money and
  reads the estate on somebody's behalf.
* **It never hides the ceiling.** When the budget stops a run, the response names the
  cap and the period, and the run row stays visible with `stopped_budget`.
"""
import json

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models, secrets
from backend.app.ai import authz, engine, orchestrator, presets, profiles
from backend.app.ai import prompts as prompt_registry
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/ai", tags=["ai"])

_principal = authz.principal
_require_analyst = authz.require_analyst


# ─────────────────────────── providers ───────────────────────────

class ProviderIn(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    kind: str = "openai-compatible"
    base_url: str = Field(default="", max_length=255)
    model: str = Field(default="", max_length=128)
    api_key: str | None = Field(default=None, max_length=4096)
    price_in: float | None = None
    price_out: float | None = None
    max_output_tokens: int = Field(default=1024, ge=1, le=32768)
    is_default: bool = False
    enabled: bool = True


class ProviderPatch(BaseModel):
    name: str | None = None
    base_url: str | None = None
    model: str | None = None
    api_key: str | None = None          # "" clears, absent keeps
    price_in: float | None = None
    price_out: float | None = None
    max_output_tokens: int | None = Field(default=None, ge=1, le=32768)
    is_default: bool | None = None
    enabled: bool | None = None


def _provider_data(row: models.AiProvider) -> dict:
    return {"id": row.id, "name": row.name, "kind": row.kind,
            "base_url": row.base_url, "model": row.model,
            "key_set": bool(row.secret_cipher),
            "price_in": row.price_in, "price_out": row.price_out,
            "price_known": row.price_in is not None and row.price_out is not None,
            "max_output_tokens": row.max_output_tokens,
            "enabled": row.enabled, "is_default": row.is_default}


def _one_default(session: Session, keep_id: str) -> None:
    for row in session.query(models.AiProvider).all():
        if row.id != keep_id and row.is_default:
            row.is_default = False


@router.get("/providers/presets")
def list_presets():
    """The shape of a provider, so the operator only pastes a key.

    Declared before `/providers` so the literal path wins the match; a preset is
    static data and needs no organization.
    """
    return {"data": presets.PRESETS}


@router.get("/providers")
def list_providers(org: models.Organization = Depends(auth.require_admin),
                   session: Session = Depends(get_session)):
    rows = (session.query(models.AiProvider)
            .order_by(models.AiProvider.name).all())
    return {"data": [_provider_data(row) for row in rows]}


@router.post("/providers", status_code=status.HTTP_201_CREATED)
def create_provider(payload: ProviderIn,
                    org: models.Organization = Depends(auth.require_admin),
                    session: Session = Depends(get_session)):
    if payload.kind not in models.AI_PROVIDER_KINDS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"kind must be one of {sorted(models.AI_PROVIDER_KINDS)}")
    if (session.query(models.AiProvider)
            .filter_by(name=payload.name).one_or_none() is not None):
        raise HTTPException(status.HTTP_409_CONFLICT, "provider name already exists")
    row = models.AiProvider(
        name=payload.name, kind=payload.kind, base_url=payload.base_url.strip(),
        model=payload.model.strip(), price_in=payload.price_in,
        price_out=payload.price_out, max_output_tokens=payload.max_output_tokens,
        enabled=payload.enabled, is_default=payload.is_default,
        secret_cipher=secrets.seal(session, payload.api_key) if payload.api_key else None)
    session.add(row)
    session.flush()
    if row.is_default:
        _one_default(session, row.id)
    _audit_log(session, org.id, _actor(org), "ai.provider_created",
               "ai_provider", row.id, row.name)
    session.commit()
    return {"data": _provider_data(row)}


@router.patch("/providers/{provider_id}")
def patch_provider(provider_id: str, payload: ProviderPatch,
                   org: models.Organization = Depends(auth.require_admin),
                   session: Session = Depends(get_session)):
    row = session.get(models.AiProvider, provider_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "provider not found")
    if payload.name is not None and payload.name != row.name:
        if (session.query(models.AiProvider)
                .filter_by(name=payload.name).one_or_none() is not None):
            raise HTTPException(status.HTTP_409_CONFLICT, "provider name already exists")
        row.name = payload.name
    if payload.base_url is not None:
        row.base_url = payload.base_url.strip()
    if payload.model is not None:
        row.model = payload.model.strip()
    if payload.api_key is not None:
        row.secret_cipher = secrets.seal(session, payload.api_key) if payload.api_key \
            else None
    if payload.price_in is not None:
        row.price_in = payload.price_in
    if payload.price_out is not None:
        row.price_out = payload.price_out
    if payload.max_output_tokens is not None:
        row.max_output_tokens = payload.max_output_tokens
    if payload.enabled is not None:
        row.enabled = payload.enabled
    if payload.is_default:
        row.is_default = True
        _one_default(session, row.id)
    _audit_log(session, org.id, _actor(org), "ai.provider_updated",
               "ai_provider", row.id, row.name)
    session.commit()
    return {"data": _provider_data(row)}


@router.delete("/providers/{provider_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_provider(provider_id: str,
                    org: models.Organization = Depends(auth.require_admin),
                    session: Session = Depends(get_session)):
    row = session.get(models.AiProvider, provider_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "provider not found")
    used = (session.query(models.AiRun).filter_by(provider_id=provider_id).count())
    if used:
        # Deleting would either orphan the ledger or erase what a run cost. The
        # honest answer is "no": disable it, and the history keeps its provider.
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{used} run(s) used this provider; disable it instead — deleting would "
            "leave their cost with no provider behind it")
    name = row.name
    session.delete(row)
    _audit_log(session, org.id, _actor(org), "ai.provider_deleted",
               "ai_provider", provider_id, name)
    session.commit()
    return None


@router.post("/providers/{provider_id}/test")
def test_provider(provider_id: str,
                  org: models.Organization = Depends(auth.require_admin),
                  session: Session = Depends(get_session)):
    """One tiny completion: the exact error text, or the model that answered."""
    row = session.get(models.AiProvider, provider_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "provider not found")
    if not row.secret_cipher:
        # A local runtime is a real provider with no key: test it like any other.
        try:
            result = engine.complete(row, "",
                                     [{"role": "user", "content": "ping"}], [])
            return {"ok": True, "model": row.model,
                    "sample": result["content"][:120], "keyless": True}
        except Exception as error:
            return {"ok": False, "error": str(error)[:500], "keyless": True}
    try:
        key = secrets.open_sealed(session, row.secret_cipher)
        result = engine.complete(row, key,
                                 [{"role": "user", "content": "ping"}], [])
        return {"ok": True, "model": row.model, "sample": result["content"][:120]}
    except Exception as error:
        return {"ok": False, "error": str(error)[:500]}


# ─────────────────────────── settings and spend ───────────────────────────

class SettingsPatch(BaseModel):
    monthly_token_cap: int | None = Field(default=None, ge=0)
    monthly_cost_cap: float | None = Field(default=None, ge=0)
    max_steps: int | None = Field(default=None, ge=1, le=40)
    max_specialists: int | None = Field(default=None, ge=1, le=6)
    redteam_allowed: bool | None = None


def _settings_data(session: Session) -> dict:
    row = engine.settings_row(session)
    return {"monthly_token_cap": row.monthly_token_cap,
            "monthly_cost_cap": row.monthly_cost_cap,
            "max_steps": row.max_steps,
            "max_specialists": row.max_specialists,
            "redteam_allowed": row.redteam_allowed,
            "updated_at": row.updated_at.isoformat() if row.updated_at else None,
            "updated_by": row.updated_by}


@router.get("/settings")
def get_settings(org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    return {"data": _settings_data(session)}


@router.patch("/settings")
def patch_settings(payload: SettingsPatch,
                   org: models.Organization = Depends(auth.require_admin),
                   session: Session = Depends(get_session)):
    row = engine.settings_row(session)
    if payload.monthly_token_cap is not None:
        row.monthly_token_cap = payload.monthly_token_cap
    if payload.monthly_cost_cap is not None:
        row.monthly_cost_cap = payload.monthly_cost_cap
    if payload.max_steps is not None:
        row.max_steps = payload.max_steps
    if payload.max_specialists is not None:
        row.max_specialists = payload.max_specialists
    if payload.redteam_allowed is not None:
        row.redteam_allowed = payload.redteam_allowed
    row.updated_at = models.utcnow()
    row.updated_by = _actor(org)
    session.commit()
    return {"data": _settings_data(session)}


def _latest_usage(session: Session) -> dict:
    """What the provider last reported about cost, verbatim.

    No interpretation: a flat plan's allowance has a shape we have not seen yet, and a
    meter that guesses whether `42` is a percentage or a count is worse than one that
    shows the number the vendor sent.
    """
    row = (session.query(models.AiStep)
           .filter(models.AiStep.usage_json.isnot(None))
           .order_by(models.AiStep.created_at.desc()).first())
    if row is None:
        return {}
    try:
        return json.loads(row.usage_json or "{}")
    except ValueError:
        return {}


@router.get("/spend")
def get_spend(org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    spend = engine.month_spend(session)
    settings = engine.settings_row(session)
    return {"data": {**spend,
                     "token_cap": settings.monthly_token_cap,
                     "cost_cap": settings.monthly_cost_cap,
                     "token_used_pct": _pct(spend["tokens"],
                                            settings.monthly_token_cap),
                     "cost_used_pct": _pct(spend["cost_usd"],
                                           settings.monthly_cost_cap),
                     "provider_usage": _latest_usage(session)}}


def _pct(used, cap) -> float | None:
    if not cap:
        return None
    return round(100.0 * used / cap, 1)


@router.get("/profiles")
def list_profiles(org: models.Organization = Depends(auth.require_org)):
    return {"data": profiles.PROFILES}


# ─────────────────────────── prompts (A8) ───────────────────────────

class PromptIn(BaseModel):
    key: str = Field(min_length=2, max_length=64)
    body: str = Field(min_length=20, max_length=20000)
    notes: str | None = Field(default=None, max_length=2000)


class PromptPatch(BaseModel):
    body: str | None = Field(default=None, min_length=20, max_length=20000)
    notes: str | None = Field(default=None, max_length=2000)


@router.get("/lookup/{ref}")
def lookup_ref(ref: str,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """Which object is this id. A miss is an answer: `kind: None`."""
    from backend.app.ai import lookup as id_lookup
    return {"data": id_lookup.lookup(ref, org=org, session=session)}


@router.get("/prompts")
def list_prompts(org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """Every participant's instructions: the active version, the drafts, the floor.

    Reads are open to the org because "what was it told" is not a secret — writes are
    admin, because a prompt changes what every future answer says.
    """
    return {"data": prompt_registry.describe(session)}


@router.post("/prompts", status_code=status.HTTP_201_CREATED)
def create_prompt(payload: PromptIn,
                  org: models.Organization = Depends(auth.require_admin),
                  session: Session = Depends(get_session)):
    """A new **draft** version. Nothing changes until somebody activates it."""
    if payload.key not in prompt_registry.keys(session):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"unknown prompt key '{payload.key}'; "
                            f"available: {prompt_registry.keys(session)}")
    row = prompt_registry.draft(session, payload.key, payload.body,
                                notes=payload.notes, author=_actor(org))
    _audit_log(session, org.id, _actor(org), "ai.prompt_drafted", "ai_prompt",
               row.id, f"{row.key}@{row.version}")
    session.commit()
    return {"data": prompt_registry.row_data(session, row)}


@router.patch("/prompts/{prompt_id}")
def patch_prompt(prompt_id: str, payload: PromptPatch,
                 org: models.Organization = Depends(auth.require_admin),
                 session: Session = Depends(get_session)):
    """Edit a draft. An active version is history: a change is a new version."""
    row = session.get(models.AiPrompt, prompt_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "prompt not found")
    if row.status != "draft":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{row.key}@{row.version} is {row.status}: an active prompt is history — "
            "draft a new version instead")
    if payload.body is not None:
        row.body = payload.body
    if payload.notes is not None:
        row.notes = payload.notes
    _audit_log(session, org.id, _actor(org), "ai.prompt_edited", "ai_prompt",
               row.id, f"{row.key}@{row.version}")
    session.commit()
    return {"data": prompt_registry.row_data(session, row)}


@router.post("/prompts/{prompt_id}/activate")
def activate_prompt(prompt_id: str,
                    org: models.Organization = Depends(auth.require_admin),
                    session: Session = Depends(get_session)):
    """Promote a version. The previous active one is archived, never deleted."""
    row = session.get(models.AiPrompt, prompt_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "prompt not found")
    if row.status == "active":
        raise HTTPException(status.HTTP_409_CONFLICT, "already active")
    prompt_registry.activate(session, row, actor=_actor(org))
    _audit_log(session, org.id, _actor(org), "ai.prompt_activated", "ai_prompt",
               row.id, f"{row.key}@{row.version}")
    session.commit()
    return {"data": prompt_registry.row_data(session, row)}


# ─────────────────────────── runs ───────────────────────────

class RunIn(BaseModel):
    question: str = Field(min_length=3, max_length=4000)
    profile: str = "palantir"
    mode: str = "ask"


def _run_data(run: models.AiRun, steps: list[models.AiStep] | None = None) -> dict:
    data = {"id": run.id, "actor": run.actor, "role": run.actor_role,
            "question": run.question, "mode": run.mode, "status": run.status,
            "stop_reason": run.stop_reason, "model": run.model,
            "answer": run.answer, "steps": run.steps,
            "tool_calls": run.tool_calls, "tokens_in": run.tokens_in,
            "tokens_out": run.tokens_out, "cost_usd": run.cost_usd,
            "price_known": run.price_known, "error": run.error,
            "started_at": run.started_at.isoformat() if run.started_at else None,
            "finished_at": run.finished_at.isoformat() if run.finished_at else None}
    if steps is not None:
        data["cached_tokens"] = sum(row.cached_tokens or 0 for row in steps)
        data["step_rows"] = [{"seq": row.seq, "role": row.role,
                              "prompt_version": row.prompt_version,
                              "phase": row.phase,
                              "tool_calls": json.loads(row.tool_calls or "[]"),
                              "handoff": json.loads(row.handoff or "null"),
                              "tokens_in": row.tokens_in,
                              "tokens_out": row.tokens_out,
                              "cached_tokens": row.cached_tokens or 0,
                              "usage": json.loads(row.usage_json or "null"),
                              "cost_usd": row.cost_usd,
                              "duration_ms": row.duration_ms}
                             for row in steps]
    return data


@router.post("/runs", status_code=status.HTTP_201_CREATED)
def create_run(payload: RunIn,
               principal: dict = Depends(_principal),
               request_org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """Ask Palantír. The run row is written first, then the loop closes it."""
    _require_analyst(principal)
    profile = profiles.get(payload.profile)
    if profile is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"unknown profile '{payload.profile}'; "
                            f"available: {sorted(profiles.BY_KEY)}")
    if payload.profile != "palantir":
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED,
                            f"profile '{payload.profile}' arrives with F4/F5; F1 "
                            "ships the read-only analyst")
    if payload.mode not in {"ask", "act"}:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "mode must be ask or act")
    if payload.mode == "act":
        raise HTTPException(status.HTTP_501_NOT_IMPLEMENTED,
                            "act mode needs the field agent (F4)")

    provider = engine.default_provider(session)
    actor = str(principal.get("email") or principal.get("user_id")
                or principal["kind"])
    run = models.AiRun(org_id=request_org.id, actor=actor,
                       actor_role=principal["role"], question=payload.question,
                       mode=payload.mode,
                       provider_id=provider.id if provider else None,
                       model=provider.model if provider else None)
    session.add(run)
    session.commit()

    orchestrator.execute(session, run)
    steps = (session.query(models.AiStep).filter_by(run_id=run.id)
             .order_by(models.AiStep.seq).all())
    _audit_log(session, request_org.id, actor, f"ai.run_{run.status}", "ai_run",
               run.id, payload.question[:200])
    session.commit()
    return {"data": _run_data(run, steps)}


@router.get("/runs")
def list_runs(limit: int = Query(default=20, ge=1, le=100),
              offset: int = Query(default=0, ge=0),
              mode: str | None = Query(default=None,
                                       description="ask | mission | compact | eval"),
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    # A run whose process died is closed here, on read: the ledger never shows
    # `running` for something nobody is running.
    engine.sweep_stale_runs(session)
    query = (session.query(models.AiRun)
             .filter_by(org_id=org.id)
             .order_by(models.AiRun.started_at.desc()))
    if mode:
        query = query.filter(models.AiRun.mode == mode)
    total = query.count()
    rows = query.offset(offset).limit(limit).all()
    return {"data": [_run_data(row) for row in rows], "total": total,
            "limit": limit, "offset": offset}


@router.get("/runs/{run_id}")
def get_run(run_id: str, org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    engine.sweep_stale_runs(session)
    run = session.get(models.AiRun, run_id)
    if run is None or run.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    steps = (session.query(models.AiStep).filter_by(run_id=run.id)
             .order_by(models.AiStep.seq).all())
    return {"data": _run_data(run, steps)}


def _actor(org) -> str:
    return f"org:{org.slug}"

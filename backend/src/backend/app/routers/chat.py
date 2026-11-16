"""Chat sessions: ask, read the record, compact (F1, §4c).

The split this router enforces:

* `chat_turns` is the **record** — every message, verbatim, never pruned;
* the **prompt** is assembled per turn (`brief + pins + last K turns`);
* a compaction writes a divider turn, so the seam is visible and the raw turns stay
  readable behind it.

A turn also creates an `ai_run`, so "what did the assistant do to answer this" has a
receipt with steps, tokens and cost — the session answers *what was said*, the run
answers *what was executed*.
"""
from __future__ import annotations

import json
import re
from urllib.parse import urlsplit
from datetime import timedelta

from fastapi import (APIRouter, Depends, HTTPException, Query, Response,
                     status)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models, secrets, shauron_signing
from backend.app.ai import (agents, authz, engine, orchestrator,
                            session as context, profiles)
from backend.app.ai import planner, suggestions as suggestions_ai
from backend.app.db import get_session as db_session
from backend.app.db import session_factory

router = APIRouter(prefix="/api/v1/ai", tags=["chat"])


# ─────────────────────────── payloads ───────────────────────────

class SessionIn(BaseModel):
    title: str = Field(default="", max_length=255)
    profile: str = "palantir"
    subject_kind: str | None = Field(default=None, max_length=32)
    subject_id: str | None = Field(default=None, max_length=64)


class SessionPatch(BaseModel):
    title: str | None = Field(default=None, max_length=255)
    archive: bool | None = None


class TurnIn(BaseModel):
    question: str = Field(min_length=3, max_length=4000)
    #: Run the loop off the request (A4). The turn comes back `pending` with its run id
    #: and the client polls the run; `false` keeps the synchronous contract every test
    #: and every script already relies on.
    background: bool = False


class PinIn(BaseModel):
    turn_id: str | None = None
    note: str | None = Field(default=None, max_length=512)


# ─────────────────────────── serialization ───────────────────────────

def _session_data(session: models.ChatSession, turns: int | None = None,
                  cost: float | None = None) -> dict:
    return {"id": session.id, "title": session.title,
            "profile": session.profile_key, "status": session.status,
            "subject_kind": session.subject_kind,
            "subject_id": session.subject_id,
            "created_by": session.created_by,
            "brief_version": session.brief_version,
            "brief_tokens": session.brief_tokens,
            "has_brief": bool(session.brief),
            "last_turn_at": (session.last_turn_at.isoformat()
                             if session.last_turn_at else None),
            "created_at": session.created_at.isoformat() if session.created_at else None,
            "turns": turns, "cost_usd": cost}


def _turn_data(row: models.ChatTurn) -> dict:
    return {"id": row.id, "seq": row.seq, "role": row.role,
            "author": row.author, "profile": row.profile_key,
            "content": row.content,
            "citations": json.loads(row.citations or "[]"),
            "suggestions": json.loads(getattr(row, "suggestions", None) or "[]"),
            "run_id": row.run_id, "tokens": row.tokens,
            "created_at": row.created_at.isoformat() if row.created_at else None}


def _citations(session_db: Session, run: models.AiRun | None) -> list[str]:
    """The ids this answer actually read — the receipt, on the turn.

    Read from the run's own steps: the refs each tool call returned, plus the
    `evidence_refs` of every claim that survived validation. An INVALID claim is
    excluded on purpose: it cites what no tool returned, which is the definition of
    something that must not appear as evidence.
    """
    if run is None:
        return []
    refs: list[str] = []

    def add(value) -> None:
        text = str(value or "").strip()
        if text and text not in refs:
            refs.append(text)

    for step in (session_db.query(models.AiStep).filter_by(run_id=run.id)
                 .order_by(models.AiStep.seq).all()):
        try:
            calls = json.loads(step.tool_calls or "[]")
        except ValueError:
            calls = []
        for call in calls if isinstance(calls, list) else []:
            if not isinstance(call, dict):
                continue
            for ref in call.get("refs") or []:
                add(ref)
        try:
            handoff = json.loads(step.handoff or "null")
        except ValueError:
            handoff = None
        if isinstance(handoff, dict):
            for claim in handoff.get("claims") or []:
                if not isinstance(claim, dict) or claim.get("invalid"):
                    continue
                for ref in claim.get("evidence_refs") or []:
                    add(ref)
    return refs[:40]


MENTION_RE = re.compile(r"^\s*@([^\s,;:]+)\s*[,:]?\s*", re.UNICODE)


def _split_mention(text: str) -> tuple[str, str | None]:
    """`@palantir does X` → (`does X`, `palantir`). No mention → (`text`, None).

    The mention is stripped from the question so the profile is not asked to talk
    about its own name, and it never reaches the model as prose it could ignore.
    """
    match = MENTION_RE.match(text or "")
    if not match:
        return (text or "").strip(), None
    rest = (text or "")[match.end():].strip()
    return (rest or (text or "").strip()), match.group(1)


def _get(session_db: Session, org: models.Organization,
         session_id: str) -> models.ChatSession:
    row = session_db.get(models.ChatSession, session_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found")
    return row


# ─────────────────────────── sessions ───────────────────────────

@router.post("/sessions", status_code=status.HTTP_201_CREATED)
def create_session(payload: SessionIn,
                   principal: dict = Depends(authz.principal),
                   org: models.Organization = Depends(auth.require_org),
                   session_db: Session = Depends(db_session)):
    authz.require_analyst(principal)
    if profiles.get(payload.profile) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"unknown profile '{payload.profile}'")
    row = models.ChatSession(org_id=org.id, created_by=authz.actor_of(principal),
                             title=payload.title.strip(),
                             profile_key=payload.profile,
                             subject_kind=payload.subject_kind,
                             subject_id=payload.subject_id)
    session_db.add(row)
    session_db.commit()
    return {"data": _session_data(row, turns=0, cost=0.0)}


@router.get("/sessions")
def list_sessions(limit: int = Query(default=20, ge=1, le=100),
                  offset: int = Query(default=0, ge=0),
                  include_archived: bool = Query(default=False),
                  org: models.Organization = Depends(auth.require_org),
                  session_db: Session = Depends(db_session)):
    query = session_db.query(models.ChatSession).filter_by(org_id=org.id)
    if not include_archived:
        query = query.filter(models.ChatSession.archived_at.is_(None))
    query = query.order_by(models.ChatSession.last_turn_at.desc().nullslast(),
                           models.ChatSession.created_at.desc())
    total = query.count()
    rows = query.offset(offset).limit(limit).all()
    out = []
    for row in rows:
        turns = (session_db.query(models.ChatTurn)
                 .filter_by(session_id=row.id).count())
        cost = _session_cost(session_db, row)
        out.append(_session_data(row, turns=turns, cost=cost))
    return {"data": out, "total": total, "limit": limit, "offset": offset}


def _session_cost(session_db: Session, session: models.ChatSession) -> float | None:
    run_ids = [row.run_id for row in session_db.query(models.ChatTurn)
               .filter_by(session_id=session.id).all() if row.run_id]
    if not run_ids:
        return 0.0
    runs = (session_db.query(models.AiRun)
            .filter(models.AiRun.id.in_(run_ids)).all())
    if any(run.cost_usd is None for run in runs):
        return None
    return round(sum(run.cost_usd or 0.0 for run in runs), 6)


@router.get("/sessions/{session_id}")
def get_session(session_id: str,
                include_brief: bool = Query(default=True),
                org: models.Organization = Depends(auth.require_org),
                session_db: Session = Depends(db_session)):
    row = _get(session_db, org, session_id)
    turns = (session_db.query(models.ChatTurn)
             .filter_by(session_id=row.id).order_by(models.ChatTurn.seq).all())
    pins = (session_db.query(models.ChatPin)
            .filter_by(session_id=row.id).order_by(models.ChatPin.created_at).all())
    data = _session_data(row, turns=len(turns), cost=_session_cost(session_db, row))
    data["turn_rows"] = [_turn_data(turn) for turn in turns]
    data["pins"] = [{"id": pin.id, "turn_id": pin.turn_id, "note": pin.note}
                    for pin in pins]
    if include_brief:
        data["brief"] = row.brief
    return {"data": data}


@router.patch("/sessions/{session_id}")
def patch_session(session_id: str, payload: SessionPatch,
                  principal: dict = Depends(authz.principal),
                  org: models.Organization = Depends(auth.require_org),
                  session_db: Session = Depends(db_session)):
    authz.require_analyst(principal)
    row = _get(session_db, org, session_id)
    if payload.title is not None:
        row.title = payload.title.strip()
    if payload.archive:
        row.archived_at = models.utcnow()
        row.status = "archived"
    elif payload.archive is False:
        row.archived_at = None
        row.status = "idle"
    row.updated_at = models.utcnow()
    session_db.commit()
    return {"data": _session_data(row)}


# ─────────────────────────── turns ───────────────────────────

def _run_brief(run: models.AiRun) -> dict:
    return {"id": run.id, "status": run.status, "stop_reason": run.stop_reason,
            "tokens_in": run.tokens_in, "tokens_out": run.tokens_out,
            "cost_usd": run.cost_usd, "price_known": run.price_known,
            "steps": run.steps, "tool_calls": run.tool_calls}


def _write_turn(session_db: Session, row: models.ChatSession,
                run: models.AiRun | None, *, answer: str, actor: str,
                profile_key: str, assistant_role: str,
                extra_citations: list[str] | None = None,
                suggestions: list[dict] | None = None) -> models.ChatTurn:
    """The assistant turn, with the receipt. One writer, used by both paths."""
    turn = models.ChatTurn(
        org_id=row.org_id, session_id=row.id,
        seq=context.next_seq(session_db, row), role=assistant_role, author=actor,
        profile_key=profile_key, content=answer,
        # The receipt of a proposal is the mission it created: without its id the
        # answer cannot be followed anywhere.
        citations=json.dumps((extra_citations or []) + _citations(session_db, run)),
        suggestions=json.dumps(suggestions or []),
        run_id=run.id if run is not None else None,
        tokens=((run.tokens_in or 0) + (run.tokens_out or 0)) if run else 0)
    session_db.add(turn)
    row.status = ("idle" if run is None or run.status == "answered" else "needs_you")
    session_db.commit()
    return turn


def _finish_turn(session_db: Session, row: models.ChatSession, run: models.AiRun,
                 provider, messages: list[dict], *, actor: str, profile_key: str,
                 assistant_role: str, answer_prefix: str,
                 agent: dict | None = None, org: models.Organization | None = None):
    """Run the loop (or explain why it cannot) and write the answer. Shared by the
    synchronous turn and the background one: two implementations of this is how a
    receipt ends up on one path and not the other."""
    buttons: list[dict] = []
    if org is None:      # the background path passes no org; the row knows it
        org = session_db.get(models.Organization, row.org_id)
    if provider is None:
        run.status = "stopped_no_provider"
        run.error = "configure a provider in Settings → AI"
        run.finished_at = models.utcnow()
        session_db.commit()
        answer = answer_prefix + "No provider configured. Settings → AI."
    else:
        orchestrator.execute(session_db, run, context=messages, agent=agent)
        # The buttons are what the answer *offers*; they are validated against the
        # estate here, so the screen never renders an affordance the platform cannot
        # honour. `org` is None only on the background path, which carries none.
        text, buttons = suggestions_ai.extract(session_db, org, run.answer or "")
        run.answer = text or run.answer
        answer = answer_prefix + (text
                                  or (run.error or f"the run ended as {run.status}"))
    assistant = _write_turn(session_db, row, run, answer=answer, actor=actor,
                            profile_key=profile_key,
                            assistant_role=assistant_role,
                            suggestions=buttons)
    compaction = None
    if provider is not None and context.needs_compaction(session_db, row, messages):
        compaction = _compact(session_db, row, provider)
    return assistant, compaction


def _spawn_turn(session_db: Session, session_id: str, run_id: str,
                messages: list[dict], *, actor: str, profile_key: str,
                assistant_role: str, answer_prefix: str) -> None:
    """Continue the turn in another thread, with its own session.

    `Session` is not thread-safe and FastAPI's request session closes when the response
    is sent, so the worker opens its own — the same idiom the clock and the background
    runs already use. The thread is a daemon: a deploy that kills the process leaves a
    run that reads `running`, which is honest, and `GET /ai/runs/{id}` is what the
    operator polls either way.
    """
    import threading

    def work() -> None:
        own = session_factory()()
        try:
            row = own.get(models.ChatSession, session_id)
            run = own.get(models.AiRun, run_id)
            if row is None or run is None:
                return
            provider = engine.default_provider(own)
            _finish_turn(own, row, run, provider, messages, actor=actor,
                         profile_key=profile_key, assistant_role=assistant_role,
                         answer_prefix=answer_prefix)
        except Exception as error:      # a broken thread must leave a closed run
            own.rollback()
            run = own.get(models.AiRun, run_id)
            if run is not None:
                run.status = "failed"
                run.error = str(error)[:500]
                run.finished_at = models.utcnow()
                own.commit()
        finally:
            own.close()

    threading.Thread(target=work, name=f"ai-turn-{run_id[:8]}", daemon=True).start()


@router.post("/sessions/{session_id}/turns", status_code=status.HTTP_201_CREATED)
def create_turn(session_id: str, payload: TurnIn, response: Response,
                principal: dict = Depends(authz.principal),
                org: models.Organization = Depends(auth.require_org),
                session_db: Session = Depends(db_session)):
    """One question: record it, assemble the context, run Palantír, record the answer."""
    authz.require_analyst(principal)
    row = _get(session_db, org, session_id)
    if row.archived_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "session is archived")

    actor = authz.actor_of(principal)
    question, mention = _split_mention(payload.question)
    user_turn = models.ChatTurn(
        org_id=org.id, session_id=row.id,
        seq=context.next_seq(session_db, row), role="user", author=actor,
        content=(payload.question.strip() if not question else question),
        citations="[]")
    session_db.add(user_turn)
    row.last_turn_at = models.utcnow()
    row.status = "running"
    if not row.title:
        row.title = user_turn.content[:120]
    session_db.commit()

    # D71: an explicit `@name` addresses that profile. Only Palantír exists today;
    # the other two answer with their phase instead of pretending to run.
    assistant_role = "orchestrator"
    profile_key = row.profile_key
    answer_prefix = ""
    unavailable = None
    proposal = None
    agent = None
    refusal = None
    if mention:
        key = mention.lower()
        if key in {"palantir", "palantír"}:
            assistant_role, profile_key = "specialist", "palantir"
        elif profiles.get(key) is not None:
            # A field profile addressed in the conversation proposes a mission: the
            # chat still never executes, but it stops being a dead end.
            capability = "validate" if key == "angmar" else "discover"
            profile_key = key
            unavailable = (profiles.get(key)["name"], capability)
            proposal = propose_mission(session_db, org, row, actor=actor,
                                       capability=capability, question=user_turn.content)
        else:
            # A catalogue agent is addressed by its slug. Until now the console listed
            # four cards and every mention fell into the branch below: a declared agent
            # that nothing could run is a card, not an agent.
            spec = (session_db.query(models.AgentSpec)
                    .filter_by(slug=key, status="active").one_or_none())
            if spec is not None:
                candidate = agents.as_specialist(spec)
                if candidate["tools"]:
                    agent = candidate
                    profile_key = spec.slug
                    assistant_role = "specialist"
                else:
                    # Terminal on purpose: a spec with no tools would fall through to a
                    # generic Palantír run that answers about an estate the agent was
                    # never allowed to read. That is a paragraph, not an agent.
                    refusal = (
                        f"«{spec.name}» existe pero no puede correr: no declara "
                        "herramientas, y un agente que sólo escribe prosa sobre un "
                        "parque que no puede leer es una respuesta inventada con buena "
                        "redacción. Dale tools en la ficha del agente y vuelve a "
                        "nombrarlo.")
                    assistant_role = "orchestrator"
            else:
                answer_prefix = (f"No specialist is called «{mention}». Available today: "
                                 f"Palantír (read-only analyst).\n\n")
                assistant_role = "orchestrator"
    elif ACTIVE_VERB_RE.search(user_turn.content) and (
            TARGET_RE.search(user_turn.content)
            or FINDING_ID_RE.search(user_turn.content)):
        # No mention, but the sentence asks for an action against a host. Answering it in
        # read-only mode is correct and useless: the operator would have to retype the
        # same sentence with a name in front. The verb is the intent, the host is the
        # envelope, and the proposal still stops at the human gate.
        proposal = propose_mission(session_db, org, row, actor=actor,
                                   capability="validate", question=user_turn.content)
        unavailable = ("campo", "validate")
        assistant_role = "orchestrator"
        answer_prefix = ("No nombraste un agente, pero pediste una acción contra un "
                         "host: lo tomé como validación.\n\n")

    command = _room_command(session_db, user_turn.content)
    if command is not None:
        specs, room_question = command
        provider = engine.default_provider(session_db)
        if len(specs) < 2:
            named = ", ".join(f"`{spec['slug']}`" for spec in specs) or "ninguno"
            answer = (f"Una sala necesita al menos dos agentes activos con herramientas; "
                      f"reconocí {named}. Nombralos así: `/sala @estate.analyst "
                      f"@change.impact ¿pregunta?`")
            assistant = _write_turn(session_db, row, None, answer=answer, actor=actor,
                                    profile_key=profile_key,
                                    assistant_role="orchestrator")
            session_db.commit()
            row.status = "idle"
            return {"data": {"turn": _turn_data(assistant),
                             "session": _session_data(
                                 row,
                                 turns=session_db.query(models.ChatTurn)
                                 .filter_by(session_id=row.id).count(),
                                 cost=_session_cost(session_db, row)),
                             "run": None, "compaction": None}}
        last = _run_room(session_db, row, provider, actor=actor,
                         agents_in_room=specs, question=room_question)
        if last is None:
            raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                                "the room produced no turn")
        last_run = session_db.get(models.AiRun, last.run_id) if last.run_id else None
        if last_run is not None:
            response.headers["X-Run-Id"] = last_run.id
        return {"data": {"turn": _turn_data(last),
                         "session": _session_data(
                             row,
                             turns=session_db.query(models.ChatTurn)
                             .filter_by(session_id=row.id).count(),
                             cost=_session_cost(session_db, row)),
                         "run": None if last_run is None else {
                             "id": last_run.id, "status": last_run.status,
                             "stop_reason": last_run.stop_reason,
                             "tokens_in": last_run.tokens_in,
                             "tokens_out": last_run.tokens_out,
                             "cost_usd": last_run.cost_usd,
                             "price_known": last_run.price_known,
                             "steps": last_run.steps,
                             "tool_calls": last_run.tool_calls},
                         "compaction": None}}

    messages = context.assemble(session_db, row, question=user_turn.content)
    provider = engine.default_provider(session_db)
    run = None

    if refusal is not None:
        # Written on the same path as a proposal: no run, a turn, the same payload.
        assistant = _write_turn(session_db, row, None, answer=answer_prefix + refusal,
                                actor=actor, profile_key=profile_key,
                                assistant_role=assistant_role)
        session_db.commit()
        row.status = "idle"
        return {"data": {"turn": _turn_data(assistant),
                         "session": _session_data(
                             row,
                             turns=session_db.query(models.ChatTurn)
                             .filter_by(session_id=row.id).count(),
                             cost=_session_cost(session_db, row)),
                         "run": None, "compaction": None}}
    elif unavailable is not None:
        name, capability = unavailable
        answer = answer_prefix + _proposal_answer(proposal or {}, capability)
        # The receipt of a proposal is the mission it created and the finding it
        # named: without those ids the answer cannot be followed anywhere.
        created = (proposal or {}).get("mission") or {}
        extra = [ref for ref in (created.get("id"),
                                 ((proposal or {}).get("ids") or {}).get("finding"))
                 if ref]
        assistant = _write_turn(
            session_db, row, run, answer=answer, actor=actor,
            profile_key=profile_key, assistant_role=assistant_role,
            extra_citations=extra)
        session_db.commit()
        compaction = None
    else:
        run = models.AiRun(org_id=org.id, actor=actor, actor_role=principal["role"],
                           session_id=row.id,
                           question=user_turn.content, mode="ask",
                           provider_id=provider.id if provider else None,
                           model=provider.model if provider else None)
        session_db.add(run)
        session_db.commit()

        if payload.background and provider is not None:
            # A chain of five specialists is minutes, and a request that holds the
            # socket for minutes is a 504 waiting for a proxy timeout. The run row is
            # already written `running`; the loop continues in its own session and the
            # client polls `GET /ai/runs/{id}` for the receipt.
            _spawn_turn(session_db, row.id, run.id, messages, actor=actor,
                        profile_key=profile_key, assistant_role=assistant_role,
                        answer_prefix=answer_prefix)
            return JSONResponse(status_code=202, content={
                "data": {"pending": True,
                         "turn": _turn_data(user_turn),
                         "run": _run_brief(run),
                         "session": _session_data(row)}})

        assistant, compaction = _finish_turn(
            session_db, row, run, provider, messages, actor=actor, agent=agent, org=org,
            profile_key=profile_key, assistant_role=assistant_role,
            answer_prefix=answer_prefix)

    # The run id is what a support answer needs ("which run cost that?") and what the
    # client polls; sending it costs one header.
    if run is not None:
        response.headers["X-Run-Id"] = run.id

    return {"data": {"turn": _turn_data(assistant),
                     "session": _session_data(
                         row,
                         turns=session_db.query(models.ChatTurn)
                         .filter_by(session_id=row.id).count(),
                         cost=_session_cost(session_db, row)),
                     "run": None if run is None else {
                         "id": run.id, "status": run.status,
                         "stop_reason": run.stop_reason,
                         "tokens_in": run.tokens_in,
                         "tokens_out": run.tokens_out,
                         "cost_usd": run.cost_usd,
                         "price_known": run.price_known,
                         "steps": run.steps,
                         "tool_calls": run.tool_calls},
                     "compaction": compaction}}


@router.post("/sessions/{session_id}/compact")
def compact_session(session_id: str,
                    principal: dict = Depends(authz.principal),
                    org: models.Organization = Depends(auth.require_org),
                    session_db: Session = Depends(db_session)):
    authz.require_analyst(principal)
    row = _get(session_db, org, session_id)
    provider = engine.default_provider(session_db)
    if provider is None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "configure a provider in Settings → AI")
    result = _compact(session_db, row, provider)
    return {"data": {**result, "session": _session_data(row)}}


def _compact(session_db: Session, row: models.ChatSession, provider) -> dict:
    try:
        key = (secrets.open_sealed(session_db, provider.secret_cipher)
               if provider.secret_cipher else "")
    except Exception as error:
        return {"compacted": False, "reason": f"provider key unusable: {error}"}
    return context.compact(session_db, row, provider=provider, api_key=key)



# ──────────────────────────── a room of agents ────────────────────────────
#
# A chat turn answers with one voice. A room answers with several: the agents take
# turns, each sees what the ones before it said, and can bring a peer back in by
# mentioning it. Nobody schedules anything — the room is a queue, and it goes quiet when
# a turn brings nobody back, which is what "the room calms down by itself" means when
# it is not a metaphor.
#
# What it deliberately is not: free chat. Every turn is one `AiRun` with one agent's
# tools and ceilings, the transcript enters the prompt as data, and the whole room stops
# on a turn ceiling — six voices is a room, forty is a bill.

ROOM_TURN_CEILING = 6
ROOM_TURNS_PER_AGENT = 2
#: Mentions *inside* prose, unlike `MENTION_RE` which only reads the leading one.
ROOM_MENTION_RE = re.compile(r"@([a-z0-9][a-z0-9._-]{1,62})", re.IGNORECASE)


def _room_command(session_db: Session, question: str) -> tuple[list[dict], str] | None:
    """`/sala @a @b <pregunta>` → the agents addressed and the question itself.

    The command is parsed here rather than in the UI so a room works from the composer,
    from a script and from a mission all at once — and so an agent named in the command
    is the same agent `@slug` addresses anywhere else.
    """
    stripped = question.lstrip()
    if not stripped.lower().startswith(("/sala", "/room")):
        return None
    body = stripped[5:].strip()
    slugs: list[str] = []
    for match in ROOM_MENTION_RE.finditer(body):
        slug = match.group(1).lower()
        if slug not in slugs:
            slugs.append(slug)
    body = ROOM_MENTION_RE.sub("", body).strip() or question
    specs = []
    for slug in slugs[:ROOM_TURN_CEILING]:
        row = (session_db.query(models.AgentSpec)
               .filter_by(slug=slug, status="active").one_or_none())
        if row is not None:
            candidate = agents.as_specialist(row)
            if candidate["tools"]:
                specs.append(candidate)
    return specs, body


def _run_room(session_db: Session, row: models.ChatSession, provider, *,
              actor: str, agents_in_room: list[dict], question: str) -> models.ChatTurn | None:
    """Take turns until nobody brings a peer back. Returns the last turn written.

    Each agent answers once before anyone repeats (`ROOM_TURNS_PER_AGENT`), and a turn
    that mentions a peer puts that peer at the back of the queue. The transcript is a
    list of `slug: said`, passed as context — never as instructions.
    """
    seen: dict[str, int] = {}
    queue = list(agents_in_room)
    said: list[str] = []
    last: models.ChatTurn | None = None
    turns = 0
    while queue and turns < ROOM_TURN_CEILING:
        spec = queue.pop(0)
        slug = spec["slug"]
        if seen.get(slug, 0) >= ROOM_TURNS_PER_AGENT:
            continue
        seen[slug] = seen.get(slug, 0) + 1
        transcript = "\n\n".join(
            [f"Operador: {question}"] +
            [f"{author}: {text}" for author, text in said]) or f"Operador: {question}"
        run = models.AiRun(org_id=row.org_id, actor=actor, actor_role="analyst",
                           session_id=row.id, question=question, mode="ask",
                           provider_id=provider.id if provider else None,
                           model=provider.model if provider else None)
        session_db.add(run)
        session_db.commit()
        try:
            orchestrator.execute(session_db, run,
                                 context=[{"role": "user", "content": transcript}],
                                 agent=spec)
        except Exception as error:  # one voice failing must not silence the room
            run.status, run.error = "failed", str(error)[:200]
            session_db.commit()
        answer = (run.answer or run.error or f"the run ended as {run.status}").strip()
        last = _write_turn(session_db, row, run, answer=answer, actor=actor,
                           profile_key=slug, assistant_role="specialist")
        session_db.commit()
        said.append((slug, answer))
        turns += 1
        # A mention of a peer is the only thing that brings another voice back: the
        # room ends by lack of questions, not by a counter running out.
        for match in ROOM_MENTION_RE.finditer(answer):
            peer_slug = match.group(1).lower()
            if peer_slug == slug or seen.get(peer_slug, 0) >= ROOM_TURNS_PER_AGENT:
                continue
            peer = next((a for a in agents_in_room if a["slug"] == peer_slug), None)
            if peer is not None and peer not in queue:
                queue.append(peer)
    return last


# ──────────────────────────── a room of agents ────────────────────────────

# ─────────────────── from a question to a bounded mission ───────────────────
#
# The chat does not execute (invariant 12). But a read-only answer that ends in
# `unknown` used to be a dead end: the operator had to leave the conversation, remember
# the finding id, and re-type the envelope in Missions. This turns that dead end into a
# proposal — a mission in `awaiting_approval`, with the targets the estate already
# knows, and the reason it cannot run yet when it cannot.

FINDING_ID_RE = re.compile(r"\b[0-9a-f]{32}\b")
#: A host or URL the operator typed in the conversation. A lab target has no finding and
#: no asset yet; refusing to act until somebody files one is how "validá esto" became a
#: dead end. The declared value is recorded so widening scope is legible.
#: An operator who says "probá esto contra <host>" is asking for execution, not for a
#: briefing. Palantír answered that request with a correct refusal — it is read-only by
#: design — and the conversation stopped there. The verb is the intent; the host is the
#: envelope. Both present means: propose the mission, and say that is what happened.
ACTIVE_VERB_RE = re.compile(
    r"\b(prob[aá]|probar|probalo|valid[aá]|validar|ejecut[aá]|ejecutar|reproduc[ií]|"
    r"reproducir|explot[aá]|explotar|dispar[aá]|corr[eé]|correr|lanza|chequear\s+en\s+vivo)\b",
    re.IGNORECASE)

TARGET_RE = re.compile(r"\b(?:https?://[^\s,;]+|(?:[a-z0-9-]+\.)+[a-z]{2,}(?::\d+)?)\b",
                       re.IGNORECASE)
FIELD_TOOLS = ["curl", "python"]


def _finding_target(session_db: Session, finding: models.Finding) -> tuple[str | None, str]:
    """The host a validation would talk to, and where the value came from.

    `finding.url` is **not** a candidate: on a scanner finding it is the advisory's own
    link — a real case resolved to `https://nvd.nist.gov` and the scope check refused a
    host we never meant to touch. A target comes from the estate: the asset the finding
    is attached to, or the endpoint that was actually recorded. When neither exists, the
    honest answer is "we do not know where this runs", which is also what a null
    `last_checked_at` on the deployment is saying.
    """
    if finding.asset_id:
        asset = session_db.get(models.Asset, finding.asset_id)
        if asset is not None and asset.value:
            return str(asset.value).strip(), "asset.value"
    # A finding's `url` is two different things: on a scanner row it is a link to the
    # advisory (`nvd.nist.gov`), on a field row it is the exact endpoint that was
    # exploited. The origin is not the discriminator — the inventory is: if the url's
    # host is an asset this estate owns, it is a target. If it is not, it is a link.
    if finding.url and str(finding.url).strip():
        candidate = str(finding.url).strip()
        parsed = urlsplit(candidate if "//" in candidate else f"https://{candidate}")
        if parsed.netloc:
            known = (session_db.query(models.Asset)
                     .filter_by(org_id=finding.org_id)
                     .filter(models.Asset.value.in_([
                         f"{parsed.scheme}://{parsed.netloc}",
                         f"http://{parsed.netloc}", f"https://{parsed.netloc}",
                         parsed.netloc]))
                     .first())
            if known is not None:
                return candidate, "finding.url→asset"
    if finding.endpoint and str(finding.endpoint).strip():
        # An endpoint is often a *path* (`/rest/user/login`), not an origin. Taking it as
        # one produced `https:///rest/user/login` — a target with no host, refused by the
        # scope check with a message that read like a policy problem instead of a
        # malformed value.
        candidate = str(finding.endpoint).strip()
        parsed = urlsplit(candidate if "//" in candidate else f"https://{candidate}")
        if parsed.netloc:
            return candidate, "finding.endpoint"
    return None, "none"


def propose_mission(session_db: Session, org: models.Organization, thread,
                    *, actor: str, capability: str, question: str) -> dict:
    """A mission proposal from a conversation. Never executed: `awaiting_approval`.

    Returns `{"mission": {...}}` when the envelope was written, or
    `{"blocked": reason, "needs": "finding"|"target"|"grant", "ids": {...}}` when it was
    not — and the difference is the whole point: scope is a grant, not a sentence the
    operator can talk themselves into.
    """
    from backend.app.routers import agent as agent_router

    candidates = FINDING_ID_RE.findall(question or "")
    finding = None
    for candidate in candidates:
        row = session_db.get(models.Finding, candidate)
        if row is not None and row.org_id == org.id:
            finding = row
            break

    # A declared target: the operator named a host in the conversation. This is how a
    # lab scenario gets validated without pretending a finding exists.
    declared = None
    for candidate in TARGET_RE.findall(question or ""):
        if FINDING_ID_RE.fullmatch(candidate):
            continue
        if session_db.get(models.Finding, candidate) is not None:
            continue
        declared = candidate.rstrip(".,;)")
        break

    if finding is None and declared is None:
        return {"blocked": "no finding id in the question", "needs": "finding",
                "ids": {"candidates": candidates}}

    if finding is not None:
        value, source = _finding_target(session_db, finding)
        ids = {"finding": finding.id, "asset": finding.asset_id,
               "component": finding.component_id}
        if not value and declared is None:
            return {"blocked": ("this finding is not attached to an asset or an "
                                "endpoint, so nothing in the estate says which host it "
                                "runs on"),
                    "needs": "target", "ids": ids, "advisory_url": finding.url}
        if not value:
            value, source = declared, "chat.declared"
    else:
        value, source = declared, "chat.declared"
        ids = {"finding": None, "asset": None, "component": None}

    # Same normalisation the mission API applies: the envelope names the origin.
    target_value = value
    if "//" not in target_value:
        target_value = f"https://{target_value}"
    parts = urlsplit(target_value)
    origin = f"{parts.scheme}://{parts.netloc}" if parts.netloc else target_value

    if not urlsplit(origin).netloc:
        return {"blocked": (f"the target for this finding is not an address: "
                            f"`{value}`"), "needs": "target", "ids": ids}
    decision = agent_router._scope_decision(session_db, org, "url", origin, capability)
    if not decision.allowed:
        return {"blocked": decision.reason or "outside the effective scope",
                "needs": "grant", "ids": {**ids, "target": origin},
                "target": origin, "source": source, "capability": capability,
                "matched": getattr(decision, "matched_rule", None)}

    # The plan, before the mission: a goal is not a plan, and approving one without the
    # other is how the operator approves a sentence and the agent improvises.
    plan_row, plan_prose = planner.plan(
        session_db, org, actor=actor,
        question=(f"Plan for finding {finding.id}: {finding.title}. Target: {origin}."
                  if finding is not None else f"Plan for {origin}: {question.strip()}"))
    if plan_row is None:
        # Fail closed: a mission without a plan is a sentence the worker improvises on.
        # The planner's own prose is the reason, and it is worth more than a template.
        return {"blocked": "el planner no produjo un plan ejecutable",
                "needs": "plan", "ids": {"finding": finding.id if finding is not None
                                         else None, "target": origin},
                "prose": (plan_prose or "").strip()[:1200]}

    profile = agent_router.PROFILE_FOR.get(capability, "angmar")
    now = models.utcnow()
    mission = models.AgentMission(
        org_id=org.id, actor=actor, actor_role="analyst",
        goal=(((plan_row or {}).get("hypothesis") or "").strip()
              or (f"validate {finding.title[:150]} on {origin}" if finding is not None
                  else f"prove or disprove, on {origin}: "
                       f"{question.strip()[:400]}"))[:2000],
        capability=capability, profile=profile,
        # A proposal is not an authorization: the human gate is the point.
        status="awaiting_approval",
        targets=json.dumps([{"kind": "url", "value": origin, "declared": value,
                             "source": source, "methods": ["GET", "POST"],
                             "rate_per_min": 20}]),
        tools=json.dumps(FIELD_TOOLS),
        budget=json.dumps({"steps": 8, "tokens": 20000, "wall_s": 600, "usd": 0.0}),
        evidence=json.dumps({"required": ["request", "response", "verdict"],
                             "finding_id": finding.id if finding is not None else None,
                             "task_kind": ("exploit.chain"
                                           if (plan_row or {}).get("safety") == "active"
                                           or finding is None else "validate.finding"),
                             "declared_target": declared,
                             "plan": plan_row,
                             "proposed_from": "chat"}),
        deadline_at=now + timedelta(minutes=30))
    session_db.add(mission)
    session_db.flush()
    # The mission's ledger row belongs to this thread: the field agent then speaks in
    # the conversation it was proposed from (A6).
    agent_router._mission_run(session_db, mission, thread.id)
    # "Si le estoy mandando algo ya le doy permisos": a target the operator typed into the
    # conversation, covered by an active grant, does not wait for a second yes. The gate
    # stays for what the estate did not authorise — there it asks, inline.
    auto = source == "chat.declared" and decision.allowed
    if auto:
        mission.status = "approved"
        mission.approved_by = f"chat:{actor}"
        mission.approved_at = now
        session_db.flush()
        agent_router._first_task(session_db, mission)

    signed = shauron_signing.sign_ticket(session_db, {
        "schema": "barad-mission-v1", "mission_id": mission.id, "org_id": org.id,
        "origin": "chat-proposal", "profile": mission.profile,
        "goal": mission.goal, "capability": mission.capability,
        "targets": json.loads(mission.targets), "tools": json.loads(mission.tools),
        "grant_id": None, "budget": json.loads(mission.budget),
        "deadline_at": mission.deadline_at.isoformat()})
    mission.signature = signed[shauron_signing.SIGNATURE_FIELD]
    return {"mission": agent_router._mission_data(mission, tasks=0),
            "target": origin, "declared": value, "source": source, "ids": ids,
            "plan": plan_row, "auto": auto}


def _proposal_answer(result: dict, capability: str) -> str:
    """What the operator reads. It names the next action, never the outcome."""
    if "mission" in result:
        mission = result["mission"]
        if result.get("auto"):
            return (
                "**La misión está aprobada y la tarea en cola** — la pediste vos contra ese "
                "host y el parque lo tiene autorizado, así que no te la devuelvo para un "
                "segundo sí.\n\n"
                f"- misión `{mission['id'][:12]}…` · capability `{capability}` · "
                f"perfil `{mission['profile']}`\n"
                f"- target: {result['target']} (desde {result['source']})\n"
                f"- prueba exigida: "
                f"{', '.join((mission['evidence'] or {}).get('required') or [])}\n"
                + (f"\n{planner.describe(result['plan'])}\n\n" if result.get("plan") else "")
                + "El worker la levanta en segundos y devuelve request/response/veredicto.")
        return (
            "Armé la misión y está esperando tu aprobación — no ejecuta nada hasta que "
            "la apruebes.\n\n"
            f"- misión `{mission['id'][:12]}…` · capability `{capability}` · "
            f"perfil `{mission['profile']}`\n"
            f"- target: {result['target']} (desde {result['source']})\n"
            f"- herramientas: {', '.join(mission['tools'])} · tope: "
            f"{(mission['budget'] or {}).get('steps')} pasos / "
            f"{(mission['budget'] or {}).get('tokens')} tokens / 30 min\n"
            f"- prueba exigida: {', '.join((mission['evidence'] or {}).get('required') or [])}\n"
            + (f"- hallazgo: `{(mission['evidence'] or {}).get('finding_id')}`\n\n"
               if (mission['evidence'] or {}).get("finding_id")
               else "- sin hallazgo: es un target declarado en este chat\n\n")
            + (f"\n{planner.describe(result['plan'])}\n\n" if result.get("plan") else "")
            + f"Aprobala en Missions (`#missions::{mission['id']}`) y el agente de campo "
            "corre ahí con su envelope firmado: lee qué está realmente desplegado, prueba "
            "la hipótesis y devuelve request/response. Eso entra como candidato y pasa "
            "los gates antes de tocar el hallazgo — el veredicto del modelo no lo "
            "reemplaza.")
    needs = result.get("needs")
    ids = ", ".join(f"{key} `{value}`" for key, value in (result.get("ids") or {}).items()
                    if value)
    if needs == "plan":
        prose = (result.get("prose") or "").strip()
        return (
            "**No armé la misión**, y es a propósito: el planner leyó el hallazgo y no "
            "produjo un plan ejecutable. Una misión sin plan es una frase que el agente "
            "de campo improvisa, y eso no es una validación.\n\n"
            + (f"Lo que concluyó:\n\n> {prose}\n\n" if prose else "")
            + "Con eso en la mano se decide mejor: o falta un dato (versión, asset, "
              "target), o la técnica no está documentada y hay que investigarla antes.")
    if needs == "finding":
        return ("Para armar una misión necesito el **id del hallazgo** (32 caracteres "
                "hex). Sin él no sé qué se va a probar ni contra qué host.")
    if needs == "target":
        advisory = result.get("advisory_url")
        return (
            f"No puedo armarla: {result.get('blocked')}.\n\n"
            + (f"(El `url` del hallazgo es la referencia del advisory —{advisory}—, no "
               "un host del parque: probar contra ahí no diría nada.)\n\n" if advisory
               else "")
            + "Lo que falta es el vínculo que hoy nadie tiene: qué asset corre esto "
            "realmente — el mismo hueco que un deployment con `last_checked_at: null` "
            f"está gritando. Ids: {ids}. Cuando el hallazgo apunte a un asset, la "
            "misión se arma sola.")
    return (
        "No puedo armarla todavía, y el motivo es concreto: "
        f"**{result.get('blocked')}**.\n\n"
        f"- target: {result.get('target')}\n"
        f"- capacidad: `{capability}` (scope `active_verification`)\n"
        f"- ids: {ids}\n\n"
        "Ese host no está cubierto por ningún grant activo, y una misión sin grant no se "
        "crea — es la regla, no un paso burocrático. Pedí el grant desde el asset y "
        "volvé a pedirme la misión: se arma sola.")


# ─────────────────── from a question to a bounded mission ───────────────────

# ─────────────────────────── the channel (A6) ───────────────────────────

def _iso(value) -> str:
    return value.isoformat() if value else ""


@router.get("/sessions/{session_id}/thread")
def session_thread(session_id: str,
                   org: models.Organization = Depends(auth.require_org),
                   session_db: Session = Depends(db_session)):
    """The conversation as relations: said, delegated, executed, observed, refused.

    A read model over three tables that already exist — `chat_turns` (what was said),
    `ai_steps` (what each participant did, including the prompt version) and
    `agent_task_events` (what the field agent saw and what was refused). Nothing is
    copied: a thread that kept its own copy would drift from the ledger within a week,
    which is why the channel is a projection and never a second store.
    """
    row = _get(session_db, org, session_id)
    events: list[dict] = []

    for turn in (session_db.query(models.ChatTurn).filter_by(session_id=row.id)
                 .order_by(models.ChatTurn.seq).all()):
        if turn.role == "compaction":
            continue
        events.append({"kind": "said", "author": turn.author or turn.role,
                       "role": turn.role, "at": _iso(turn.created_at),
                       "content": turn.content, "run_id": turn.run_id,
                       "citations": json.loads(turn.citations or "[]"),
                       "tokens": turn.tokens or 0, "order": turn.seq})

    runs = (session_db.query(models.AiRun).filter_by(session_id=row.id).all())
    run_ids = [run.id for run in runs]
    tokens = 0
    if run_ids:
        for step in (session_db.query(models.AiStep)
                     .filter(models.AiStep.run_id.in_(run_ids))
                     .order_by(models.AiStep.created_at, models.AiStep.seq).all()):
            try:
                handoff = json.loads(step.handoff or "null")
            except ValueError:
                handoff = None
            try:
                calls = json.loads(step.tool_calls or "[]")
            except ValueError:
                calls = []
            step_tokens = (step.tokens_in or 0) + (step.tokens_out or 0)
            tokens += step_tokens
            events.append({
                # A field step names the task kind as its author, so the channel shows
                # `validate.finding` speaking for itself, not "field".
                "kind": "field_step" if step.role == "field" else "delegated",
                "author": step.phase if step.role == "field" else step.role,
                "at": _iso(step.created_at), "run_id": step.run_id,
                "prompt_version": step.prompt_version,
                "tools": [call.get("tool") for call in calls
                          if isinstance(call, dict) and call.get("tool")],
                "claims": (handoff if isinstance(handoff, dict) else {}).get(
                    "claims") or [],
                "skipped": (handoff if isinstance(handoff, dict) else {}).get(
                    "skipped") or [],
                "invalid_refs": (handoff if isinstance(handoff, dict) else {}).get(
                    "invalid_refs") or 0,
                "tokens": step_tokens,
                "order": 0,
            })

    # The field half: tasks whose mission points at a run in this thread.
    missions = (session_db.query(models.AgentMission)
                .filter(models.AgentMission.run_id.in_(run_ids)).all()
                if run_ids else [])
    mission_run = {mission.id: mission.run_id for mission in missions}
    task_by_id: dict[str, models.AgentTask] = {}
    if missions:
        tasks = (session_db.query(models.AgentTask)
                 .filter(models.AgentTask.mission_id.in_(
                     [mission.id for mission in missions])).all())
        task_by_id = {task.id: task for task in tasks}
        if task_by_id:
            for event in (session_db.query(models.AgentTaskEvent)
                          .filter(models.AgentTaskEvent.task_id.in_(
                              list(task_by_id)))
                          .order_by(models.AgentTaskEvent.created_at).all()):
                task = task_by_id[event.task_id]
                try:
                    payload = json.loads(event.payload or "{}")
                except ValueError:
                    payload = {}
                events.append({
                    "kind": event.kind, "author": task.worker or task.kind,
                    "task": task.kind, "at": _iso(event.created_at),
                    "run_id": mission_run.get(task.mission_id),
                    "payload": payload, "order": event.seq,
                })

    events.sort(key=lambda item: (item["at"], item.get("order") or 0))
    return {"data": {"session": _session_data(row), "events": events,
                     "totals": {"events": len(events), "tokens": tokens,
                                "runs": len(runs)}}}


# ─────────────────────────── pins ───────────────────────────

@router.post("/sessions/{session_id}/pins", status_code=status.HTTP_201_CREATED)
def create_pin(session_id: str, payload: PinIn,
               principal: dict = Depends(authz.principal),
               org: models.Organization = Depends(auth.require_org),
               session_db: Session = Depends(db_session)):
    authz.require_analyst(principal)
    row = _get(session_db, org, session_id)
    if payload.turn_id:
        turn = session_db.get(models.ChatTurn, payload.turn_id)
        if turn is None or turn.session_id != row.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "turn not found")
    pin = models.ChatPin(org_id=org.id, session_id=row.id,
                         turn_id=payload.turn_id, note=payload.note,
                         created_by=authz.actor_of(principal))
    session_db.add(pin)
    session_db.commit()
    return {"data": {"id": pin.id, "turn_id": pin.turn_id, "note": pin.note}}


@router.delete("/sessions/{session_id}/pins/{pin_id}",
               status_code=status.HTTP_204_NO_CONTENT)
def delete_pin(session_id: str, pin_id: str,
               principal: dict = Depends(authz.principal),
               org: models.Organization = Depends(auth.require_org),
               session_db: Session = Depends(db_session)):
    authz.require_analyst(principal)
    row = _get(session_db, org, session_id)
    pin = session_db.get(models.ChatPin, pin_id)
    if pin is None or pin.session_id != row.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "pin not found")
    session_db.delete(pin)
    session_db.commit()
    return None

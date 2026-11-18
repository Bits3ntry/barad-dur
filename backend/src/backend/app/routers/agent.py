"""The field runtime's platform half: missions, tasks, gateway, scope (F4).

What lives here and what does not, because the line is the whole design:

* here: the **envelope** (what may be touched, with which tools, under which
  ceiling), the task ledger, the two channels Shauron uses — `POST /llm/complete` and
  batched `POST /tasks/{id}/events` — and the scope decision the egress proxy asks.
* not here: running a tool. A FastAPI container has no pinned tooling, no run
  directory, no network position inside the target. Acting happens in Shauron (D25).

Three refusals are structural rather than advisory:

* a mission whose target is not in the effective scope is not created at all;
* a task token opens exactly two paths and expires with its lease (D60);
* the gateway refuses the *next* completion when either ceiling is reached — the
  platform's monthly cap or the mission's own budget — and says which one.
"""
from __future__ import annotations

import hashlib
import json
import re
import secrets as stdlib_secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, auth_local, decisions, models, scoping, secrets, shauron_signing
from backend.app.ai import authz, engine, prompts as prompt_registry
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/agent", tags=["agent"])

LEASE_MINUTES = 10
TOKEN_TTL_MINUTES = 30

#: The envelope speaks the profile's language; the scope engine speaks its own. The
#: mapping is explicit so neither vocabulary silently borrows the other's authority.
SCOPE_CAPABILITY = {"validate": "active_verification",
                    "discover": "passive_discovery",
                    "exploit": "active_verification"}

#: The lane each profile may open (D42). Angmar reproduces a documented finding;
#: Morgoth discovers and exploits, and exploiting needs a grant and an operator
#: decision that red teaming is allowed at all.
PROFILE_LANES = {"angmar": {"validate"},
                 "morgoth": {"discover", "exploit"}}
#: capability → the profile that owns it, used when the caller does not name one.
PROFILE_FOR = {"validate": "angmar", "discover": "morgoth", "exploit": "morgoth"}

#: Critical first, because the briefing is a queue of what to try, not a list.
_SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


# ─────────────────────────────── payloads ────────────────────────────────────

class TargetIn(BaseModel):
    kind: str = Field(default="url")
    value: str
    methods: list[str] = Field(default_factory=lambda: ["GET"])
    rate_per_min: int = Field(default=20, ge=1, le=600)


class BudgetIn(BaseModel):
    steps: int = Field(default=10, ge=1, le=200)
    # A validate mission spends ~2.5–3k tokens per completion (tool schema + the
    # envelope + the brief), so ten steps need ~30k and a lane running twelve needs
    # ~36k. A 20k ceiling refused the eighth completion with `429 mission token
    # budget reached` *after* the agent had done the work, which reads as a broken
    # agent. The ceiling is a cost control, not a trap: 60k funds the default run
    # and still stops a runaway loop.
    tokens: int = Field(default=60000, ge=0)
    wall_s: int = Field(default=600, ge=30, le=14400)
    usd: float = Field(default=0.0, ge=0.0)


class MissionIn(BaseModel):
    goal: str = Field(min_length=4)
    capability: str = Field(default="validate")
    #: The conversation this mission belongs to, when it was started from one: the
    #: channel then shows the field agent beside the orchestrator that aimed it (A6).
    session_id: str | None = Field(default=None, max_length=36)
    #: Optional: the capability decides the profile when the caller does not.
    profile: str | None = None
    targets: list[TargetIn] = Field(min_length=1)
    tools: list[str] = Field(default_factory=lambda: ["curl"])
    grant_id: str | None = None
    grant_level: str | None = None
    budget: BudgetIn = Field(default_factory=BudgetIn)
    evidence: dict = Field(default_factory=lambda: {"required": ["request", "response"]})
    deadline_minutes: int = Field(default=30, ge=1, le=1440)
    actor: str = Field(min_length=1, max_length=255)


class TaskIn(BaseModel):
    kind: str
    target: dict
    tools: list[str] | None = None
    must_return: list[str] = Field(default_factory=lambda: ["request", "response"])


class ClaimIn(BaseModel):
    worker: str = Field(min_length=1, max_length=128)


class EventIn(BaseModel):
    kind: str
    tool: str | None = None
    payload: dict = Field(default_factory=dict)


class EventsIn(BaseModel):
    events: list[EventIn] = Field(min_length=1, max_length=50)


class CompleteIn(BaseModel):
    messages: list[dict] = Field(min_length=1)
    tools: list[dict] = Field(default_factory=list)
    max_tokens: int | None = None


class ScopeIn(BaseModel):
    target_type: str = "url"
    value: str
    capability: str = "validate"


# ─────────────────────────────── helpers ─────────────────────────────────────

def _mission_data(row: models.AgentMission, tasks: int | None = None) -> dict:
    data = {
        "id": row.id, "goal": row.goal, "capability": row.capability,
        "profile": row.profile, "status": row.status, "actor": row.actor, "role": row.actor_role,
        "targets": json.loads(row.targets or "[]"),
        "tools": json.loads(row.tools or "[]"),
        "grant_id": row.grant_id, "grant_level": row.grant_level,
        "budget": json.loads(row.budget or "{}"),
        "evidence": json.loads(row.evidence or "{}"),
        "run_id": row.run_id,
        "deadline_at": row.deadline_at.isoformat() if row.deadline_at else None,
        "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
        "revoked_by": row.revoked_by,
        "approved_by": getattr(row, "approved_by", None),
        "approved_at": (row.approved_at.isoformat()
                        if getattr(row, "approved_at", None) else None),
        "signature": row.signature,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
    }
    if tasks is not None:
        data["tasks"] = tasks
    return data


def _task_data(row: models.AgentTask, events: int | None = None) -> dict:
    data = {
        "id": row.id, "mission_id": row.mission_id, "kind": row.kind,
        "target": json.loads(row.target or "{}"),
        "tools": json.loads(row.tools or "[]"),
        "must_return": json.loads(row.must_return or "[]"),
        "status": row.status, "attempts": row.attempts, "worker": row.worker,
        "approved_by": getattr(row, "approved_by", None),
        "approved_at": (row.approved_at.isoformat()
                        if getattr(row, "approved_at", None) else None),
        "lease_expires_at": row.lease_expires_at.isoformat() if row.lease_expires_at else None,
        "result": json.loads(row.result) if row.result else None,
        "error": row.error,
        "finished_at": row.finished_at.isoformat() if row.finished_at else None,
    }
    if events is not None:
        data["events"] = events
    return data


def _mission_or_404(session: Session, org: models.Organization,
                    mission_id: str) -> models.AgentMission:
    row = session.get(models.AgentMission, mission_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "mission not found")
    return row


def _envelope(session: Session, mission: models.AgentMission,
              task: models.AgentTask, token_expires_at) -> dict:
    """The signed document Shauron trusts — and the only thing it trusts."""
    document = {
        "schema": "barad-mission-v1",
        "mission_id": mission.id, "task_id": task.id,
        "run_id": mission.run_id, "org_id": mission.org_id,
        "origin": "shauron-ai", "profile": mission.profile,
        "goal": mission.goal, "capability": mission.capability,
        "targets": [json.loads(task.target or "{}")]
        if task.target else json.loads(mission.targets or "[]"),
        "tools": json.loads(task.tools or "[]"),
        "must_return": json.loads(task.must_return or "[]"),
        "grant_id": mission.grant_id, "grant_level": mission.grant_level,
        "budget": json.loads(mission.budget or "{}"),
        "evidence": json.loads(mission.evidence or "{}"),
        "deadline_at": mission.deadline_at.isoformat() if mission.deadline_at else None,
        "token_expires_at": token_expires_at.isoformat(),
    }
    return shauron_signing.sign_ticket(session, document)


def _scope_decision(session: Session, org: models.Organization, target_type: str,
                    value: str, capability: str):
    targets = session.query(models.ScopeTarget).filter_by(org_id=org.id).all()
    exclusions = session.query(models.ScopeExclusion).filter_by(org_id=org.id).all()
    scope_capability = SCOPE_CAPABILITY.get(capability, capability)
    try:
        return scoping.decide(targets, exclusions, target_type, value, scope_capability)
    except scoping.ScopeValueError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from None


def _aware(value: datetime | None) -> datetime | None:
    """SQLite hands back naive datetimes; every comparison here is in UTC."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _task_token(x_agent_token: str | None = Header(default=None),
                session: Session = Depends(get_session)) -> models.AgentTask:
    """A task token: hashed at rest, bound to one task, dies with its lease."""
    if not x_agent_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "missing X-Agent-Token: a field task presents its own "
                            "short-lived token, never an API key")
    digest = auth_local.token_hash(x_agent_token)
    task = (session.query(models.AgentTask)
            .filter_by(token_hash=digest).one_or_none())
    if task is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "unknown or spent task token")
    if _aware(task.token_expires_at) is not None \
            and _aware(task.token_expires_at) < models.utcnow():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "task token expired")
    mission = session.get(models.AgentMission, task.mission_id)
    if mission is None or mission.status == "revoked":
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "mission revoked: the task boundary stops here")
    return task


def _mission_of(session: Session, task: models.AgentTask) -> models.AgentMission:
    mission = session.get(models.AgentMission, task.mission_id)
    if mission is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "mission gone")
    return mission


def _mission_run(session: Session, mission: models.AgentMission,
                 session_id: str | None = None) -> models.AiRun:
    """The ledger row this mission's model calls are written to.

    Created **with the mission**, never at the first completion: a mission whose spend
    has no row cannot be capped, and `engine.month_spend` reads `ai_steps` — so the
    half of the harness that touches targets was the half nobody counted. It also
    heals missions created before this existed: the first completion makes the row.
    """
    if mission.run_id:
        run = session.get(models.AiRun, mission.run_id)
        if run is not None:
            return run
    provider = engine.default_provider(session)
    budget = json.loads(mission.budget or "{}")
    run = models.AiRun(
        org_id=mission.org_id, actor=mission.actor, actor_role=mission.actor_role,
        session_id=session_id,
        question=f"mission: {mission.goal}"[:4000], mode="mission",
        provider_id=provider.id if provider else None,
        model=provider.model if provider else None,
        # The mission's own ceiling, so a run-level check exists as well as the
        # per-completion one; NULL means the monthly cap is the only bound.
        token_budget=int(budget.get("tokens") or 0) or None)
    session.add(run)
    session.flush()
    mission.run_id = run.id
    return run


def _close_mission_run(session: Session, mission: models.AgentMission,
                       status: str = "answered") -> None:
    """Close the mission's ledger row, once. A finished mission is not `running`."""
    if not mission.run_id:
        return
    run = session.get(models.AiRun, mission.run_id)
    if run is None or run.finished_at is not None:
        return
    run.status = status
    run.finished_at = models.utcnow()


#: Releases before a task is failed instead of requeued. Three claims that all died
#: is evidence about the task, not about the queue.
MAX_ATTEMPTS = 3


def _settle_mission(session: Session, mission_id: str) -> None:
    """A mission with nothing left open is no longer `running`."""
    # The caller just changed a task's status; without the flush the counts below
    # still see the old row and the mission never closes.
    session.flush()
    mission = session.get(models.AgentMission, mission_id)
    if mission is None or mission.status not in {"queued", "running", "leased", "claimed"}:
        return
    open_tasks = (session.query(models.AgentTask)
                  .filter(models.AgentTask.mission_id == mission_id,
                          models.AgentTask.status.in_(("queued", "claimed", "running")))
                  .count())
    if open_tasks:
        return
    failed = (session.query(models.AgentTask)
              .filter(models.AgentTask.mission_id == mission_id,
                      models.AgentTask.status == "failed").count())
    mission.status = "failed" if failed else "done"
    mission.finished_at = models.utcnow()
    _close_mission_run(session, mission, status="failed" if failed else "answered")


def _release_expired_leases(session: Session, org_id: str) -> int:
    """Give back the tasks whose worker disappeared.

    A lane that claims a task and dies — a crash, a killed container, a provider
    that answers `429` without the loop posting `final` — leaves the row `claimed`
    and invisible to every other worker, because the queue lists `queued` only. The
    mission then reads `running` for ever, which is the screen lying. The lease is
    the only fact that says the worker is gone, so the lease is what puts it back:
    the task returns to the queue, and after `MAX_ATTEMPTS` releases it fails with
    the reason, so the mission closes instead of hanging.
    """
    now = models.utcnow()
    rows = (session.query(models.AgentTask)
            .filter(models.AgentTask.org_id == org_id,
                    models.AgentTask.status.in_(("claimed", "running")))
            .all())
    released = 0
    for row in rows:
        # `lease_expires_at` is already the deadline. Only when it is missing does
        # the row's own write time stand in for the claim — adding the lease to a
        # deadline that exists double-counts it and nothing ever releases.
        lease = _aware(row.lease_expires_at)
        if lease is None:
            stamp = _aware(row.updated_at)
            lease = stamp + timedelta(minutes=LEASE_MINUTES) if stamp else None
        if lease is None or lease > now:
            continue
        if (row.attempts or 0) >= MAX_ATTEMPTS:
            row.status = "failed"
            row.error = row.error or "lease expired without a final event"
            row.finished_at = now
            row.worker = None
            row.lease_expires_at = None
            _settle_mission(session, row.mission_id)
        else:
            row.status = "queued"
            row.worker = None
            row.lease_expires_at = None
            row.token_hash = None
            row.token_expires_at = None
        released += 1
    if released:
        session.commit()
    return released


def _normalise_target(target: TargetIn) -> dict:
    """A mission names an origin; a task names a path.

    An operator pastes the deep link they were looking at, and the envelope then covered
    exactly that path — so the first sibling URL the agent tried came back "outside the
    mission envelope", fourteen times on this estate, on the same host. The scope engine
    already treats an origin as covering its paths, so the honest normalisation is to
    the origin, and the value the operator wrote travels as `declared`: widening scope
    stays a decision somebody can read, not an accident of how a URL was typed.
    """
    data = target.model_dump()
    value = str(data.get("value") or "").strip()
    if data.get("kind") == "url" and "//" in value:
        parts = urlsplit(value)
        origin = f"{parts.scheme}://{parts.netloc}"
        if (parts.path.strip("/") or parts.query) and parts.netloc:
            data["declared"] = value
            data["value"] = origin
    return data


def _session_of(session: Session, org: models.Organization,
                session_id: str | None) -> str | None:
    """The conversation a mission was started from, or None — never a guess.

    A thread id that does not belong to this organization is a 404, not a silent None:
    otherwise a mission would quietly disappear from the channel the operator was
    looking at.
    """
    if not session_id:
        return None
    row = session.get(models.ChatSession, session_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "session not found")
    return row.id


# ─────────────────────────────── missions ────────────────────────────────────

@router.post("/missions", status_code=status.HTTP_201_CREATED)
def create_mission(payload: MissionIn = None,
                   principal: dict = Depends(authz.principal),
                   org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    """Create the authorization. A target outside the scope is a refusal, not a note."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    authz.require_analyst(principal)
    if payload.capability not in models.AGENT_CAPABILITIES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"capability must be one of {sorted(models.AGENT_CAPABILITIES)}")

    # Which profile is doing this, and may that profile open this lane (D42)?
    profile = (payload.profile or PROFILE_FOR[payload.capability]).lower()
    if profile not in models.AGENT_PROFILES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"profile must be one of {sorted(models.AGENT_PROFILES)}")
    if payload.capability not in PROFILE_LANES[profile]:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"{profile} may not open the {payload.capability} lane "
            f"(allowed: {sorted(PROFILE_LANES[profile])})")
    if payload.capability == "exploit":
        settings = engine.settings_row(session)
        if not settings.redteam_allowed:
            raise HTTPException(
                status.HTTP_403_FORBIDDEN,
                "exploitation is off: Settings → AI does not allow red-team "
                "hypotheses, so no mission may open the exploit lane")
        if not payload.grant_id:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "the exploit lane needs a grant_id: exploitation without a grant is "
                "not in the envelope")

    targets = [_normalise_target(target) for target in payload.targets]
    refused = []
    for target in targets:
        decision = _scope_decision(session, org, target["kind"], target["value"],
                                   payload.capability)
        if not decision.allowed:
            refused.append({"target": target["value"],
                            "why": decision.reason or "outside the effective scope",
                            "matched": decision.matched_rule})
    if refused:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {"message": "the mission has targets outside the effective scope",
             "refused": refused})

    now = models.utcnow()
    mission = models.AgentMission(
        org_id=org.id, actor=payload.actor, actor_role="analyst",
        goal=payload.goal, capability=payload.capability, profile=profile,
        # Nothing runs on creation. A mission is the operator's authorization, and the
        # operator is the one who approves it (D85): the envelope exists, its tasks do
        # not start until a human presses the gate.
        status="awaiting_approval",
        targets=json.dumps(targets),
        tools=json.dumps(payload.tools),
        grant_id=payload.grant_id, grant_level=payload.grant_level,
        budget=json.dumps(payload.budget.model_dump()),
        evidence=json.dumps(payload.evidence),
        deadline_at=now + timedelta(minutes=payload.deadline_minutes))
    session.add(mission)
    session.flush()
    # The ledger row exists before anything can spend: a mission is a budget, and a
    # budget with no meter is a promise.
    _mission_run(session, mission, _session_of(session, org, payload.session_id))

    signed = shauron_signing.sign_ticket(session, {
        "schema": "barad-mission-v1", "mission_id": mission.id,
        "org_id": org.id, "origin": "shauron-ai", "profile": mission.profile,
        "goal": mission.goal,
        "capability": mission.capability, "targets": json.loads(mission.targets),
        "tools": json.loads(mission.tools), "grant_id": mission.grant_id,
        "budget": json.loads(mission.budget),
        "deadline_at": mission.deadline_at.isoformat()})
    mission.signature = signed[shauron_signing.SIGNATURE_FIELD]
    _audit_log(session, org.id, payload.actor, "agent.mission_created", "agent_mission",
               mission.id, f"{payload.capability}: {payload.goal[:120]}")
    session.commit()
    return {"data": _mission_data(mission, tasks=0)}


@router.get("/missions")
def list_missions(limit: int = Query(default=20, ge=1, le=100),
                  offset: int = Query(default=0, ge=0),
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    query = (session.query(models.AgentMission)
             .filter_by(org_id=org.id)
             .order_by(models.AgentMission.created_at.desc()))
    total = query.count()
    rows = query.offset(offset).limit(limit).all()
    return {"data": [_mission_data(row, tasks=session.query(models.AgentTask)
                                   .filter_by(mission_id=row.id).count())
                     for row in rows], "total": total,
            "limit": limit, "offset": offset}


@router.get("/missions/{mission_id}")
def get_mission(mission_id: str, org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    mission = _mission_or_404(session, org, mission_id)
    tasks = (session.query(models.AgentTask).filter_by(mission_id=mission.id)
             .order_by(models.AgentTask.created_at).all())
    return {"data": {**_mission_data(mission, tasks=len(tasks)),
                     "task_rows": [_task_data(task) for task in tasks]}}


def _covered_by(envelope_value: str, task_value: str) -> bool:
    """Whether the envelope entry covers the task's target.

    An origin covers its own paths. The mission normalises a pasted URL to its origin
    on purpose (widening scope must not be an accident of how a URL was typed), so the
    task that follows it names a path — and comparing the two strings refused a task
    for being *inside* the envelope it was created from. Same rule as the scope
    engine: same scheme and host means covered; a different host is not.
    """
    if task_value == envelope_value:
        return True
    try:
        want, have = urlsplit(task_value), urlsplit(envelope_value)
    except ValueError:
        return False
    if not (want.scheme and want.netloc and have.scheme and have.netloc):
        return False
    return (want.scheme, want.netloc) == (have.scheme, have.netloc)


@router.post("/missions/{mission_id}/tasks", status_code=status.HTTP_201_CREATED)
def add_task(mission_id: str, payload: TaskIn = None,
             org: models.Organization = Depends(auth.require_org),
             session: Session = Depends(get_session)):
    """Add one contract. The target must already be inside the mission's envelope."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    mission = _mission_or_404(session, org, mission_id)
    if mission.status == "revoked":
        raise HTTPException(status.HTTP_409_CONFLICT, "mission is revoked")
    if mission.status in {"draft", "awaiting_approval"}:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "mission awaits approval: nothing is dispatched before "
                            "the operator approves it")
    if payload.kind not in models.AGENT_TASK_KINDS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"kind must be one of {sorted(models.AGENT_TASK_KINDS)}")
    envelope_values = {target["value"] for target in json.loads(mission.targets or "[]")}
    task_value = payload.target.get("value")
    if task_value and not any(_covered_by(value, task_value)
                              for value in envelope_values):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"target {task_value} is not in the mission envelope; widening scope is "
            "a new mission, not a new task")
    task = models.AgentTask(
        org_id=org.id, mission_id=mission.id, kind=payload.kind,
        target=json.dumps(payload.target),
        tools=json.dumps(payload.tools or json.loads(mission.tools or "[]")),
        must_return=json.dumps(payload.must_return), status="queued")
    session.add(task)
    session.commit()
    return {"data": _task_data(task, events=0)}


@router.post("/missions/{mission_id}/approve")
def approve_mission(mission_id: str,
                    org: models.Organization = Depends(auth.require_admin),
                    session: Session = Depends(get_session)):
    """The gate. Approving is a human act and it is written as one."""
    mission = session.get(models.AgentMission, mission_id)
    if mission is None or mission.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "mission not found")
    if mission.status != "awaiting_approval":
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"mission is {mission.status}, not awaiting approval")
    mission.status = "approved"
    mission.approved_by = "console"
    mission.approved_at = models.utcnow()
    _audit_log(session, org.id, "console", "agent.mission_approved", "agent_mission",
               mission.id, mission.goal[:120])
    # Approving a mission that already says what it will run is one act, not two. The
    # proposal carries `evidence.task_kind`; without this the operator approves and the
    # mission then sits there until somebody remembers to file a task by hand — which is
    # how a queue looks alive and does nothing.
    spawned = _first_task(session, mission)
    session.commit()
    return {"data": _mission_data(mission),
            "task": _task_brief(spawned) if spawned is not None else None}


def _first_task(session: Session, mission: models.AgentMission):
    """The task the proposal described, written on approval. Never a guess.

    Only when the mission names one kind and one target: a mission with two targets needs
    a human to say which one runs first, and inventing an order is worse than asking.
    """
    try:
        evidence = json.loads(mission.evidence or "{}")
        targets = json.loads(mission.targets or "[]")
    except ValueError:
        return None
    kind = evidence.get("task_kind")
    if kind not in models.AGENT_TASK_KINDS or len(targets) != 1:
        return None
    existing = (session.query(models.AgentTask)
                .filter_by(mission_id=mission.id).count())
    if existing:
        return None
    target = targets[0]
    task = models.AgentTask(
        org_id=mission.org_id, mission_id=mission.id, kind=kind,
        target=json.dumps(target), tools=mission.tools,
        must_return=json.dumps(evidence.get("required") or []),
        status="queued")
    session.add(task)
    session.flush()
    return task


def _task_brief(task: models.AgentTask) -> dict:
    return {"id": task.id, "kind": task.kind, "status": task.status}


@router.post("/missions/{mission_id}/reject")
def reject_mission(mission_id: str, payload: dict = None,
                   org: models.Organization = Depends(auth.require_admin),
                   session: Session = Depends(get_session)):
    """Refusing is also a decision, and it names the reason."""
    mission = session.get(models.AgentMission, mission_id)
    if mission is None or mission.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "mission not found")
    if mission.status not in {"awaiting_approval", "approved"}:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"mission is {mission.status}")
    reason = (payload or {}).get("reason") or "rejected by the operator"
    mission.status = "revoked"
    mission.revoked_at = models.utcnow()
    mission.revocation_reason = reason
    _audit_log(session, org.id, "console", "agent.mission_rejected", "agent_mission",
               mission.id, reason[:120])
    session.commit()
    return {"data": _mission_data(mission)}


@router.post("/missions/{mission_id}/revoke")
def revoke_mission(mission_id: str, actor: str = Query(default="console"),
                   org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    """The kill switch: queued tasks expire, tokens stop working, partial work stays."""
    mission = _mission_or_404(session, org, mission_id)
    mission.status = "revoked"
    mission.revoked_at = models.utcnow()
    mission.revoked_by = actor
    stopped = (session.query(models.AgentTask)
               .filter_by(mission_id=mission.id)
               .filter(models.AgentTask.status.in_(["queued", "claimed", "running"]))
               .all())
    for task in stopped:
        task.status = "expired"
        task.error = "mission revoked"
        task.finished_at = models.utcnow()
    # The kill switch closes the ledger row too: a revoked mission that keeps reading
    # `running` is a run you cannot tell apart from one still spending.
    _close_mission_run(session, mission, "killed")
    _audit_log(session, org.id, actor, "agent.mission_revoked", "agent_mission",
               mission.id, f"{len(stopped)} task(s) stopped")
    session.commit()
    return {"data": _mission_data(mission), "stopped": len(stopped)}


def _proof_text(request: dict, url: str) -> str | None:
    """`METHOD /path?query` + headers + body, the format the Repeat panel seeds from.

    The query string is part of the request: `GET /rest/products/search` without
    `?q='))--` is a different request and repeats nothing. Dropping it made every
    promoted SQLi point at the clean endpoint.
    """
    if not isinstance(request, dict) or not request.get("url"):
        return None
    method = str(request.get("method") or "GET").upper()
    parts = urlsplit(request["url"])
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    lines = [f"{method} {path} HTTP/1.1"]
    if parts.netloc:
        lines.append(f"Host: {parts.netloc}")
    for name, value in (request.get("headers") or {}).items():
        lines.append(f"{name}: {value}")
    body = request.get("body") or ""
    return "\n".join(lines) + ("\n\n" + body if body else "")


def _response_text(exchange: dict | None, limit: int = 2000) -> str | None:
    """The response the gate actually got, in the same shape as the request.

    A finding without its response is a claim: the reader cannot tell a 200 with the
    whole catalogue from a 401.
    """
    if not isinstance(exchange, dict) or exchange.get("status") is None:
        return None
    lines = [f"HTTP/1.1 {exchange.get('status')}"]
    for name, value in (exchange.get("response_headers") or {}).items():
        lines.append(f"{name}: {value}")
    body = str(exchange.get("response_body") or "")
    return "\n".join(lines) + ("\n\n" + body[:limit] if body else "")


def _endpoint_of(url: str | None) -> str | None:
    """`http://host:3111/rest/user/login` → `/rest/user/login` (empty path → `/`)."""
    if not url:
        return None
    return urlsplit(url).path or "/"


# ──────────────────────────────── tasks ──────────────────────────────────────

@router.get("/tasks")
def list_tasks(status_filter: str = Query(default="queued", alias="status"),
               kind: str | None = Query(default=None),
               limit: int = Query(default=20, ge=1, le=100),
               per_mission: int = Query(default=4, ge=1, le=50),
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """The pending queue a runtime lane polls.

    Oldest first, but capped per mission: one session with fifty tasks must not take
    every lane. This is the fairness rule, and it lives in the query — a client cannot
    opt out of it.
    """
    # Before answering: a task whose lease expired is the queue's again. Doing it
    # here means every runtime lane heals the backlog by simply polling.
    if status_filter == "queued":
        _release_expired_leases(session, org.id)
    query = (session.query(models.AgentTask)
             .filter_by(org_id=org.id, status=status_filter))
    if kind:
        query = query.filter_by(kind=kind)
    rows = query.order_by(models.AgentTask.created_at).all()
    taken: dict[str, int] = {}
    page = []
    for row in rows:
        used = taken.get(row.mission_id or "", 0)
        if used >= per_mission:
            continue
        taken[row.mission_id or ""] = used + 1
        page.append(_task_data(row))
        if len(page) >= limit:
            break
    return {"data": page, "total": len(page)}


@router.post("/tasks/{task_id}/claim")
def claim_task(task_id: str, payload: ClaimIn = None,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """Hand one task to one worker, with a lease and a token it cannot widen."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    task = session.get(models.AgentTask, task_id)
    if task is None or task.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "task not found")
    mission = _mission_of(session, task)
    if mission.status == "revoked":
        raise HTTPException(status.HTTP_409_CONFLICT, "mission revoked")
    now = models.utcnow()
    if _aware(mission.deadline_at) is not None \
            and _aware(mission.deadline_at) < now:
        raise HTTPException(status.HTTP_409_CONFLICT, "mission deadline passed")
    if task.status in {"done", "failed", "expired"}:
        raise HTTPException(status.HTTP_409_CONFLICT, f"task is {task.status}")
    if task.status in {"claimed", "running"} \
            and _aware(task.lease_expires_at) is not None \
            and _aware(task.lease_expires_at) > now:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"task leased to {task.worker} until "
                            f"{task.lease_expires_at.isoformat()}")

    token = stdlib_secrets.token_hex(24)
    task.status = "claimed"
    task.worker = payload.worker
    task.attempts += 1
    task.lease_expires_at = now + timedelta(minutes=LEASE_MINUTES)
    task.token_hash = auth_local.token_hash(token)
    task.token_expires_at = now + timedelta(minutes=TOKEN_TTL_MINUTES)
    if mission.status == "approved":
        mission.status = "running"
    session.commit()
    from fastapi.responses import JSONResponse
    return JSONResponse(status_code=200, content={
        "data": {"task": _task_data(task), "token": token,
                 "envelope": _envelope(session, mission, task, task.token_expires_at)}})


@router.post("/tasks/{task_id}/events", status_code=status.HTTP_202_ACCEPTED)
def post_events(task_id: str, payload: EventsIn = None,
                task: models.AgentTask = Depends(_task_token),
                session: Session = Depends(get_session)):
    """Batched ingestion. 202, not a decision: the answer is not approval."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if task.id != task_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "this token belongs to another task")
    last = (session.query(models.AgentTaskEvent)
            .filter_by(task_id=task.id)
            .order_by(models.AgentTaskEvent.seq.desc()).first())
    seq = (last.seq if last else 0)
    # A worker that is posting events is alive, and the lease exists to detect the ones
    # that are not. Without this renewal a run longer than the lease was reaped mid-work
    # — the queue handed it to a second worker, the first kept going with a token that no
    # longer matched, and after three attempts the task died as "lease expired without a
    # final event" over a run that had been answering all along.
    task.lease_expires_at = models.utcnow() + timedelta(minutes=LEASE_MINUTES)
    task.token_expires_at = models.utcnow() + timedelta(minutes=TOKEN_TTL_MINUTES)
    accepted = 0
    for event in payload.events:
        if event.kind not in models.AGENT_EVENT_KINDS:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"event kind must be one of "
                                f"{sorted(models.AGENT_EVENT_KINDS)}")
        seq += 1
        session.add(models.AgentTaskEvent(
            org_id=task.org_id, task_id=task.id, seq=seq, kind=event.kind,
            tool=event.tool, payload=json.dumps(event.payload)))
        accepted += 1
        if event.kind == "final":
            task.status = "failed" if event.payload.get("error") else "done"
            task.result = json.dumps(event.payload)
            task.error = event.payload.get("error")
            task.finished_at = models.utcnow()
            task.token_hash = None
            session.flush()
            mission = _mission_of(session, task)
            remaining = (session.query(models.AgentTask)
                         .filter_by(mission_id=mission.id)
                         .filter(models.AgentTask.status.in_(["queued", "claimed",
                                                              "running"])).count())
            if remaining == 0 and mission.status != "revoked":
                mission.status = "done"
                mission.finished_at = models.utcnow()
                # The money stops when the work stops: a closed mission leaves a
                # closed run, not one that reads `running` for ever in the ledger.
                _close_mission_run(session, mission)
            # A finished task states a claim, and a claim becomes a candidate — not
            # a finding. The gates are what decide whether it is usable, so the row
            # is written here and settled later, by a person or by `/promote`.
            _candidate_from_task(session, task)
            # The verdict belongs to the finding that was asked about, not only to
            # the thread: otherwise the row keeps `exploit_state: none` while the chat
            # shows a verdict, and the screens count a validated finding as unproven.
            _record_validation(session, mission, task)
            # Discovery is only discovery if the estate keeps it: every path the run
            # answered becomes an observation on the asset it answered on.
            _record_observations(session, mission, task)
            # The verdict belongs to the conversation that asked for it: a mission born in
            # a chat that finishes without a word in that chat looks like a failure.
            _announce_in_chat(session, mission, task)
    session.commit()
    return {"data": {"accepted": accepted, "next_seq": seq},
            "task": _task_data(task)}


def _record_validation(session: Session, mission: models.AgentMission,
                       task: models.AgentTask) -> None:
    """Write the field verdict onto the finding the mission was asked about.

    The answer already reaches the thread and the task; without this it never reaches
    the row, so a finding validated on camera kept `exploit_state: none` and every
    count stayed as if nobody had looked. Only the machine's axis moves here:
    `triage_status` is still the operator's.
    """
    try:
        evidence = json.loads(mission.evidence or "{}")
    except ValueError:
        return
    finding_id = (evidence or {}).get("finding_id")
    if not finding_id:
        return
    finding = session.get(models.Finding, finding_id)
    if finding is None or finding.org_id != mission.org_id:
        return
    try:
        payload = json.loads(task.result or "{}")
    except ValueError:
        return
    answer = (payload.get("answer") or "").strip()
    if not answer:
        return
    upper = answer.upper()
    if "NOT VULNERABLE" in upper:
        # Probed and not reproduced: weaker than proven, stronger than untouched.
        state = "attempted"
    elif "VULNERABLE" in upper:
        state = "reproduced"
    elif "INCONCLUSIVE" in upper:
        state = "attempted"
    else:
        return
    finding.validation_output = answer[:8000]
    finding.exploit_state = state


def _record_observations(session: Session, mission: models.AgentMission,
                         task: models.AgentTask) -> int:
    """What a recon run saw becomes observations on the asset it saw them on.

    A discovery whose result only lives in the task's prose is a paragraph: the asset
    page cannot show it, `deployment_chain` cannot cite it, and the next run rediscovers
    the same paths. Each `tool`/`observation` pair the worker posted carries a URL, a
    status and a size — that is an observation, so it is written as one.
    """
    if task.kind != "recon.surface":
        return 0
    events = (session.query(models.AgentTaskEvent)
              .filter_by(task_id=task.id).order_by(models.AgentTaskEvent.seq).all())
    written = 0
    pending: dict | None = None
    for event in events:
        try:
            payload = json.loads(event.payload or "{}")
        except ValueError:
            continue
        if event.kind == "tool":
            pending = payload
            continue
        if event.kind != "observation" or pending is None:
            continue
        url = next((str(arg) for arg in (pending.get("argv") or [])
                    if str(arg).lower().startswith(("http://", "https://"))), None)
        pending = None
        if not url:
            continue
        parts = urlsplit(url)
        host = parts.netloc.split("@")[-1].split(":")[0].lower() if parts.netloc else ""
        if not host:
            continue
        asset = (session.query(models.Asset)
                 .filter(models.Asset.org_id == mission.org_id,
                         models.Asset.value.in_([host, f"{parts.scheme}://{parts.netloc}",
                                                 url]))
                 .first())
        if asset is None:
            continue
        head = str(payload.get("head") or "")
        status = None
        first = head.splitlines()[0] if head else ""
        pieces = first.split()
        if len(pieces) >= 2 and pieces[1].isdigit():
            status = int(pieces[1])
        if status is None:
            # A call whose output carries no status line (`-o /dev/null -w …`) says
            # nothing about the path: writing it would overwrite a real observation
            # with an empty one for the same subject.
            continue
        subject = parts.path or "/"
        value = {"status": status, "bytes": payload.get("bytes"),
                 "method": "GET", "url": url}
        existing = (session.query(models.Observation)
                    .filter_by(org_id=mission.org_id, asset_id=asset.id, kind="web_path",
                               subject=subject[:1024], source="agent:recon")
                    .one_or_none())
        if existing is not None:
            existing.value = value
            existing.observed_at = models.utcnow()
            existing.coverage = "full" if status and 200 <= status < 400 else "partial"
        else:
            session.add(models.Observation(
                org_id=mission.org_id, asset_id=asset.id, kind="web_path",
                subject=subject[:1024], value=value, source="agent:recon",
                coverage="full" if status and 200 <= status < 400 else "partial"))
            # The session is created without autoflush, so the next lookup for this
            # subject would miss the row we just added and write it twice.
            session.flush()
        written += 1
    return written


def _announce_in_chat(session: Session, mission: models.AgentMission,
                      task: models.AgentTask) -> None:
    """Write the field agent's report as a turn of the thread that proposed the mission."""
    if not mission.run_id:
        return
    run = session.get(models.AiRun, mission.run_id)
    if run is None or not run.session_id:
        return
    row = session.get(models.ChatSession, run.session_id)
    if row is None or row.org_id != mission.org_id:
        return
    try:
        payload = json.loads(task.result or "{}")
    except ValueError:
        payload = {}
    answer = (payload.get("answer") or "").strip()
    if not answer:
        # A run that died (budget, allowlist, timeout) used to leave the thread in
        # silence, so the operator kept waiting for a report that was never coming.
        reason = (task.error or payload.get("error")
                  or f"el run terminó en `{task.status}` sin producir informe")
        from backend.app.routers import chat as chat_router
        chat_router._write_turn(
            session, row, None,
            answer=(f"**La misión no cerró** · tarea `{task.id[:8]}…` · "
                    f"`{task.status}`\n\n{str(reason)[:600]}\n\n"
                    "La traza de la tarea tiene los eventos: lo que se ejecutó y lo que "
                    "la plataforma se negó a ejecutar. Eso es información, no un "
                    "veredicto."),
            actor="agent", profile_key=mission.profile, assistant_role="specialist",
            extra_citations=[ref for ref in (mission.id, task.id) if ref])
        return
    # A recon run has no verdict to give: the worker still ends its brief with one, so
    # grading a discovery as `INCONCLUSIVE` read as a failed validation of something
    # nobody claimed. The badge says what the run was.
    recon = task.kind == "recon.surface"
    verdict = " · **discovery**" if recon else ""
    if not recon:
        upper = answer.upper()
        for candidate in ("NOT VULNERABLE", "VULNERABLE", "INCONCLUSIVE"):
            if candidate in upper:
                verdict = f" · **{candidate}**"
                break
    from backend.app.routers import chat as chat_router
    title = "Informe de reconocimiento" if recon else "Informe del agente de campo"
    chat_router._write_turn(
        session, row, None,
        answer=(f"**{title}** · tarea `{task.id[:8]}…` · "
                f"`{task.status}`{verdict}\n\n{answer}"),
        actor="agent", profile_key=mission.profile, assistant_role="specialist",
        extra_citations=[ref for ref in (mission.id, task.id) if ref])


@router.get("/tasks/{task_id}/events")
def list_events(task_id: str, org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    task = session.get(models.AgentTask, task_id)
    if task is None or task.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "task not found")
    rows = (session.query(models.AgentTaskEvent).filter_by(task_id=task.id)
            .order_by(models.AgentTaskEvent.seq).all())
    return {"data": [{"seq": row.seq, "kind": row.kind, "tool": row.tool,
                      "payload": json.loads(row.payload or "{}"),
                      "at": row.created_at.isoformat()} for row in rows],
            "total": len(rows)}


def _usage_json(result: dict) -> str | None:
    """What the provider reported beyond the counters, verbatim (see A9)."""
    usage = dict(result.get("usage_raw") or {})
    for key in ("prompt_tokens", "completion_tokens", "total_tokens"):
        usage.pop(key, None)
    return json.dumps(usage) if usage else None


# ──────────────────────────── the two channels ───────────────────────────────

FIELD_LANGUAGE = ("Write the report in the language of the mission goal. Requests, "
                  "responses, headers and payloads stay verbatim; the prose around them "
                  "follows the operator's language.")


def _plan_brief(mission: models.AgentMission) -> str:
    """The approved plan, written where the worker actually reads.

    The worker gets the target, the tools and what the task must return — never
    `mission.evidence.plan`. So a discovery that was approved with five steps wandered
    through thirty calls and rediscovered paths it had already answered, which is also
    what made the run outlive its lease. The plan travels with the field instructions.
    """
    try:
        evidence = json.loads(mission.evidence or "{}")
    except ValueError:
        return ""
    steps = ((evidence.get("plan") or {}).get("steps") or [])
    if not steps:
        return ""
    lines = ["**Plan aprobado** — el operador lo leyó antes de aprobarlo; seguilo en orden:"]
    for index, step in enumerate(steps, start=1):
        line = (f"{step.get('n') or index}. {step.get('method') or 'GET'} "
                f"{step.get('path') or '/'}")
        if step.get("expect"):
            line += f" — {step['expect']}"
        lines.append(line)
    lines.append("Cuando esos pasos estén cubiertos, escribí el informe: no enumeres rutas "
                 "que el plan no pide y no repitas una que ya respondió.")
    return "\n".join(lines)


def _narrow_tools(tools: list[dict], allowed: list[str]) -> list[dict]:
    """The envelope is the first lock on tools; the worker's registry is the second.

    The field loop sends one function, `run_tool`, whose `tool` enum lists what may
    run. A mission that granted `curl` must not even *offer* `nmap`: the refusal that
    costs a step (and tells the model something false about why) is generated
    downstream, so the cheapest fix is not to generate it. A schema named anything
    else survives only if the envelope names it too.
    """
    allowed_set = {name for name in (allowed or []) if name}
    out: list[dict] = []
    for tool in tools or []:
        if not isinstance(tool, dict):
            continue
        function = tool.get("function") or {}
        name = function.get("name") or ""
        parameters = function.get("parameters") or {}
        properties = parameters.get("properties") or {}
        if name == "run_tool" and isinstance(properties.get("tool"), dict):
            narrowed = json.loads(json.dumps(tool))
            tool_param = narrowed["function"]["parameters"]["properties"]["tool"]
            tool_param["enum"] = [item for item in (tool_param.get("enum") or [])
                                  if item in allowed_set] or sorted(allowed_set)
            out.append(narrowed)
        elif name in allowed_set:
            out.append(tool)
    return out


@router.post("/llm/complete")
def complete(payload: CompleteIn = None,
             task: models.AgentTask = Depends(_task_token),
             session: Session = Depends(get_session)):
    """The gateway. It refuses the next completion when either ceiling is reached."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    mission = _mission_of(session, task)
    budget = json.loads(mission.budget or "{}")
    # The mission's ledger row, created with the mission and self-healed here for the
    # missions that predate it. Without it `spent` is zero forever, the mission ceiling
    # never fires, and the monthly meter — which reads `ai_steps` — cannot see the one
    # half of the harness that touches targets.
    run = _mission_run(session, mission)
    session.commit()

    spent = (run.tokens_in or 0) + (run.tokens_out or 0)
    ceiling = int(budget.get("tokens") or 0)
    if ceiling and spent >= ceiling:
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            f"mission token budget reached ({spent} of {ceiling}); the next "
            "completion is refused, not truncated")

    provider = engine.default_provider(session)
    if provider is None:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "no provider configured in Settings → AI")
    try:
        api_key = (secrets.open_sealed(session, provider.secret_cipher)
                   if provider.secret_cipher else "")
    except Exception as error:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR,
                            f"provider key cannot be decrypted: {error}") from error

    settings = engine.settings_row(session)
    try:
        engine.budget_check(session, settings, estimate_tokens=1200)
    except engine.BudgetExceeded as error:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, error.reason) from None

    # The field loop's instructions are editable from the console: the platform
    # prepends (or replaces) the system message here, so Shauron keeps no prompt
    # registry of its own and the change needs no image rebuild.
    field_body, field_label = prompt_registry.resolve(session,
                                                      prompt_registry.FIELD_KEY)
    messages = list(payload.messages or [])
    # The worker keeps no prompt registry, so the language rule for the field report has to
    # ride with the instructions the platform prepends — otherwise a Spanish mission comes
    # back as an English report, which is what the operator then reads in the thread.
    field_body = (field_body or "") + ("\n\n" + FIELD_LANGUAGE if True else "")
    # The approved plan is the difference between a run that follows five steps and one
    # that rediscovers the same surface until its lease expires.
    plan_brief = _plan_brief(mission)
    if plan_brief:
        field_body = field_body + "\n\n" + plan_brief
    if messages and (messages[0] or {}).get("role") == "system":
        messages = [{"role": "system", "content": field_body + "\n\n" +
                     (messages[0].get("content") or "")}] + messages[1:]
    else:
        messages = [{"role": "system", "content": field_body}] + messages

    try:
        result = engine.complete(provider, api_key, messages,
                                 _narrow_tools(payload.tools,
                                               json.loads(task.tools or "[]")
                                               or json.loads(mission.tools or "[]")),
                                 transport=None, session_id=task.id,
                                 max_tokens=payload.max_tokens)
    except engine.ProviderError as error:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(error)) from None

    # Usage is written where the ledger reads it: a field completion is a step.
    # `phase` names the task kind, which is also the participant's name in the
    # channel; `tool_calls` records what the model asked to run (the worker's events
    # record what actually ran).
    last = (session.query(models.AiStep).filter_by(run_id=run.id)
            .order_by(models.AiStep.seq.desc()).first())
    seq = (last.seq if last else 0) + 1
    cost, known = engine.price(provider, result["tokens_in"], result["tokens_out"])
    # The console paints a call red when its `status` is not 200, so a record without
    # `status` painted every field step as `failed` over calls that ran fine. The name
    # is the tool that actually ran (`run_tool` is the envelope, the enum value is the
    # command), because "run_tool · run_tool · run_tool" says nothing.
    asked = []
    for call in (result.get("tool_calls") or []):
        function = call.get("function") or {}
        try:
            args = json.loads(function.get("arguments") or "{}")
        except ValueError:
            args = {}
        inner = args.get("tool") if isinstance(args, dict) else None
        asked.append({"tool": inner or function.get("name") or "",
                      "fn": function.get("name") or "", "args": args, "status": 200})
    session.add(models.AiStep(
        org_id=run.org_id, run_id=run.id, seq=seq, role="field",
        prompt_version=field_label, phase=task.kind, parent_run_id=run.id,
        tool_calls=json.dumps(asked),
        tokens_in=result["tokens_in"], tokens_out=result["tokens_out"],
        cached_tokens=result.get("cached_tokens", 0), cost_usd=cost,
        usage_json=_usage_json(result)))
    run.steps += 1
    run.tool_calls += len(asked)
    run.tokens_in += result["tokens_in"]
    run.tokens_out += result["tokens_out"]
    run.price_known = run.price_known and known
    if cost is not None:
        run.cost_usd = (run.cost_usd or 0.0) + cost
    session.commit()
    return {"data": {"content": result["content"],
                     "tool_calls": result["tool_calls"],
                     "tokens_in": result["tokens_in"],
                     "tokens_out": result["tokens_out"],
                     "mission_tokens_spent": spent + result["tokens_in"]
                     + result["tokens_out"],
                     "mission_token_budget": ceiling or None}}


@router.post("/scope/check")
def scope_check(payload: ScopeIn = None,
                task: models.AgentTask = Depends(_task_token),
                session: Session = Depends(get_session)):
    """The proxy asks here before a connection. A denial is recorded, not argued."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    mission = _mission_of(session, task)
    decision = _scope_decision(session, _org_of(session, mission), payload.target_type,
                               payload.value, payload.capability)
    allowed = decision.allowed
    # The envelope is narrower than the organization's scope: a task may only touch
    # what the mission named, even if the org's scope is wider.
    envelope = json.loads(mission.targets or "[]")
    if allowed and not any(_envelope_covers(target, payload.target_type, payload.value)
                           for target in envelope):
        allowed = False
        reason = "outside the mission envelope"
    else:
        reason = decision.reason
    if not allowed:
        last = (session.query(models.AgentTaskEvent).filter_by(task_id=task.id)
                .order_by(models.AgentTaskEvent.seq.desc()).first())
        session.add(models.AgentTaskEvent(
            org_id=task.org_id, task_id=task.id, seq=(last.seq if last else 0) + 1,
            kind="refusal", tool=None,
            payload=json.dumps({"target": payload.value, "why": reason})))
        session.commit()
    return {"data": {"allowed": allowed, "reason": reason,
                     "target": payload.value, "capability": payload.capability}}


def _envelope_covers(target: dict, kind: str, value: str) -> bool:
    """Does the mission's own target list cover this request?

    Matched by what the target *is*, not by string equality: a mission that names
    `http://host:3111` authorises that origin, so its paths are inside it. Comparing
    whole URLs refused every path but `/`, which left an approved mission able to
    fetch one page and conclude nothing — a pentest that cannot request a single
    endpoint is not a cautious pentest, it is a broken one.
    """
    if (target.get("kind") or "") != kind:
        return False
    allowed = (target.get("value") or "").strip()
    asked = (value or "").strip()
    if not allowed or not asked:
        return False
    if kind == "domain":
        allowed, asked = allowed.lower().rstrip("."), asked.lower().rstrip(".")
        return asked == allowed or asked.endswith("." + allowed)
    if kind != "url":
        return allowed.lower() == asked.lower()
    a = urlsplit(allowed if "//" in allowed else f"https://{allowed}")
    b = urlsplit(asked if "//" in asked else f"https://{asked}")
    if a.scheme.lower() != b.scheme.lower() or a.netloc.lower() != b.netloc.lower():
        return False
    allowed_path = a.path.rstrip("/")
    asked_path = b.path.rstrip("/")
    if not allowed_path:
        return True          # the origin itself: every path on it is in scope
    return asked_path == allowed_path or asked_path.startswith(allowed_path + "/")


def _org_of(session: Session, mission: models.AgentMission) -> models.Organization:
    org = session.get(models.Organization, mission.org_id)
    if org is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "organization gone")
    return org

# ─────────────────────── the autonomous scan, from a cycle ───────────────────
#
# The operator's flow is: create a cycle → press one button → wait for findings.
# Everything between those two clicks is here: the cycle's own scope becomes the
# mission envelope, the mission is approved by the person who pressed the button,
# and every URL in that scope becomes one task for a field agent. Nothing is
# invented at this step — a target the scope does not cover is refused by name.

TASK_FOR_CAPABILITY = {"validate": "validate.finding",
                       "discover": "recon.surface",
                       "exploit": "exploit.chain"}


class CycleScanIn(BaseModel):
    capability: str = "validate"
    goal: str | None = None
    tools: list[str] = Field(default_factory=lambda: ["curl"])
    budget: BudgetIn = Field(default_factory=BudgetIn)
    deadline_minutes: int = Field(default=30, ge=1, le=1440)
    #: Pressing the button *is* the approval. Set false to leave the mission in
    #: `awaiting_approval` and approve it from the Missions screen instead.
    auto_approve: bool = True
    #: Blank means "the caller on the token": the same rule as promote, so a client
    #: that has a credential but no display name is not stopped by validation.
    actor: str = Field(default="", max_length=255)


def _cycle_scan_targets(session: Session, org: models.Organization,
                        cycle: models.Cycle) -> tuple[list[dict], list[dict], list[str]]:
    """The cycle's scope as field-agent targets.

    Only *assets* become targets: a project is a container, and an agent that
    cannot name the URL it touches has nothing to say. A domain asset is widened to
    `https://` because the tool speaks HTTP; the asset keeps its own value.
    """
    from backend.app.routers import cycles as cycles_router

    selection = ((cycle.snapshot or {}).get("selection")
                 if cycle.snapshot_at else (cycle.selection or {}))
    members, gaps = cycles_router._resolve_selection(session, org, selection or {})
    targets, skipped = [], []
    for member in members:
        if member.get("entity_type") != "asset":
            continue
        asset = session.get(models.Asset, member["entity_id"])
        if asset is None or asset.archived_at is not None:
            continue
        value = asset.value.strip()
        lower = value.lower()
        if lower.startswith(("http://", "https://")):
            target_value = value
        elif asset.type in {"domain", "subdomain"}:
            target_value = f"https://{lower}"
        else:
            skipped.append({"asset": value, "why": "not a URL or a domain"})
            continue
        targets.append({"kind": "url", "value": target_value,
                        "asset_id": asset.id, "methods": ["GET", "POST"],
                        "rate_per_min": 20})
    return targets, skipped, gaps


def _cycle_briefing(session: Session, org: models.Organization,
                    targets: list[dict]) -> dict:
    """What the estate already knows about the stack behind the scope.

    Before a single request is sent, the platform can say: this host runs this
    component, at this version, and these open advisories apply to that version.
    A pentest that ignores that spends its budget rediscovering the SBOM — the
    first run has to be aimed at what the deployed versions already claim, and the
    agent's job is to prove which of those claims is reachable.
    """
    per_target: list[dict] = []
    technologies: dict[str, int] = {}
    advisories: list[dict] = []
    seen_components: set[str] = set()

    for target in targets:
        asset_id = target.get("asset_id")
        entry = {"asset": target.get("value"), "kind": target.get("kind"),
                 "deployments": [], "technologies": [], "advisories": []}
        if asset_id:
            links = (session.query(models.AssetLink)
                     .filter_by(org_id=org.id, asset_id=asset_id).all())
            deployment_ids = [link.entity_id for link in links
                              if link.entity_type == "deployment"]
            for deployment in (session.query(models.Deployment)
                               .filter(models.Deployment.id.in_(deployment_ids)).all()
                               if deployment_ids else []):
                component = (session.get(models.ApplicationComponent,
                                         deployment.application_component_id)
                             if deployment.application_component_id else None)
                version = (session.get(models.ProjectVersion, deployment.version_id)
                           if deployment.version_id else None)
                entry["deployments"].append({
                    "component": getattr(component, "name", None) or deployment.name,
                    "component_id": deployment.application_component_id,
                    "environment": deployment.environment,
                    "exposure": deployment.exposure,
                    "version": (version.version if version else deployment.version_label),
                    "version_id": deployment.version_id,
                })
                # The version says which packages ship; without a declared version
                # the component's only version is used and the entry says it is a
                # fallback — never another version's findings dressed as this one's.
                versions = (session.query(models.ProjectVersion)
                            .filter_by(component_id=deployment.application_component_id).all()
                            if deployment.application_component_id else [])
                version = next((candidate for candidate in versions
                                if candidate.id == deployment.version_id), None)
                if version is None and len(versions) == 1:
                    version = versions[0]
                if version is not None:
                    entry["deployments"][-1]["version"] = version.version
                    entry["deployments"][-1]["version_id"] = version.id
                    entry["deployments"][-1]["version_source"] = (
                        "declared" if version.id == deployment.version_id else "only version")
                    rows = (session.query(models.VersionComponent)
                            .filter_by(project_version_id=version.id).all())
                    names: dict[str, int] = {}
                    package_ids: list[str] = []
                    for row in rows:
                        package_ids.append(row.component_id)
                        package = session.get(models.Component, row.component_id)
                        if package and package.name:
                            names[package.name] = names.get(package.name, 0) + 1
                    top = sorted(names, key=lambda name: (-names[name], name))[:12]
                    entry["technologies"] = sorted(set(entry["technologies"]) | set(top))
                    for name in top:
                        technologies[name] = technologies.get(name, 0) + 1
                    entry["_packages"] = list(set(entry.get("_packages") or []) | set(package_ids))
                    entry["_version_ids"] = list(set(entry.get("_version_ids") or []) | {version.id})

            package_ids = entry.get("_packages") or []
            version_ids = entry.get("_version_ids") or []
            if package_ids or version_ids:
                query = (session.query(models.Finding)
                         .filter(models.Finding.org_id == org.id,
                                 models.Finding.kind == "vulnerability",
                                 models.Finding.status == "open"))
                if package_ids and version_ids:
                    query = query.filter(models.Finding.component_id.in_(package_ids),
                                         models.Finding.last_seen_version_id.in_(version_ids))
                else:
                    query = query.filter(models.Finding.component_id.in_(package_ids))
                rows = query.all()
                ranked = sorted(rows, key=lambda f: (_SEVERITY_ORDER.get(
                    (f.severity or "").lower(), 9), f.title or ""))[:12]
                # The advisory belongs to the deployment whose version it came
                # from: a finding points at a *package*, never at the app component.
                holder = next((d for d in entry["deployments"]
                               if d.get("version_id") in version_ids), None) or entry["deployments"][0]
                for finding in ranked:
                    item = {"title": _one_line(finding.title),
                            "severity": finding.severity,
                            "cvss": getattr(finding, "cvss_score", None),
                            "component": holder.get("component"),
                            "version": holder.get("version")}
                    entry["advisories"].append(item)
                    if finding.id not in seen_components:
                        seen_components.add(finding.id)
                        advisories.append({**item, "asset": entry["asset"]})
        entry.pop("_packages", None)
        entry.pop("_version_ids", None)
        per_target.append(entry)

    return {
        "targets": per_target,
        "technologies": sorted(technologies, key=lambda name: (-technologies[name], name))[:20],
        "advisories": advisories[:20],
        "counts": {
            "targets": len(per_target),
            "components": len({d.get("component_id") for entry in per_target
                               for d in entry["deployments"] if d.get("component_id")}),
            "versions": len({d.get("version") for entry in per_target
                             for d in entry["deployments"] if d.get("version")}),
            "advisories": len(advisories),
        },
    }


_GENERIC_HEADINGS = {"summary", "description", "impact", "overview", "details",
                     "resumen", "descripción", "impacto"}


def _one_line(text: str | None, limit: int = 160) -> str:
    """Advisory text arrives as markdown; a queue needs one informative line."""
    lines = []
    for raw in (text or "").splitlines():
        line = raw.strip().lstrip("#").replace("**", "").strip()
        if line and line.lower().rstrip(":. ") not in _GENERIC_HEADINGS:
            lines.append(" ".join(line.split()))
        elif lines:
            break          # a heading after content closes that section
    return (lines[0] if lines else "")[:limit]


def _briefing_goal(cycle: models.Cycle, briefing: dict) -> str:
    """The first run's objective, read from the deployed stack — not from the name."""
    counts = briefing["counts"]
    if counts["advisories"]:
        names = ", ".join(sorted({item["component"] or "?"
                                  for item in briefing["advisories"]})[:4])
        return (f"{cycle.name}: {counts['advisories']} open advisor"
                f"{'y' if counts['advisories'] == 1 else 'ies'} apply to the deployed "
                f"stack ({names}); prove which one is reachable and exploitable")
    if counts["components"]:
        return (f"{cycle.name}: the scope declares {counts['components']} component(s) "
                f"and {counts['versions']} version(s) with no open advisory — "
                "fingerprint what is really running and test it")
    return f"{cycle.name}: find and prove an exploitable weakness in scope"




@router.post("/cycles/{cycle_id}/scan", status_code=status.HTTP_201_CREATED)
def scan_cycle(cycle_id: str, payload: CycleScanIn = None,
               principal: dict = Depends(authz.principal),
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """Start the autonomous pentest of a cycle: one mission, one task per target."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    authz.require_analyst(principal)
    actor = (payload.actor or "").strip() or authz.actor_of(principal)
    cycle = session.get(models.Cycle, cycle_id)
    if cycle is None or cycle.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "cycle not found")
    if cycle.state != "active":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"cycle is {cycle.state}: activate it first, so the scope cannot move "
            "under a run that is already spending budget")
    if payload.capability not in models.AGENT_CAPABILITIES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"capability must be one of {sorted(models.AGENT_CAPABILITIES)}")
    task_kind = TASK_FOR_CAPABILITY[payload.capability]

    targets, skipped, gaps = _cycle_scan_targets(session, org, cycle)
    if not targets:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            {"message": "this cycle's scope holds no URL or domain asset an agent "
                        "could touch",
             "gaps": gaps, "skipped": skipped})

    allowed, refused = [], []
    for target in targets:
        decision = _scope_decision(session, org, target["kind"], target["value"],
                                   payload.capability)
        if decision.allowed:
            allowed.append(target)
        else:
            refused.append({"target": target["value"],
                            "why": decision.reason or "outside the effective scope"})
    if not allowed:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            {"message": "every target of this cycle is outside the "
                                        "effective scope", "refused": refused})

    profile = PROFILE_FOR[payload.capability]
    if payload.capability not in PROFILE_LANES[profile]:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"{profile} may not open the {payload.capability} lane")

    # The first run is briefed before it is aimed: what the estate already knows
    # about the deployed stack decides the goal, and the briefing travels with the
    # mission so the agent starts from the SBOM instead of rediscovering it.
    briefing = _cycle_briefing(session, org, allowed)
    goal = payload.goal or _briefing_goal(cycle, briefing)

    now = models.utcnow()
    mission = models.AgentMission(
        org_id=org.id, actor=actor, actor_role="analyst",
        goal=goal[:2000],
        capability=payload.capability, profile=profile,
        status="awaiting_approval",
        targets=json.dumps([{k: t[k] for k in ("kind", "value", "methods",
                                              "rate_per_min")} for t in allowed]),
        tools=json.dumps(payload.tools),
        budget=json.dumps(payload.budget.model_dump()),
        # The cycle it belongs to travels with the mission: a mission that cannot
        # name its cycle leaves findings with no campaign, and the review queue with
        # no way back to the scan that produced the claim.
        evidence=json.dumps({"required": ["request", "response"],
                             "cycle_id": cycle.id,
                             "briefing": briefing}),
        deadline_at=now + timedelta(minutes=payload.deadline_minutes))
    session.add(mission)
    session.flush()
    _mission_run(session, mission)
    signed = shauron_signing.sign_ticket(session, {
        "schema": "barad-mission-v1", "mission_id": mission.id,
        "org_id": org.id, "origin": "shauron-ai", "profile": mission.profile,
        "goal": mission.goal, "capability": mission.capability,
        "targets": json.loads(mission.targets), "tools": json.loads(mission.tools),
        "grant_id": None, "budget": json.loads(mission.budget),
        "deadline_at": mission.deadline_at.isoformat()})
    mission.signature = signed[shauron_signing.SIGNATURE_FIELD]

    if payload.auto_approve:
        mission.status = "approved"
        mission.approved_by = actor
        mission.approved_at = now

    tasks = []
    if mission.status == "approved":
        for target in allowed:
            task = models.AgentTask(
                org_id=org.id, mission_id=mission.id, kind=task_kind,
                target=json.dumps({k: target[k] for k in ("kind", "value", "asset_id")}),
                tools=json.dumps(payload.tools),
                must_return=json.dumps(["request", "response", "verdict"]),
                status="queued")
            session.add(task)
            tasks.append(task)
        session.flush()

    _audit_log(session, org.id, actor, "agent.cycle_scan", "cycle", cycle.id,
               f"{len(tasks)} task(s) over {len(allowed)} target(s)"
               + (f"; refused {len(refused)}" if refused else ""))
    session.commit()
    return {"data": {"mission": _mission_data(mission, tasks=len(tasks)),
                     "tasks": [_task_data(task, events=0) for task in tasks],
                     "targets": [t["value"] for t in allowed],
                     "refused": refused, "skipped": skipped, "gaps": gaps,
                     # What the run was aimed at, so the screen can say "3 advisories
                     # on 2 deployed versions" instead of implying it guessed.
                     "briefing": briefing}}

def _candidate_from_task(session: Session, task: models.AgentTask) -> models.Candidate | None:
    """Turn a finished task into a candidate, with the evidence that proves it.

    The candidate is the claim plus the observations that back it: every `tool`
    event names a URL, the `observation` right after it carries the status line.
    A candidate without a locator cannot be confirmed by the gate chain, which is
    why the locator travels on the observation and not in the model's prose.
    """
    from backend.app.harness import evidence as harness_evidence

    events = (session.query(models.AgentTaskEvent).filter_by(task_id=task.id)
              .order_by(models.AgentTaskEvent.seq).all())
    final = next((row for row in reversed(events) if row.kind == "final"), None)
    if final is None:
        return None
    payload = json.loads(final.payload or "{}")
    answer = str(payload.get("answer") or payload.get("verdict") or "").strip()
    if not answer:
        return None

    items, pairs, argv_now = [], [], None
    for event in events:
        body = json.loads(event.payload or "{}")
        if event.kind == "tool":
            argv_now = body.get("argv") or []
        elif event.kind == "observation" and argv_now:
            head = str(body.get("head") or "").splitlines()
            statement = (head[0] if head else "no answer").strip()[:300]
            url = next((arg for arg in argv_now if isinstance(arg, str)
                        and arg.startswith(("http://", "https://"))), None)
            if url:
                items.append(harness_evidence.Evidence("observation", statement, url))
                pairs.append((argv_now, statement, url))
            argv_now = None
    if not items:
        # No readable exchange: the answer is an assumption and the gates will say
        # so out loud instead of the row looking like proof.
        items = [harness_evidence.Evidence("assumption", answer[:1000])]

    # The request Repeat will re-send: the one that proves the claim and can be
    # re-sent as it stands. A pair that needs a credential minted during the run is
    # not reproducible (the agent's own log redacts it), so a payload that stands
    # alone outranks a chain that would need the session rebuild.
    request = None
    if pairs:
        argv, _statement, url = _decisive_pair(pairs, answer)
        request = _request_from_argv(argv, url)

    title = _claim_title(answer)
    # What the agent actually asserted. A reachability check ("the host is alive and
    # is really Juice Shop") is a perfectly good result and a terrible finding: the
    # queue has to say which of the two it is holding, or a scope validation gets
    # promoted as a HIGH vulnerability and the "usable" badge stops meaning anything.
    claim_kind = _claim_kind(answer)
    envelope = {"evidence": json.loads(harness_evidence.as_json(items)),
                "claim_kind": claim_kind}
    if request:
        envelope["request"] = request
    row = models.Candidate(
        org_id=task.org_id, mission_id=task.mission_id, title=title,
        claim=answer[:8000], evidence=json.dumps(envelope, ensure_ascii=False),
        severity=_severity_hint(answer),
        state="proposed" if claim_kind == "vulnerability" else "rejected")
    session.add(row)
    session.flush()
    return row


def _decisive_pair(pairs, answer: str):
    """Which recorded exchange is the proof, and is still replayable.

    Scoring, not guessing: a payload (non-GET) beats a probe, a request that stands
    without a session beats one carrying a redacted bearer, and a 2xx beats a 4xx.
    The verdict's own text breaks ties, because the agent usually names the path it
    is claiming about.
    """

    def score(pair):
        argv, statement, url = pair
        request = _request_from_argv(argv, url) or {}
        headers = {str(key).lower(): str(value)
                   for key, value in (request.get("headers") or {}).items()}
        points = 0
        if str(request.get("method", "GET")).upper() != "GET":
            points += 4
        if request.get("body"):
            points += 2
        if "authorization" in headers:
            points -= 3
        if "..." in json.dumps(headers):
            points -= 3          # a redacted credential cannot be sent again
        if " 2" in statement:
            points += 1
        # The request has to be about what the claim is about: a claim that quotes
        # `/rest/admin/application-version` is not proved by a login POST, however
        # juicy that POST was. The headline is weighted far above method or body.
        path = urlsplit(url).path or "/"
        if path != "/" and path in headline:
            points += 8
        elif path != "/" and path in answer:
            points += 3
        return points

    # What the claim talks about first is what it is about: the earliest path the
    # answer names, among the exchanges that were actually recorded. Scoring only
    # breaks ties — a login POST that answered 200 outranked the version endpoint the
    # claim was quoting, and the finding pointed at the wrong request.
    named = []
    for pair in pairs:
        path = urlsplit(pair[2]).path or "/"
        if path == "/":
            continue
        at = (answer or "").find(path)
        if at >= 0:
            named.append((at, pair))
    if named:
        named.sort(key=lambda item: item[0])
        return named[0][1]
    return max(pairs, key=score)


#: A claim is a vulnerability when the words it uses are about breaking something.
#: Detection by vocabulary is coarse on purpose: the cost of a false negative here is
#: an operator reading one extra row, the cost of a false positive is a fabricated
#: finding, which is the one thing this platform must never produce.
_VULNERABILITY_WORDS = (
    "bypass", "injection", "sqli", "xss", "ssrf", "lfi", "rfi", "traversal",
    "idor", "rce", "takeover", "escalation", "exfiltration", "exfiltrate",
    "deserialization", "csrf", "open redirect", "unauthorized access",
    "unauthenticated", "leak", "disclosure", "exposed", "misconfiguration",
    "weak password", "default credential", "token forgery", "alg:none",
    "missing authorization", "broken access", "privilege",
)
_REACHABILITY_WORDS = (
    "scope claim", "scope validation", "reachable", "is live", "no vulnerab",
    "nothing exploitable", "no finding", "not vulnerable", "sin hallazgos",
)


_VERDICT_LINE = re.compile(r"^\s*[*_`]*verdict[*_`]*\s*[:—\-]\s*(.+)$", re.I | re.M)
_NEGATIVE_VERDICT = ("not vulnerable", "no vulnerable", "no exploit", "nothing exploit",
                     "inconclusive", "none", "false positive", "no weakness")


def _claim_kind(answer: str) -> str:
    """`vulnerability` or `observation`, from what the answer asserts.

    The agent is asked to close with `VERDICT: …` and that line wins, because reading
    prose is how "no SQL injection found" became an SQL injection finding: the word is
    there, the claim is the opposite of it. Without the line the sentences are read
    one by one and a negated sentence is skipped rather than counted.
    """
    text = answer or ""
    for match in _VERDICT_LINE.finditer(text):
        line = match.group(1).strip().lower()
        if any(bad in line for bad in _NEGATIVE_VERDICT):
            return "observation"
        if (any(word in line for word in _VULNERABILITY_WORDS)
                or "vulnerable" in line or "exploitable" in line):
            return "vulnerability"
        return "observation"
    for sentence in re.split(r"(?<=[.!?])\s+", text):
        low = sentence.lower()
        if any(neg in low for neg in ("no ", "not ", "n't ", "cannot", "unable",
                                      "ruled out", "without ", "sin ")):
            continue
        if any(word in low for word in _VULNERABILITY_WORDS):
            return "vulnerability"
    if any(word in text.lower() for word in _REACHABILITY_WORDS):
        return "observation"
    # Unclassified: the gates still have to prove it, and they are the stronger test.
    return "vulnerability"


def _severity_hint(answer: str) -> str:
    text = (answer or "").lower()
    if any(word in text for word in ("takeover", "rce", "remote code", "admin",
                                     "mass", "exfiltration")):
        return "critical"
    if any(word in text for word in _VULNERABILITY_WORDS):
        return "high"
    return "medium"


def _claim_title(answer: str, limit: int = 200) -> str:
    """The verdict as a title: markdown stripped, headings dropped.

    The first line of a field agent's answer is usually `## Deliverable`; using it
    as the finding's title makes every autonomous finding look the same.
    """
    skipped = ("deliverable", "summary", "conclusion", "resumen", "entregable",
               "findings", "hallazgos", "recommendation", "recomendación",
               "what i tried", "what i did", "lo que probé", "lo que hice",
               "recap", "overview")
    # Narration about the run is not a claim about the target: "I have enough to
    # close this out" says nothing a reader can act on.
    narration = ("i have enough", "here is what", "what i actually", "closing with",
                 "i'm now being", "i am now being", "let me", "tengo suficiente",
                 "acá está lo que", "voy a ")
    for raw in answer.splitlines():
        line = raw.strip().lstrip("#").strip()
        line = line.replace("**", "").replace("`", "").strip()
        bare = line.lower().rstrip(":.")
        if len(line) <= 12 or bare in skipped:
            continue
        if any(line.lower().startswith(phrase) for phrase in narration):
            continue
        return " ".join(line.split())[:limit]
    return " ".join(answer.split())[:limit]


def _request_from_argv(argv: list, url: str) -> dict | None:
    """The HTTP request a `curl` invocation carried, as a chain step.

    This is the bridge the whole feature rests on: the agent's own tool call is
    what Repeat re-sends, so nobody has to retype the payload that proved it.
    """
    if not argv:
        return None
    method, headers, body = "GET", {}, None
    flags = {"-X": "method", "--request": "method", "-H": "header",
             "--header": "header", "-d": "body", "--data": "body",
             "--data-raw": "body", "--json": "body"}
    index = 0
    while index < len(argv):
        token = str(argv[index])
        target = flags.get(token)
        if target and index + 1 < len(argv):
            value = str(argv[index + 1])
            if target == "method":
                method = value.upper()
            elif target == "header":
                name, _, header_value = value.partition(":")
                if name.strip():
                    headers[name.strip()] = header_value.strip()
            elif target == "body":
                body = value
            index += 2
            continue
        index += 1
    step = {"label": "the request that proved it", "method": method, "url": url}
    if headers:
        step["headers"] = headers
    if body:
        step["body"] = body
    return step


class PromoteIn(BaseModel):
    validate: bool = True
    cycle_id: str | None = None
    severity: str | None = None
    #: Blank is fine: the request carries a credential, so the audit row names the
    #: caller from the token instead of failing validation with "at least 1
    #: character" — an error about a label, on a click that had everything else.
    actor: str = Field(default="", max_length=255)
    #: A run that confirmed reachability and nothing exploitable is still evidence a
    #: person may want to keep. Refusing the human is not the gate's job; the gate's
    #: job is to stop the record from claiming an exploit that did not happen — so it
    #: is kept as an `exposure`, never as a vulnerability.
    accept_observation: bool = False


@router.post("/candidates/{candidate_id}/promote", status_code=status.HTTP_201_CREATED)
def promote_candidate(candidate_id: str, payload: PromoteIn = None,
                      principal: dict = Depends(authz.principal),
                      org: models.Organization = Depends(auth.require_org),
                      session: Session = Depends(get_session)):
    """Settle a candidate and, when it stands, write the finding.

    A candidate is a proposal. This runs the gate chain (replay, then the sibling
    probe), and only a claim that survives becomes a finding — with the mission,
    task and candidate ids attached, so the finding page can show the trace that
    produced it instead of a verdict with no story.
    """
    from backend.app.harness import evidence as harness_evidence
    from backend.app.harness import gates as harness_gates

    payload = payload or PromoteIn()
    actor = (payload.actor or "").strip() or authz.actor_of(principal)
    row = session.get(models.Candidate, candidate_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "candidate not found")
    try:
        envelope = json.loads(row.evidence or "{}")
    except ValueError:
        envelope = {}
    # What the human said wins over the classifier: clicking "accept as observation"
    # on a claim the envelope called a vulnerability files an exposure, because the
    # record has to match the decision, not the heuristic that came before it.
    observation = (payload.accept_observation
                   or (isinstance(envelope, dict)
                       and envelope.get("claim_kind") == "observation"))
    if observation and not payload.accept_observation:
        # Nothing to promote as a vulnerability: the run confirmed reachability. The
        # screen offers the override, and taking it files an exposure instead.
        row.state = "rejected"
        session.commit()
        return {"data": {"promoted": False, "candidate_state": row.state,
                         "observation": True,
                         "reason": "the run confirmed reachability, not an "
                                   "exploitable condition — accept it as an "
                                   "observation to keep the evidence"}}

    items = harness_evidence.normalize(row.evidence)
    if not harness_evidence.confirmable(items):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "the candidate names no locator: there is nothing to reproduce, so it "
            "cannot be promoted")

    gates = None
    #: The exchange that satisfied the gate. The same request/response is what the
    #: finding keeps: re-deriving it afterwards would store a proof nobody verified.
    captured: dict = {}
    if payload.validate:
        from backend.app.routers import agents as agents_router

        def replay(*, finding_id=None, target=None, expect=None, request=None, **_):
            """Re-send what the claim points at.

            A candidate that came from a scanner finding replays that finding's
            stored request; one that came from a field agent replays the agent's own
            tool call (the exact method, headers and body it used), which is why the
            candidate carries `request` in its envelope.
            """
            if finding_id:
                return agents_router.replay_request(
                    finding_id=finding_id, target=target, expect=expect,
                    org=org, session=session).get("data", {})
            if not request:
                return {"state": "blocked", "missing": ["request"]}
            from backend.app import repeat as repeat_engine

            try:
                # The grant is issued to the agent identity, not to the person who
                # pressed the button: the human approved the mission, the machine
                # holds the intrusive_testing grant the replay needs.
                outcome = repeat_engine.run(session, org, [request],
                                            actor=actor,
                                            principal="agents")
            except repeat_engine.ChainError as error:
                return {"state": "blocked", "missing": [str(error)]}
            step = (outcome.get("steps") or [{}])[-1]
            state = {"ok": "reproduced", "denied": "denied",
                     "error": "failed"}.get(outcome.get("result"), "observed")
            if state in {"reproduced", "observed"} and "exchange" not in captured:
                captured["exchange"] = step
            return {"state": state, "response": {"status": step.get("status")},
                    "error": outcome.get("error"),
                    "authorized": step.get("authorized")}

        def sibling(*, finding_id, label_a, label_b, owner_marker=None):
            return agents_router.probe_sibling(
                agents_router.SiblingIn(finding_id=finding_id, label_a=label_a,
                                        label_b=label_b, owner_marker=owner_marker),
                org=org, session=session).get("data", {})

        gates = harness_gates.run_chain(session, org, row, replay=replay,
                                        sibling=sibling)
        session.flush()
        if row.state == "refuted":
            session.commit()
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                {"message": "the claim did not survive the gates; it is not a finding",
                 "state": row.state, "gates": gates})

    locator = next((item.locator for item in items
                    if item.stance == "observation" and item.locator), None)
    # The decisive request names the endpoint the finding is about; the first
    # observation is usually the homepage the agent opened with.
    proven = (envelope.get("request") or {}) if isinstance(envelope, dict) else {}
    target_url = proven.get("url") or locator or ""
    asset = None
    if target_url:
        # The asset that owns this endpoint: the URL itself, then its host. Looking
        # only for a *domain* asset left every finding of a URL asset (the practice
        # target, a host declared as a URL) without a project — the finding existed
        # and belonged to nobody.
        asset = (session.query(models.Asset)
                 .filter_by(org_id=org.id, type="url", value=target_url).one_or_none())
        host = target_url.split("//")[-1].split("/")[0].split(":")[0].lower()
        if asset is None:
            asset = (session.query(models.Asset)
                     .filter_by(org_id=org.id, type="domain", value=host).one_or_none())
        if asset is None:
            asset = (session.query(models.Asset)
                     .filter(models.Asset.org_id == org.id,
                             models.Asset.value.like(f"%{host}%"))
                     .first())
    # An exposure is not a vulnerability: it enters the queue as `low` unless the
    # person promoting it says otherwise, so a reachability check does not compete
    # with real CVEs for attention.
    severity = (payload.severity
                or ("low" if observation else row.severity or "HIGH")).upper()
    fingerprint = hashlib.sha256(
        f"{org.id}|agent|{row.id}|{target_url}".encode()).hexdigest()
    finding = models.Finding(
        org_id=org.id, project_id=asset.project_id if asset else None,
        asset_id=asset.id if asset else None,
        agent_mission_id=row.mission_id, agent_candidate_id=row.id,
        # An accepted observation is an exposure, not a vulnerability: the record has
        # to say which of the two it holds.
        kind="exposure" if observation else "vulnerability",
        vector="network", fingerprint=fingerprint,
        source="shauron:ai", origin="shauron-ai",
        title=(row.title or "autonomous finding")[:1024],
        detail=json.dumps({"claim": row.claim,
                           "evidence": [{"stance": i.stance, "statement": i.statement,
                                         "locator": i.locator} for i in items],
                           "gates": gates}, ensure_ascii=False)[:8000],
        severity=severity, url=target_url or None,
        # The finding answers "what do I replay": the method and path of the request
        # that proved it, not a bare host. Without them the Repeat tab opens on
        # `GET —` and the file reads like a claim nobody can act on.
        http_method=(envelope.get("request") or {}).get("method") if isinstance(envelope, dict) else None,
        endpoint=_endpoint_of(target_url),
        # The exact request that proved it, in the shape the Repeat panel reads:
        # without the body a POST replay reaches an endpoint that needs a payload and
        # answers 401, which reads like a bad finding instead of a missing field.
        proof_request=_proof_text(proven, target_url),
        # The response the gate actually got. A finding that keeps the payload and not
        # the answer reads as a claim: nobody can tell the 200 with the catalogue from
        # a 401 without replaying it themselves.
        proof_response=_response_text(captured.get("exchange")),
        status="open",
        evidence_level="observed",
        exploit_state=("observed" if observation
                       else "reproduced" if row.state == "validated" else "attempted"))
    # The task id lives on the candidate's mission; the newest finished task is the
    # one that spoke, and it is the one whose trace the finding must open.
    task = (session.query(models.AgentTask)
            .filter_by(mission_id=row.mission_id, status="done")
            .order_by(models.AgentTask.finished_at.desc()).first())
    finding.agent_task_id = task.id if task else None
    session.add(finding)
    session.flush()
    # The click that promoted it *is* the confirmation, and it goes through the one
    # decision writer: `validate` → triage `triaged`. A hand-written "confirmed" is
    # outside the vocabulary the screens and counts read, so it rendered raw and only
    # looked settled because it was not "new".
    decisions.apply(session, org, finding, "validate", actor)
    # The candidate has to point at its finding, or the review queue keeps offering
    # "promote" on a claim that already became one — a second click, a second finding.
    row.finding_id = finding.id
    row.state = "validated"
    # Which campaign this finding belongs to. The screen that promotes it may not
    # know (the queue can be opened on its own), so the mission is asked: it recorded
    # its cycle when it was dispatched. Without this a validated finding existed but
    # never appeared in the cycle's outcome — the campaign looked like it produced
    # nothing.
    cycle_id = payload.cycle_id
    if not cycle_id and row.mission_id:
        mission = session.get(models.AgentMission, row.mission_id)
        if mission is not None:
            try:
                cycle_id = (json.loads(mission.evidence or "{}") or {}).get("cycle_id")
            except ValueError:
                cycle_id = None
    if cycle_id:
        cycle = session.get(models.Cycle, cycle_id)
        if cycle is not None and cycle.org_id == org.id:
            linked = (session.query(models.CycleFinding)
                      .filter_by(cycle_id=cycle.id, finding_id=finding.id).one_or_none())
            if linked is None:
                session.add(models.CycleFinding(
                    org_id=org.id, cycle_id=cycle.id, finding_id=finding.id,
                    source="agent"))
    _audit_log(session, org.id, actor, "agent.candidate_promoted",
               "finding", finding.id,
               f"{row.id} → {finding.severity} {finding.title[:80]}")
    session.commit()
    return {"data": {"promoted": True, "finding_id": finding.id,
                     "candidate_state": row.state, "gates": gates,
                     "severity": finding.severity, "url": finding.url}}


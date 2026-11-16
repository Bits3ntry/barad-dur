"""The agent catalogue, and the thread that renders a run as people talking.

Two rules this file follows, because they are what keep the thread honest:

* **The thread is a projection.** Nothing is stored twice: chat turns, model steps and
  catalogue events are read and merged by time. A thread that kept its own copy would
  drift from the ledger within a week.
* **A spec declares tools; it does not invent them.** `validate.finding` shipped as
  `draft` naming field tools that do not exist yet, and the API reports `tools_missing`
  instead of offering a screen that cannot work.
"""
from __future__ import annotations

import hashlib
import json
import os
from urllib.parse import urlsplit

import httpx
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models, secrets as secret_store
from backend.app import severity as severity_vocab
from backend.app.ai import tools as catalog
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1", tags=["agents"])

CLASSES = {"orchestrator", "analyst", "query", "field"}
STATUSES = {"draft", "active", "archived"}


def _aware(value):
    """SQLite hands back naive datetimes; `models.utcnow()` is aware."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _json_list(value: str | None) -> list:
    try:
        parsed = json.loads(value or "[]")
    except ValueError:
        return []
    # A field agent's candidate is stored as an envelope (`evidence` + `request` +
    # `expect`), so the list read the wrong shape and every agent candidate looked
    # like it carried no proof at all.
    if isinstance(parsed, dict):
        parsed = parsed.get("evidence")
    return parsed if isinstance(parsed, list) else []


def _spec_data(row: models.AgentSpec) -> dict:
    tools = [str(name) for name in _json_list(row.tools)]
    known = set(catalog.BY_NAME)
    return {
        "id": row.id, "name": row.name, "slug": row.slug,
        "class": row.agent_class, "description": row.description,
        "avatar": row.avatar, "color": row.color,
        "tools": tools,
        # Declared and not yet real is a state worth naming: it is what `draft` means.
        "tools_missing": [name for name in tools if name not in known],
        "must_return": _json_list(row.must_return),
        "tech_affinity": _json_list(row.tech_affinity),
        "status": row.status,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


class SpecIn(BaseModel):
    name: str = Field(min_length=2, max_length=64)
    slug: str = Field(min_length=2, max_length=64, pattern=r"^[a-z0-9._-]+$")
    agent_class: str = Field(default="analyst")
    description: str | None = None
    avatar: str | None = Field(default=None, max_length=8)
    color: str | None = Field(default=None, max_length=16)
    tools: list[str] = Field(default_factory=list)
    must_return: list[str] = Field(default_factory=list)
    tech_affinity: list[str] = Field(default_factory=list)
    status: str = Field(default="draft")


class SpecPatch(BaseModel):
    name: str | None = None
    # The catalogue's editor changes what an agent is; a class that could only be
    # set at creation made "this analyst is really a field agent" unfixable.
    agent_class: str | None = None
    description: str | None = None
    avatar: str | None = None
    color: str | None = None
    tools: list[str] | None = None
    must_return: list[str] | None = None
    tech_affinity: list[str] | None = None
    status: str | None = None


def _check(values: dict) -> None:
    if values.get("agent_class") and values["agent_class"] not in CLASSES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"class must be one of {sorted(CLASSES)}")
    if values.get("status") and values["status"] not in STATUSES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"status must be one of {sorted(STATUSES)}")


@router.get("/agents")
def list_agents(q: str | None = Query(default=None),
                status_filter: str | None = Query(default=None, alias="status"),
                agent_class: str | None = Query(default=None),
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    """The catalogue, and the autocomplete behind `@` in the composer.

    Ordered with the orchestrator first: it is the one an operator addresses by
    default, and a list that buries it behind eight specialists is a list that makes
    the wrong mention the easy one.
    """
    rows = session.query(models.AgentSpec).all()
    if status_filter:
        rows = [row for row in rows if row.status == status_filter]
    if agent_class:
        rows = [row for row in rows if row.agent_class == agent_class]
    if q:
        needle = q.strip().lower()
        # Autocomplete matches the name and the slug first: searching descriptions is
        # how typing "@es" matched every agent whose blurb contains "es".
        by_name = [row for row in rows
                   if needle in (row.slug or "").lower()
                   or needle in (row.name or "").lower()]
        rows = by_name or [row for row in rows
                           if needle in (row.description or "").lower()]
    rows.sort(key=lambda row: (row.agent_class != "orchestrator", row.name.lower()))

    # Live counters: a catalogue that cannot say "this one is working right now" is a
    # form, not a team. Two aggregates, no N+1.
    from sqlalchemy import func
    open_rows = (session.query(models.AgentRun.spec_slug, func.count())
                 .filter(models.AgentRun.org_id == org.id)
                 .filter(models.AgentRun.status.in_(["queued", "running",
                                                     "waiting_approval"]))
                 .group_by(models.AgentRun.spec_slug).all())
    spend_rows = (session.query(models.AgentRun.spec_slug, func.sum(models.AgentRun.cost_usd))
                  .filter(models.AgentRun.org_id == org.id)
                  .filter(models.AgentRun.created_at >= models.utcnow().replace(
                      hour=0, minute=0, second=0, microsecond=0))
                  .group_by(models.AgentRun.spec_slug).all())
    active = {slug: count for slug, count in open_rows}
    spend = {slug: float(total or 0) for slug, total in spend_rows}

    data = []
    for row in rows:
        item = _spec_data(row)
        item["active_runs"] = active.get(row.slug, 0)
        item["cost_today_usd"] = round(spend.get(row.slug, 0.0), 4)
        data.append(item)
    return {"data": data, "total": len(data)}


@router.get("/agents/tools")
def list_tools(org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """The tool catalogue a spec may draw from, and who already uses each one."""
    owners: dict[str, list[str]] = {}
    for row in session.query(models.AgentSpec).all():
        for name in _json_list(row.tools):
            owners.setdefault(str(name), []).append(row.slug)
    return {"data": [{
        "name": tool["name"], "summary": tool["summary"],
        "method": tool["method"], "path": tool["path"],
        "params": sorted(tool["params"]),
        "risk": tool.get("risk", "read"), "target_kind": tool.get("target_kind", "none"),
        "used_by": sorted(owners.get(tool["name"], [])),
    } for tool in catalog.TOOLS], "total": len(catalog.TOOLS)}


#: The MCP surface this platform serves, in one read. The console prints it as the
#: connection sheet; the server itself (`mcp/`) imports the same catalogue.
MCP_TOOLS = ("deployment_chain", "exposure_verdict", "barad_tools", "barad_tool")


@router.get("/agents/mcp")
def mcp_sheet(org: models.Organization = Depends(auth.require_org)):
    """Everything an external agent needs to connect, and nothing that is a secret.

    The server runs where the agent runs — stdio in a laptop's client, or hosted with
    the HTTP transport — so the platform's part is the address, the identity and the
    catalogue. The API key is issued from Settings → Service keys and never appears
    here: a sheet that prints a key is a key in a screenshot.
    """
    configured = os.environ.get("PLATFORM_PUBLIC_URL", "").rstrip("/")
    return {"data": {
        "api_url": configured or None,
        "server": {"package": "barad-dur-mcp", "entrypoint": "barad-mcp",
                   "version": "0.1.0", "transports": ["stdio", "sse", "streamable-http"]},
        "instructions": catalog.MCP_INSTRUCTIONS,
        "mcp_tools": list(MCP_TOOLS),
        "catalogue": [{"name": tool["name"], "summary": tool["summary"],
                       "risk": tool.get("risk", "read")} for tool in catalog.TOOLS],
        "key_section": "settings",
    }}


@router.post("/agents", status_code=status.HTTP_201_CREATED)
def create_agent(payload: SpecIn,
                 org: models.Organization = Depends(auth.require_admin),
                 session: Session = Depends(get_session)):
    _check(payload.model_dump())
    if session.query(models.AgentSpec).filter_by(slug=payload.slug).one_or_none():
        raise HTTPException(status.HTTP_409_CONFLICT, "an agent with that slug exists")
    row = models.AgentSpec(
        name=payload.name, slug=payload.slug, agent_class=payload.agent_class,
        description=payload.description, avatar=payload.avatar, color=payload.color,
        tools=json.dumps(payload.tools), must_return=json.dumps(payload.must_return),
        tech_affinity=json.dumps(payload.tech_affinity), status=payload.status)
    session.add(row)
    _audit_log(session, org.id, "console", "agent.created", "agent_spec", row.id,
               payload.slug)
    session.commit()
    return {"data": _spec_data(row)}


@router.patch("/agents/{agent_id}")
def patch_agent(agent_id: str, payload: SpecPatch,
                org: models.Organization = Depends(auth.require_admin),
                session: Session = Depends(get_session)):
    row = session.get(models.AgentSpec, agent_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    _check(payload.model_dump())
    changed = payload.model_dump(exclude_none=True)
    for field in ("name", "description", "avatar", "color", "status", "agent_class"):
        if field in changed:
            setattr(row, field, changed[field])
    for field in ("tools", "must_return", "tech_affinity"):
        if field in changed:
            setattr(row, field, json.dumps(changed[field]))
    row.updated_at = models.utcnow()
    _audit_log(session, org.id, "console", "agent.updated", "agent_spec", row.id,
               ",".join(sorted(changed)))
    session.commit()
    return {"data": _spec_data(row)}


# ────────────────────────────── the thread ──────────────────────────────────

def _turn_event(turn: models.ChatTurn, session: Session,
                specs: dict[str, models.AgentSpec]) -> list[dict]:
    author = turn.profile_key or ("you" if turn.role == "user" else turn.role)
    spec = specs.get(author)
    at = (turn.created_at or models.utcnow()).isoformat()
    events = [{
        "id": turn.id, "at": at, "kind": "message", "author": author,
        "author_name": spec.name if spec else ("You" if author == "you" else author),
        "avatar": spec.avatar if spec else ("🙋" if author == "you" else "🐴"),
        "color": spec.color if spec else None,
        "body": turn.content, "citations": _json_list(turn.citations),
        "run_id": turn.run_id, "tokens": turn.tokens,
    }]
    if turn.run_id:
        steps = (session.query(models.AiStep).filter_by(run_id=turn.run_id)
                 .order_by(models.AiStep.seq).all())
        for step in steps:
            events.append({
                "id": step.id, "at": at, "kind": "step",
                "author": step.role, "author_name": step.role,
                "avatar": "⚙️", "color": None, "body": None,
                "tools": _json_list(step.tool_calls), "handoff": step.handoff,
                "tokens_in": step.tokens_in, "tokens_out": step.tokens_out,
                "run_id": turn.run_id, "seq": step.seq,
            })
    return events


@router.get("/agents/threads")
def list_threads(org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """Every place a conversation exists: chat sessions and missions, one shape."""
    threads = []
    for row in (session.query(models.ChatSession).filter_by(org_id=org.id)
                .order_by(models.ChatSession.last_turn_at.desc()).all()):
        turns = (session.query(models.ChatTurn).filter_by(session_id=row.id).count())
        threads.append({
            "thread": f"chat:{row.id}", "kind": "chat", "id": row.id,
            "title": row.title or "New conversation", "status": row.status,
            "turns": turns,
            "last_at": row.last_turn_at.isoformat() if row.last_turn_at else None,
        })
    for row in (session.query(models.AgentMission).filter_by(org_id=org.id)
                .order_by(models.AgentMission.created_at.desc()).all()):
        threads.append({
            "thread": f"mission:{row.id}", "kind": "mission", "id": row.id,
            "title": row.goal, "status": row.status, "turns": 0,
            "last_at": row.created_at.isoformat() if row.created_at else None,
        })
    # A finding that has been probed has a thread of its own: the evidence and every
    # replay. Only probed ones are listed — 300 unrelated findings are not a list.
    probed = (session.query(models.AgentEvent.thread, models.AgentEvent.created_at)
              .filter_by(org_id=org.id)
              .filter(models.AgentEvent.thread.like("finding:%"))
              .order_by(models.AgentEvent.created_at.desc()).all())
    seen: set[str] = set()
    for thread, at in probed:
        if thread in seen:
            continue
        seen.add(thread)
        finding = session.get(models.Finding, thread.split(":", 1)[1])
        if finding is None:
            continue
        events = (session.query(models.AgentEvent).filter_by(thread=thread).count())
        threads.append({
            "thread": thread, "kind": "finding", "id": finding.id,
            "title": finding.title or f"finding {finding.id}",
            "status": finding.status, "turns": events,
            "last_at": at.isoformat() if at else None,
        })
    threads.sort(key=lambda row: row["last_at"] or "", reverse=True)
    return {"data": threads, "total": len(threads)}


@router.get("/agents/threads/{thread}/events")
def thread_events(thread: str,
                  author: str | None = Query(default=None),
                  kind: str | None = Query(default=None),
                  limit: int = Query(default=200, ge=1, le=500),
                  offset: int = Query(default=0, ge=0),
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    """The thread, merged from what actually happened.

    Chat turns, the model steps behind each answer, and catalogue events are read in
    time order. `author=<slug>` is how a reader opens "the Palantír thread" without a
    second conversation existing.
    """
    specs = {row.slug: row for row in session.query(models.AgentSpec).all()}
    events: list[dict] = []

    if thread.startswith("chat:"):
        session_id = thread.split(":", 1)[1]
        chat = session.get(models.ChatSession, session_id)
        if chat is None or chat.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "thread not found")
        for turn in (session.query(models.ChatTurn).filter_by(session_id=session_id)
                     .order_by(models.ChatTurn.seq).all()):
            events.extend(_turn_event(turn, session, specs))
    elif thread.startswith("mission:"):
        mission_id = thread.split(":", 1)[1]
        mission = session.get(models.AgentMission, mission_id)
        if mission is None or mission.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "thread not found")
    elif thread.startswith("finding:"):
        # A finding has a thread too: the evidence it was born with, and every replay
        # an agent has run against it. Without this, "validate it" leaves no place to
        # read the answer.
        finding_id = thread.split(":", 1)[1]
        finding = session.get(models.Finding, finding_id)
        if finding is None or finding.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "thread not found")
        for occurrence in (session.query(models.Occurrence)
                           .filter_by(org_id=org.id, finding_id=finding_id)
                           .order_by(models.Occurrence.seen_at).all()):
            if not occurrence.evidence:
                continue
            events.append({
                "id": occurrence.id,
                "at": (occurrence.seen_at or models.utcnow()).isoformat(),
                "kind": "evidence", "author": "you", "author_name": "You",
                "avatar": "🙋", "color": None,
                "body": occurrence.evidence[:1200],
                "refs": [finding_id],
            })
    else:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "thread must be chat:<id>, mission:<id> or finding:<id>")
    for row in (session.query(models.AgentEvent)
                .filter_by(org_id=org.id, thread=thread)
                .order_by(models.AgentEvent.seq).all()):
        spec = specs.get(row.author_spec or "")
        events.append({
            "id": row.id, "at": (row.created_at or models.utcnow()).isoformat(),
            "kind": row.kind, "author": row.author_spec or "you",
            "author_name": spec.name if spec else (row.actor or "You"),
            "avatar": spec.avatar if spec else "🙋",
            "color": spec.color if spec else None,
            "body": row.body, "refs": _json_list(row.refs),
            "run_ref": getattr(row, "run_ref", None),
            "reply_to": getattr(row, "reply_to", None),
        })

    # The thread is three sources, not one: catalogue events above, the field's own
    # task stream, and the messages agents send each other. A run is only readable if
    # all three land in the same timeline.
    if thread.startswith("mission:"):
        mission_id = thread.split(":", 1)[1]
        task_ids = [row.id for row in session.query(models.AgentTask)
                    .filter_by(org_id=org.id, mission_id=mission_id).all()]
        if task_ids:
            for row in (session.query(models.AgentTaskEvent)
                        .filter(models.AgentTaskEvent.task_id.in_(task_ids))
                        .order_by(models.AgentTaskEvent.created_at).all()):
                events.append({
                    "id": row.id,
                    "at": (row.created_at or models.utcnow()).isoformat(),
                    "kind": "field" if row.kind != "final" else "status",
                    "author": "field", "author_name": "Field",
                    "avatar": "🛠️", "color": None,
                    "body": (row.payload or "")[:1200],
                    "refs": [row.task_id], "tool": row.tool,
                    "run_ref": row.task_id, "reply_to": None,
                })

    for row in (session.query(models.AgentMessage)
                .filter_by(org_id=org.id, mission_id=(thread.split(":", 1)[1]
                                                      if thread.startswith("mission:") else None))
                .order_by(models.AgentMessage.created_at).all()
                if thread.startswith("mission:") else []):
        sender = specs.get(row.to_spec or "")
        events.append({
            "id": row.id, "at": (row.created_at or models.utcnow()).isoformat(),
            "kind": "message", "author": row.from_run or "you",
            "author_name": sender.name if sender else (row.from_run or "You"),
            "avatar": sender.avatar if sender else "💬", "color": sender.color if sender else None,
            "body": row.body, "refs": [row.to_run] if row.to_run else [],
            "run_ref": row.from_run, "reply_to": row.reply_to,
            "to": row.to_run or row.to_spec,
            "delivered": row.delivered_at is not None,
        })

    if author:
        events = [event for event in events if event.get("author") == author]
    if kind:
        events = [event for event in events if event.get("kind") == kind]
    events.sort(key=lambda event: (event.get("at") or "", event.get("seq") or 0))
    return {"data": events[offset:offset + limit], "total": len(events),
            "thread": thread}


class EventIn(BaseModel):
    body: str = Field(min_length=1, max_length=8000)
    kind: str = Field(default="note")
    refs: list[str] = Field(default_factory=list)
    author_spec: str | None = None


@router.post("/agents/threads/{thread}/events", status_code=status.HTTP_201_CREATED)
def append_event(thread: str, payload: EventIn,
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """A note, a decision or a pin written into the thread by a human or a run."""
    last = (session.query(models.AgentEvent)
            .filter_by(thread=thread).order_by(models.AgentEvent.seq.desc())
            .first())
    row = models.AgentEvent(
        org_id=org.id, thread=thread, seq=(last.seq + 1) if last else 1,
        author_spec=payload.author_spec, actor="console", kind=payload.kind,
        body=payload.body, refs=json.dumps(payload.refs))
    session.add(row)
    session.commit()
    return {"data": {"id": row.id, "thread": thread, "seq": row.seq,
                     "kind": row.kind, "body": row.body}}


# ───────────────────── the entry: authorized domains ────────────────────────

@router.get("/agents/targets")
def authorized_targets(org: models.Organization = Depends(auth.require_org),
                       session: Session = Depends(get_session)):
    """What the field may touch, and under which grant.

    A target is not a URL the agent types: it is a row here, written when an
    administrator approved a grant. Everything downstream (a task, a probe, a replay)
    resolves its host through this list, so a domain that is not here has no route —
    the guarantee is the absence of the row, not a line in a prompt.
    """
    rows = []
    grants = (session.query(models.ScanGrant)
              .filter(models.ScanGrant.org_id == org.id,
                      models.ScanGrant.status == "active")
              .all())
    now = models.utcnow()
    for grant in grants:
        expires = _aware(grant.valid_until)
        expired = bool(expires and expires < now)
        asset = session.get(models.Asset, grant.asset_id) if grant.asset_id else None
        open_findings = 0
        if asset is not None:
            open_findings = (session.query(models.Finding)
                             .filter_by(org_id=org.id, asset_id=asset.id)
                             .filter(models.Finding.status.in_(["open", "acknowledged"]))
                             .count())
        rows.append({
            "grant_id": grant.id,
            "level": grant.level,
            "capabilities": [part for part in (grant.capabilities or "").split(",")
                             if part],
            "principal": grant.principal,
            "valid_until": expires.isoformat() if expires else None,
            "expired": expired,
            "asset_id": asset.id if asset else None,
            "asset": asset.value if asset else None,
            # A grant created before the asset link existed still names its target:
            # the reader should see the host, not a dash.
            "host": (asset.value if asset else
                     (grant.targets[0].target_value if grant.targets else None)),
            "findings_open": open_findings,
            "targets": [{"type": target.target_type, "value": target.target_value}
                        for target in grant.targets],
        })
    rows.sort(key=lambda row: (row["expired"], row["asset"] or ""))
    return {"data": rows, "total": len(rows)}


@router.get("/agents/fingerprint")
def asset_fingerprint(asset: str = Query(..., min_length=2,
                                         description="asset id or its value (host)"),
                      org: models.Organization = Depends(auth.require_org),
                      session: Session = Depends(get_session)):
    """What we already know about one target: declared runtime, observations, findings.

    This is the read half of "access a domain to test it": nothing leaves the platform.
    It answers the question a validation starts from — which runtime and which version
    sit behind that host, when it was last observed, and what is open — and it is the
    tool a field agent calls *before* it is allowed to send a request.
    """
    row = session.get(models.Asset, asset)
    if row is None or row.org_id != org.id:
        row = (session.query(models.Asset)
               .filter_by(org_id=org.id, value=asset).one_or_none())
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")

    observations = (session.query(models.Observation)
                    .filter_by(asset_id=row.id)
                    .order_by(models.Observation.observed_at.desc()).limit(30).all())
    # Two anchors, and the difference matters: a host's own findings, plus the open
    # findings of the project it belongs to. A dependency CVE lives on the component,
    # never on the domain row, so an asset-only query answers "0" for a host whose
    # project holds hundreds.
    findings = (session.query(models.Finding)
                .filter_by(org_id=org.id, asset_id=row.id)
                .filter(models.Finding.status.in_(["open", "acknowledged"]))
                .limit(50).all())
    inherited = []
    if row.project_id:
        inherited = (session.query(models.Finding)
                     .filter_by(org_id=org.id, project_id=row.project_id)
                     .filter(models.Finding.status.in_(["open", "acknowledged"]))
                     .filter(models.Finding.asset_id.is_(None))
                     .limit(50).all())

    runtime = []
    if row.project_id:
        versions = (session.query(models.ProjectVersion.id)
                    .filter_by(project_id=row.project_id).all())
        version_ids = [item[0] for item in versions]
        if version_ids:
            links = (session.query(models.VersionComponent, models.Component)
                     .join(models.Component,
                           models.Component.id == models.VersionComponent.component_id)
                     .filter(models.VersionComponent.project_version_id.in_(version_ids))
                     .all())
            seen = set()
            for link, component in links:
                purl = component.purl or ""
                if not purl.startswith(("pkg:docker/", "pkg:generic/")):
                    continue
                key = (purl, component.version)
                if key in seen:
                    continue
                seen.add(key)
                runtime.append({"purl": purl, "name": component.name,
                                "version": component.version})

    return {"data": {
        "asset": {"id": row.id, "value": row.value, "type": row.type,
                  "project_id": row.project_id,
                  "classification": getattr(row, "classification_status", None)},
        "runtime": runtime[:40],
        "observations": [{"kind": item.kind, "at": item.observed_at.isoformat()
                          if item.observed_at else None,
                          "subject": item.subject} for item in observations],
        # Host findings first, then the project's, each worst-first: a list that hides
        # the node2shell row behind fifty Vite advisories is a list nobody reads.
        "findings": sorted(
            [{"id": item.id, "title": item.title, "severity": item.severity,
              "status": item.status, "scope": "asset"} for item in findings]
            + [{"id": item.id, "title": item.title, "severity": item.severity,
                "status": item.status, "scope": "project"} for item in inherited],
            key=lambda row: (row["scope"] != "asset",
                             severity_vocab.rank(row["severity"])))[:50],
    }}


# ───────────────────── probe.replay: the request, re-sent ───────────────────

#: A test hooks the transport; production uses a real client. Nothing else changes.
_TRANSPORT = None
_REPLAY_METHODS = {"GET", "HEAD", "POST"}
_SECRET_HEADERS = {"authorization", "cookie", "x-api-key", "proxy-authorization"}


def _authorized_grant(session: Session, org: models.Organization, host: str):
    """The active grant that covers this host, or `None` (see `harness.targets`)."""
    return targets.authorized_grant(session, org, host)


def _stored_request(session: Session, org: models.Organization, finding) -> str | None:
    """The request as it was captured, from the attachment or the occurrence."""
    if finding.evidence_id:
        attachment = session.get(models.FindingAttachment, finding.evidence_id)
        if attachment and attachment.content:
            return attachment.content
    occurrences = (session.query(models.Occurrence)
                   .filter_by(org_id=org.id, finding_id=finding.id)
                   .order_by(models.Occurrence.seen_at.desc()).all())
    for occurrence in occurrences:
        if occurrence.evidence and "HTTP/" in occurrence.evidence:
            return occurrence.evidence
    return None


def _parse_http(raw: str) -> dict:
    lines = raw.replace("\r\n", "\n").split("\n")
    parts = (lines[0] or "").split()
    if len(parts) < 2:
        raise ValueError("the stored evidence does not start with a request line")
    method, path = parts[0].upper(), parts[1]
    headers: dict[str, str] = {}
    index = 1
    while index < len(lines) and lines[index].strip():
        name, _, value = lines[index].partition(":")
        headers[name.strip()] = value.strip()
        index += 1
    body = "\n".join(lines[index + 1:]).strip()
    return {"method": method, "path": path, "headers": headers, "body": body}


@router.get("/agents/replay")
def replay_request(finding_id: str = Query(..., min_length=4),
                   target: str | None = Query(default=None),
                   expect: str | None = Query(default=None),
                   org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    """Re-send the request a finding was recorded with, and nothing else.

    The guardrails are structural, not prompt-level:

    * the finding must exist in this org and carry a **stored request** — a finding
      without one is `blocked`, never an improvised probe;
    * the host must resolve through an **active, unexpired grant** (`*.domain` counts);
    * the method is GET/HEAD/POST, redirects are not followed, and credential headers
      captured from the operator are dropped rather than replayed;
    * the result is written as an `agent_event` artefact on the finding's thread, so
      "what was sent" is a row.

    `expect` is the operator's marker: when given, its presence in the response is what
    makes the state `reproduced`. Without it the answer is `observed` — a response is
    not proof that the weakness survived.
    """
    finding = session.get(models.Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")

    raw = _stored_request(session, org, finding)
    if not raw:
        return {"data": {"state": "blocked", "finding_id": finding.id,
                         "missing": ["stored request"],
                         "why": "this finding has no captured request, so there is "
                                "nothing to replay; validate needs evidence, not a "
                                "guess"}}

    try:
        parsed = _parse_http(raw)
    except ValueError as error:
        return {"data": {"state": "blocked", "finding_id": finding.id,
                         "missing": ["readable request"],
                         "why": str(error)}}

    if parsed["method"] not in _REPLAY_METHODS:
        return {"data": {"state": "blocked", "finding_id": finding.id,
                         "missing": [f"method {parsed['method']} is not replayable"],
                         "why": "only GET, HEAD and POST are replayed"}}

    host = (parsed["headers"].get("Host") or parsed["headers"].get("host") or "")
    host = host.split(":")[0].lower()
    if target:
        host = urlsplit(target if "://" in target else f"http://{target}").hostname or host
    if not host:
        return {"data": {"state": "blocked", "finding_id": finding.id,
                         "missing": ["host"],
                         "why": "the stored request does not name a host"}}

    grant = _authorized_grant(session, org, host)
    if grant is None:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            f"{host} is not covered by an active grant; a probe without a grant is "
            "not in the envelope")

    sent_headers = {name: value for name, value in parsed["headers"].items()
                    if name.lower() not in _SECRET_HEADERS
                    and name.lower() not in {"host", "content-length"}}
    url = f"http://{host}{parsed['path']}"
    started = models.utcnow()
    client = (httpx.Client(transport=_TRANSPORT, timeout=10.0,
                           follow_redirects=False) if _TRANSPORT
              else httpx.Client(timeout=10.0, follow_redirects=False))
    try:
        response = client.request(parsed["method"], url, headers=sent_headers,
                                  content=parsed["body"] or None)
    except httpx.HTTPError as error:
        return {"data": {"state": "blocked", "finding_id": finding.id,
                         "missing": ["connection"],
                         "why": f"the target did not answer: {type(error).__name__}"}}
    finally:
        client.close()

    body = response.text[:4000]
    digest = hashlib.sha256(body.encode()).hexdigest()[:16]
    if expect:
        state = "reproduced" if expect.lower() in body.lower() else "not_reproduced"
    else:
        state = "observed"

    artifact = {
        "finding_id": finding.id, "grant_id": grant.id, "host": host,
        "method": parsed["method"], "path": parsed["path"],
        "status": response.status_code, "body_sha256_16": digest,
        "body_excerpt": body[:600], "at": models.utcnow().isoformat(),
    }
    last = (session.query(models.AgentEvent)
            .filter_by(thread=f"finding:{finding.id}")
            .order_by(models.AgentEvent.seq.desc()).first())
    session.add(models.AgentEvent(
        org_id=org.id, thread=f"finding:{finding.id}",
        seq=(last.seq + 1) if last else 1, author_spec="validate.finding",
        actor="console", kind="artifact", body=json.dumps(artifact),
        refs=json.dumps([finding.id, grant.id])))
    session.commit()

    return {"data": {
        "state": state,
        "finding_id": finding.id,
        "grant": {"id": grant.id, "level": grant.level,
                  "valid_until": grant.valid_until.isoformat()
                  if grant.valid_until else None},
        "request": {"method": parsed["method"], "url": url,
                    "headers": sorted(sent_headers), "body_chars": len(parsed["body"]),
                    "dropped_headers": sorted(name for name in parsed["headers"]
                                              if name.lower() in _SECRET_HEADERS)},
        "response": {"status": response.status_code,
                     "content_type": response.headers.get("content-type"),
                     "chars": len(response.text), "body": body},
        "expect": expect,
        "artifact": artifact,
        "took_ms": int((models.utcnow() - started).total_seconds() * 1000),
    }}


# ─────────────────── runs, messages, artifacts, candidates ───────────────────

from backend.app.harness import budgets as harness_budgets
from backend.app.harness import evidence as harness_evidence
from backend.app.harness import gates as harness_gates
from backend.app.harness import policy as harness_policy
from backend.app.harness import runs as harness_runs
from backend.app.harness import sibling as harness_sibling
from backend.app.harness import targets


class RunIn(BaseModel):
    spec_slug: str = Field(min_length=2, max_length=64)
    goal: str = Field(min_length=3, max_length=8000)
    mission_id: str | None = None
    parent_run_id: str | None = None
    thread: str | None = None
    max_turns: int | None = Field(default=None, ge=0, le=200)
    cost_ceiling_usd: float | None = Field(default=None, ge=0, le=1000)


class MessageIn(BaseModel):
    body: str = Field(min_length=1, max_length=8000)
    from_run: str | None = None
    to_run: str | None = None
    to_spec: str | None = None
    mission_id: str | None = None
    reply_to: str | None = None
    kind: str = Field(default="message", max_length=24)


class ArtifactIn(BaseModel):
    kind: str = Field(max_length=32)
    sha256: str | None = Field(default=None, max_length=64)
    bytes: int = Field(default=0, ge=0)
    storage: str | None = Field(default=None, max_length=255)
    meta: dict | list | None = None
    run_id: str | None = None
    task_id: str | None = None
    mission_id: str | None = None


class CandidateIn(BaseModel):
    title: str = Field(min_length=3, max_length=2000)
    severity: str | None = Field(default=None, max_length=16)
    claim: str | None = None
    evidence: list | dict | str | None = None
    finding_id: str | None = None
    run_id: str | None = None
    mission_id: str | None = None


@router.post("/agents/runs", status_code=status.HTTP_201_CREATED)
def create_run(payload: RunIn, org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """Open one agent execution. Everything downstream attributes to this id."""
    spec = session.query(models.AgentSpec).filter_by(slug=payload.spec_slug).one_or_none()
    if spec is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    if spec.status != "active":
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"{spec.slug} is {spec.status}: a draft cannot be dispatched")
    catalogue = list(catalog.BY_NAME)
    effective = harness_policy.effective_tools(session, spec.slug, catalogue=catalogue)
    declared = _json_list(spec.tools)
    refused = [name for name in declared if name not in effective]
    try:
        run = harness_runs.create(
            session, org_id=org.id, spec_slug=spec.slug, goal=payload.goal,
            mission_id=payload.mission_id, parent_run_id=payload.parent_run_id,
            thread=payload.thread or f"run:{payload.parent_run_id or spec.slug}",
            max_turns=payload.max_turns, cost_ceiling_usd=payload.cost_ceiling_usd)
    except ValueError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error))
    session.commit()
    return {"data": {"run": harness_runs.data(session, run),
                     "tools": effective, "tools_refused": refused}}


@router.get("/agents/runs")
def list_runs(mission_id: str | None = Query(default=None),
              thread: str | None = Query(default=None),
              state: str | None = Query(default=None),
              limit: int = Query(default=50, ge=1, le=200),
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    query = session.query(models.AgentRun).filter_by(org_id=org.id)
    if mission_id:
        query = query.filter_by(mission_id=mission_id)
    if thread:
        query = query.filter_by(thread=thread)
    if state:
        query = query.filter_by(status=state)
    rows = query.order_by(models.AgentRun.created_at.desc()).limit(limit).all()
    return {"data": [harness_runs.data(session, row, depth=0) for row in rows],
            "total": len(rows)}


@router.get("/agents/runs/{run_id}")
def get_run(run_id: str, org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    run = session.get(models.AgentRun, run_id)
    if run is None or run.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    payload = harness_runs.data(session, run)
    payload["messages"] = [
        {"id": row.id, "from_run": row.from_run, "to_run": row.to_run,
         "to_spec": row.to_spec, "kind": row.kind, "body": row.body,
         "reply_to": row.reply_to, "at": row.created_at.isoformat()}
        for row in (session.query(models.AgentMessage)
                    .filter_by(org_id=org.id)
                    .filter((models.AgentMessage.from_run == run_id)
                            | (models.AgentMessage.to_run == run_id))
                    .order_by(models.AgentMessage.created_at).all())]
    payload["artifacts"] = [
        {"id": row.id, "kind": row.kind, "sha256": row.sha256, "bytes": row.bytes,
         "storage": row.storage, "task_id": row.task_id}
        for row in (session.query(models.AgentArtifact)
                    .filter_by(org_id=org.id, run_id=run_id)
                    .order_by(models.AgentArtifact.produced_at).all())]
    payload["candidates"] = [
        {"id": row.id, "title": row.title, "severity": row.severity,
         "state": row.state, "claim": row.claim}
        for row in (session.query(models.Candidate)
                    .filter_by(org_id=org.id, run_id=run_id).all())]
    return {"data": payload}


@router.post("/agents/runs/{run_id}/finish")
def finish_run(run_id: str, payload: dict,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    run = session.get(models.AgentRun, run_id)
    if run is None or run.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    state = str(payload.get("state") or "").strip()
    try:
        harness_runs.finish(session, run, state, reason=payload.get("reason"))
    except ValueError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error))
    session.commit()
    return {"data": harness_runs.data(session, run)}


@router.post("/agents/messages", status_code=status.HTTP_201_CREATED)
def post_message(payload: MessageIn, org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """A line with a recipient. Text only: it cannot widen scope or approve a tool."""
    if payload.to_run:
        target = session.get(models.AgentRun, payload.to_run)
        if target is None or target.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "recipient run not found")
    row = models.AgentMessage(
        org_id=org.id, mission_id=payload.mission_id, from_run=payload.from_run,
        to_run=payload.to_run, to_spec=payload.to_spec, kind=payload.kind,
        body=payload.body, reply_to=payload.reply_to,
        delivered_at=models.utcnow() if payload.to_run else None)
    session.add(row)
    session.commit()
    return {"data": {"id": row.id, "to_run": row.to_run, "to_spec": row.to_spec,
                     "delivered": row.delivered_at is not None}}


@router.get("/agents/messages")
def list_messages(mission_id: str | None = Query(default=None),
                  run_id: str | None = Query(default=None),
                  limit: int = Query(default=100, ge=1, le=500),
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    query = session.query(models.AgentMessage).filter_by(org_id=org.id)
    if mission_id:
        query = query.filter_by(mission_id=mission_id)
    if run_id:
        query = query.filter((models.AgentMessage.from_run == run_id)
                             | (models.AgentMessage.to_run == run_id))
    rows = query.order_by(models.AgentMessage.created_at).limit(limit).all()
    return {"data": [{"id": row.id, "from_run": row.from_run, "to_run": row.to_run,
                      "to_spec": row.to_spec, "kind": row.kind, "body": row.body,
                      "reply_to": row.reply_to,
                      "at": row.created_at.isoformat()} for row in rows]}


@router.post("/agents/artifacts", status_code=status.HTTP_201_CREATED)
def post_artifact(payload: ArtifactIn, org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    row = models.AgentArtifact(
        org_id=org.id, run_id=payload.run_id, task_id=payload.task_id,
        mission_id=payload.mission_id, kind=payload.kind, sha256=payload.sha256,
        bytes=payload.bytes, storage=payload.storage,
        meta=json.dumps(payload.meta) if payload.meta is not None else None)
    session.add(row)
    session.commit()
    return {"data": {"id": row.id, "kind": row.kind, "sha256": row.sha256}}


@router.get("/agents/artifacts")
def list_artifacts(mission_id: str | None = Query(default=None),
                   run_id: str | None = Query(default=None),
                   limit: int = Query(default=100, ge=1, le=500),
                   org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    query = session.query(models.AgentArtifact).filter_by(org_id=org.id)
    if mission_id:
        query = query.filter_by(mission_id=mission_id)
    if run_id:
        query = query.filter_by(run_id=run_id)
    rows = query.order_by(models.AgentArtifact.produced_at).limit(limit).all()
    return {"data": [{"id": row.id, "run_id": row.run_id, "task_id": row.task_id,
                      "kind": row.kind, "sha256": row.sha256, "bytes": row.bytes,
                      "storage": row.storage,
                      "at": row.produced_at.isoformat()} for row in rows]}


@router.post("/agents/candidates", status_code=status.HTTP_201_CREATED)
def post_candidate(payload: CandidateIn,
                   org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    """A proposal. It is not a finding until a gate chain says so."""
    items = harness_evidence.normalize(payload.evidence)
    row = models.Candidate(
        org_id=org.id, mission_id=payload.mission_id, run_id=payload.run_id,
        finding_id=payload.finding_id, title=payload.title, severity=payload.severity,
        claim=payload.claim, evidence=harness_evidence.as_json(items), state="proposed")
    session.add(row)
    session.commit()
    return {"data": {"id": row.id, "state": row.state,
                     "evidence": len(items),
                     "confirmable": harness_evidence.confirmable(items)}}


@router.get("/agents/candidates")
def list_candidates(mission_id: str | None = Query(default=None),
                    cycle_id: str | None = Query(default=None),
                    state: str | None = Query(default=None),
                    limit: int = Query(default=50, ge=1, le=200),
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    query = session.query(models.Candidate).filter_by(org_id=org.id)
    if mission_id:
        query = query.filter_by(mission_id=mission_id)
    if state:
        query = query.filter_by(state=state)
    rows = query.order_by(models.Candidate.created_at.desc()).limit(limit).all()
    # The review queue needs the three ids that make a row actionable: which mission
    # proposed it, which cycle it belongs to, and the finding it already became —
    # without them the screen offers "promote" on a claim that was already promoted.
    def _cycle_of(mission_id: str | None) -> str | None:
        mission = session.get(models.AgentMission, mission_id) if mission_id else None
        if mission is None:
            return None
        try:
            return (json.loads(mission.evidence or "{}") or {}).get("cycle_id")
        except ValueError:
            return None

    cycles = {row.mission_id: _cycle_of(row.mission_id) for row in rows}
    if cycle_id:
        # A claim that nobody promoted still belongs to the cycle that produced it:
        # the campaign is where an operator goes back to look at what was left on the
        # table, so the filter has to exist.
        rows = [row for row in rows if cycles.get(row.mission_id) == cycle_id]
    def _kind(value: str | None) -> str:
        try:
            envelope = json.loads(value or "{}")
        except ValueError:
            return "vulnerability"
        if isinstance(envelope, dict):
            return envelope.get("claim_kind") or "vulnerability"
        return "vulnerability"

    return {"data": [{"id": row.id, "title": row.title, "severity": row.severity,
                      "state": row.state, "run_id": row.run_id,
                      "mission_id": row.mission_id, "finding_id": row.finding_id,
                      "cycle_id": cycles.get(row.mission_id),
                      "claim_kind": _kind(row.evidence),
                      "evidence": _json_list(row.evidence)} for row in rows]}


@router.post("/agents/candidates/{candidate_id}/gates")
def run_candidate_gates(candidate_id: str,
                        org: models.Organization = Depends(auth.require_org),
                        session: Session = Depends(get_session)):
    """Run the chain. The replay capability is handed in — the harness never calls out."""
    row = session.get(models.Candidate, candidate_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "candidate not found")

    def replay(*, finding_id, target=None, expect=None):
        return replay_request(finding_id=finding_id, target=target, expect=expect,
                              org=org, session=session).get("data", {})

    def sibling(*, finding_id, label_a, label_b, owner_marker=None):
        return probe_sibling(SiblingIn(finding_id=finding_id, label_a=label_a,
                                       label_b=label_b, owner_marker=owner_marker),
                             org=org, session=session).get("data", {})

    result = harness_gates.run_chain(session, org, row, replay=replay, sibling=sibling)
    session.commit()
    return {"data": {**result, "candidate_id": row.id}}


@router.post("/agents/{agent_id}/clone", status_code=status.HTTP_201_CREATED)
def clone_agent(agent_id: str, org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    """Duplicate a spec as a draft. Cheaper and safer than re-typing ten fields."""
    source = session.get(models.AgentSpec, agent_id)
    if source is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    base = f"{source.slug}-copy"
    slug, index = base, 2
    while session.query(models.AgentSpec).filter_by(slug=slug).one_or_none():
        slug, index = f"{base}-{index}", index + 1
    row = models.AgentSpec(
        name=f"{source.name} (copy)", slug=slug, agent_class=source.agent_class,
        description=source.description, avatar=source.avatar, color=source.color,
        tools=source.tools, must_return=source.must_return,
        tech_affinity=source.tech_affinity, parent_slug=source.parent_slug,
        allowed_tools=source.allowed_tools, status="draft")
    session.add(row)
    _audit_log(session, org.id, "console", "agent.cloned", "agent_spec", row.id,
               f"{source.slug}->{slug}")
    session.commit()
    return {"data": _spec_data(row)}


# ──────────────────── probe.sibling: two identities, one answer ────────────────────

class IdentityIn(BaseModel):
    grant_id: str
    label: str = Field(min_length=1, max_length=64)
    headers: dict[str, str] = Field(min_length=1)


class SiblingIn(BaseModel):
    finding_id: str
    label_a: str = Field(min_length=1, max_length=64)
    label_b: str = Field(min_length=1, max_length=64)
    owner_marker: str | None = Field(default=None, max_length=200)
    scheme: str = Field(default="http", pattern="^https?$")


@router.post("/agents/identities", status_code=status.HTTP_201_CREATED)
def create_identity(payload: IdentityIn,
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    """Store a principal for later replay. The headers are sealed and never returned."""
    grant = session.get(models.ScanGrant, payload.grant_id)
    if grant is None or grant.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "grant not found")
    if grant.status != "active":
        raise HTTPException(status.HTTP_409_CONFLICT, f"grant is {grant.status}")
    existing = (session.query(models.GrantIdentity)
                .filter_by(grant_id=grant.id, label=payload.label).one_or_none())
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"identity {payload.label!r} already exists for this grant")
    row = models.GrantIdentity(
        org_id=org.id, grant_id=grant.id, label=payload.label,
        headers_cipher=secret_store.seal(session, json.dumps(payload.headers)))
    session.add(row)
    _audit_log(session, org.id, "console", "agent.identity_created", "scan_grant",
               grant.id, payload.label)
    session.commit()
    return {"data": {"id": row.id, "grant_id": grant.id, "label": row.label,
                     "sealed": True}}


@router.get("/agents/identities")
def list_identities(grant_id: str | None = Query(default=None),
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    """Labels only. The credential never travels on a read."""
    query = session.query(models.GrantIdentity).filter_by(org_id=org.id)
    if grant_id:
        query = query.filter_by(grant_id=grant_id)
    rows = query.order_by(models.GrantIdentity.created_at).all()
    return {"data": [{"id": row.id, "grant_id": row.grant_id, "label": row.label,
                      "sealed": True,
                      "last_used_at": row.last_used_at.isoformat()
                      if row.last_used_at else None} for row in rows]}


@router.post("/agents/sibling")
def probe_sibling(payload: SiblingIn,
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    """Send the finding's request as identity A and as identity B, then compare.

    This is the only way to turn "the code does not check ownership" into evidence: B
    receiving A's record, with A's marker in the body. Without `owner_marker` the answer
    is `ambiguous`, never `leak`.
    """
    finding = session.get(models.Finding, payload.finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")

    raw = _stored_request(session, org, finding)
    if not raw:
        return {"data": {"state": "blocked", "missing": ["stored request"],
                         "why": "a sibling probe replays the captured request; there "
                                "is none on this finding"}}
    try:
        parsed = _parse_http(raw)
    except ValueError as error:
        return {"data": {"state": "blocked", "missing": ["readable request"],
                         "why": str(error)}}

    host = (parsed["headers"].get("Host") or parsed["headers"].get("host") or "")
    host = host.split(":")[0].lower()
    if not host:
        return {"data": {"state": "blocked", "missing": ["host"],
                         "why": "the stored request does not name a host"}}

    grant = _authorized_grant(session, org, host)
    if grant is None:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            f"{host} is not covered by an active grant")

    identities = {}
    for label in (payload.label_a, payload.label_b):
        row = (session.query(models.GrantIdentity)
               .filter_by(grant_id=grant.id, label=label).one_or_none())
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                f"no identity {label!r} on grant {grant.id}")
        identities[label] = json.loads(secret_store.open_sealed(session, row.headers_cipher))
        row.last_used_at = models.utcnow()

    base = {name: value for name, value in parsed["headers"].items()
            if name.lower() not in _SECRET_HEADERS | {"host", "content-length"}}
    url = f"{payload.scheme}://{host}{parsed['path']}"
    result = harness_sibling.run(
        method=parsed["method"], url=url, body=parsed["body"] or None,
        headers_a={**base, **identities[payload.label_a]},
        headers_b={**base, **identities[payload.label_b]},
        owner_marker=payload.owner_marker)

    # The artefact records what was asked and what came back — status, hashes, sizes —
    # and never a header: a leak in the log would defeat the sealing.
    session.add(models.AgentArtifact(
        org_id=org.id, kind="sibling", mission_id=None, run_id=None,
        sha256=result.get("b", {}).get("sha256_16"), bytes=result.get("b", {}).get("chars", 0),
        storage=None,
        meta=json.dumps({"url": url, "method": parsed["method"],
                         "state": result["state"],
                         "a": result.get("a"), "b": result.get("b"),
                         "similarity": result.get("similarity"),
                         "labels": [payload.label_a, payload.label_b]})))
    session.commit()
    return {"data": {**result, "finding_id": finding.id,
                     "grant": {"id": grant.id, "level": grant.level},
                     "identities": [payload.label_a, payload.label_b]}}


@router.get("/agents/inbox")
def agent_inbox(org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    """The only queue an operator actually needs: what is waiting on a human.

    Three sources, one answer — missions that need approval, runs paused for a
    decision, and candidates ready to be judged. Everything else is progress.
    """
    rows: list[dict] = []
    for mission in (session.query(models.AgentMission)
                    .filter_by(org_id=org.id, status="awaiting_approval")
                    .order_by(models.AgentMission.created_at).limit(20).all()):
        rows.append({"kind": "mission", "id": mission.id, "title": mission.goal,
                     "detail": f"{mission.capability} · {mission.profile}",
                     "at": mission.created_at.isoformat() if mission.created_at else None})
    for run in (session.query(models.AgentRun)
                .filter_by(org_id=org.id, status="waiting_approval")
                .order_by(models.AgentRun.created_at).limit(20).all()):
        rows.append({"kind": "run", "id": run.id, "title": run.goal or run.spec_slug,
                     "detail": f"{run.spec_slug} · {run.blocked_reason or 'needs a decision'}",
                     "at": run.created_at.isoformat() if run.created_at else None})
    for candidate in (session.query(models.Candidate)
                      .filter_by(org_id=org.id, state="proposed")
                      .order_by(models.Candidate.created_at).limit(20).all()):
        rows.append({"kind": "candidate", "id": candidate.id, "title": candidate.title,
                     "detail": f"{candidate.severity or 'unrated'} · run gates",
                     "at": candidate.created_at.isoformat()
                     if candidate.created_at else None})
    rows.sort(key=lambda row: row["at"] or "", reverse=True)
    return {"data": rows, "total": len(rows)}

"""My work: the queues a person actually reads.

Every tray is a query over persisted rows — assignments on findings, work items
(tasks, requests for a decision, acceptances). Nothing here is a static mock: an
empty tray means nobody assigned anything.

Policy enforced here, not in the console:
  * a requester can never approve their own request (409);
  * only the named reviewer can approve or reject;
  * only the requester can withdraw or remind, and reminders are rate-limited.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models, severity as severity_vocab
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/my-work", tags=["my-work"])

TERMINAL = {"approved", "rejected", "withdrawn", "done"}
REVIEW_ACTIONS = {"approve", "reject"}
REMIND_INTERVAL = timedelta(hours=1)
ACCEPTANCE_WINDOW = timedelta(days=30)


def _parse_ts(value: str | None, name: str) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"{name} must be ISO-8601") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _aware(value):
    return None if value is None else (
        value if value.tzinfo else value.replace(tzinfo=timezone.utc))


def _item_data(row: models.WorkItem, session: Session) -> dict:
    finding = session.get(models.Finding, row.finding_id) if row.finding_id else None
    cycle = session.get(models.Cycle, row.cycle_id) if row.cycle_id else None
    return {"id": row.id, "kind": row.kind, "title": row.title,
            "description": row.description, "status": row.status,
            "assignee": row.assignee, "requested_by": row.requested_by,
            "reviewer": row.reviewer,
            "due_at": row.due_at.isoformat() if row.due_at else None,
            "valid_until": row.valid_until.isoformat() if row.valid_until else None,
            "decision_reason": row.decision_reason,
            "decided_by": row.decided_by,
            "decided_at": row.decided_at.isoformat() if row.decided_at else None,
            "remind_count": row.remind_count,
            "finding": ({"id": finding.id, "title": finding.title,
                         "severity": severity_vocab.canonical(finding.severity),
                         "status": finding.status} if finding else None),
            "cycle": ({"id": cycle.id, "name": cycle.name,
                       "state": cycle.state} if cycle else None),
            "created_at": row.created_at.isoformat()}


def _sorted(rows: list) -> list:
    def key(item):
        due = _aware(item.due_at)
        return (due is None, due or datetime.max.replace(tzinfo=timezone.utc))
    return sorted(rows, key=key)


@router.get("")
def my_work(actor: str = Query(..., min_length=1, max_length=255),
            include_team: bool = Query(default=True),
            due_within_hours: int | None = Query(default=None, ge=1, le=24 * 365),
            org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    """Six trays with counters, each respecting the caller's data scope."""
    items = (session.query(models.WorkItem)
             .filter_by(org_id=org.id).all())
    now = models.utcnow()
    deadline = now + timedelta(hours=due_within_hours) if due_within_hours else None

    def in_window(row) -> bool:
        if deadline is None:
            return True
        due = _aware(row.due_at)
        return due is not None and due <= deadline  # overdue included

    assigned_findings = (session.query(models.Finding)
                         .filter(models.Finding.org_id == org.id,
                                 models.Finding.assignee == actor,
                                 models.Finding.status.in_(["open", "acknowledged"]))
                         .order_by(models.Finding.sla_deadline).all())
    my_tasks = [row for row in items
                if row.kind == "task" and row.assignee == actor
                and row.status not in TERMINAL and in_window(row)]
    awaiting_review = [row for row in items
                       if row.reviewer == actor
                       and row.status in {"awaiting_review", "open"}
                       and row.kind in {"request", "review"} and in_window(row)]
    requested = [row for row in items
                 if row.requested_by == actor and row.status not in TERMINAL
                 and in_window(row)]
    acceptances = [row for row in items
                   if row.kind == "acceptance"
                   and row.status not in {"rejected", "withdrawn"}
                   and _aware(row.valid_until) is not None
                   and _aware(row.valid_until) <= now + ACCEPTANCE_WINDOW]
    team = [row for row in items
            if include_team and row.assignee and row.assignee != actor
            and row.status not in TERMINAL and in_window(row)]
    # v0 has no team objects: the tray is honest about being org-wide.
    teams_supported = False

    trays = {
        "assigned_to_me": {
            "count": len(assigned_findings),
            "findings": [{"id": row.id, "title": row.title,
                          "severity": severity_vocab.canonical(row.severity),
                          "status": row.status,
                          "sla_deadline": row.sla_deadline.isoformat()
                          if row.sla_deadline else None}
                         for row in assigned_findings]},
        "my_team": {"count": len(team), "supported": bool(teams_supported),
                    "scope": "organization",
                    "label": ("Organization queue (no teams yet)"
                              if not teams_supported else "My team"),
                    "note": ("the organization has no teams yet: this tray lists every "
                             "open item assigned to somebody else"
                             if not teams_supported else None),
                    "items": [_item_data(row, session) for row in _sorted(team)]},
        "awaiting_my_review": {"count": len(awaiting_review),
                               "items": [_item_data(row, session)
                                         for row in _sorted(awaiting_review)]},
        "requested_by_me": {"count": len(requested),
                            "items": [_item_data(row, session)
                                      for row in _sorted(requested)]},
        "acceptances_expiring": {"count": len(acceptances),
                                 "window_days": ACCEPTANCE_WINDOW.days,
                                 "items": [_item_data(row, session)
                                           for row in _sorted(acceptances)]},
        "my_tasks": {"count": len(my_tasks),
                     "items": [_item_data(row, session)
                               for row in _sorted(my_tasks)]},
    }
    return {"data": {"actor": actor, "trays": trays,
                     "due_within_hours": due_within_hours,
                     "generated_at": now.isoformat()}}


class WorkItemIn(BaseModel):
    kind: str = "task"
    title: str = Field(min_length=1, max_length=512)
    description: str | None = Field(default=None, max_length=20000)
    assignee: str | None = Field(default=None, max_length=255)
    requested_by: str | None = Field(default=None, max_length=255)
    reviewer: str | None = Field(default=None, max_length=255)
    due_at: str | None = None
    valid_until: str | None = None
    cycle_id: str | None = Field(default=None, max_length=36)
    finding_id: str | None = Field(default=None, max_length=36)
    actor: str = Field(default="system", max_length=255)


@router.post("/items", status_code=status.HTTP_201_CREATED)
def create_item(payload: WorkItemIn = None,
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.kind not in models.WORK_ITEM_KINDS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"kind must be one of {sorted(models.WORK_ITEM_KINDS)}")
    if payload.finding_id:
        finding = session.get(models.Finding, payload.finding_id)
        if finding is None or finding.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    if payload.cycle_id:
        cycle = session.get(models.Cycle, payload.cycle_id)
        if cycle is None or cycle.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "cycle not found")
    if payload.reviewer and payload.requested_by \
            and payload.reviewer == payload.requested_by:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "self-approval is not allowed: the reviewer must be "
                            "someone else")
    item = models.WorkItem(
        org_id=org.id, kind=payload.kind, title=payload.title.strip(),
        description=payload.description, assignee=payload.assignee,
        requested_by=payload.requested_by, reviewer=payload.reviewer,
        due_at=_parse_ts(payload.due_at, "due_at"),
        valid_until=_parse_ts(payload.valid_until, "valid_until"),
        cycle_id=payload.cycle_id, finding_id=payload.finding_id,
        status=("awaiting_review" if payload.kind in {"request", "acceptance"}
                else "open"))
    session.add(item)
    session.flush()
    _audit_log(session, org.id, payload.actor, "work.item_created", "work_item",
               item.id, f"{payload.kind}: {item.title}")
    session.commit()
    return {"data": _item_data(item, session)}


class WorkDecisionIn(BaseModel):
    action: str
    reason: str | None = Field(default=None, max_length=4096)
    actor: str = Field(min_length=1, max_length=255)


@router.post("/items/{item_id}/decide")
def decide_item(item_id: str, payload: WorkDecisionIn = None,
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    item = session.get(models.WorkItem, item_id)
    if item is None or item.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "work item not found")
    now = models.utcnow()
    if payload.action in REVIEW_ACTIONS:
        if item.reviewer and item.reviewer != payload.actor:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f"only {item.reviewer} can decide this item")
        if item.requested_by and item.requested_by == payload.actor:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                "self-approval is not allowed")
        if not payload.reason:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                "a decision needs a reason")
        item.status = "approved" if payload.action == "approve" else "rejected"
        item.decision_reason = payload.reason
        item.decided_by = payload.actor
        item.decided_at = now
    elif payload.action == "withdraw":
        if item.requested_by and item.requested_by != payload.actor:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                "only the requester can withdraw this item")
        item.status = "withdrawn"
        item.decision_reason = payload.reason
        item.decided_by = payload.actor
        item.decided_at = now
    elif payload.action == "remind":
        if item.requested_by and item.requested_by != payload.actor:
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                "only the requester can remind")
        last = _aware(item.last_reminded_at)
        if last is not None and now - last < REMIND_INTERVAL:
            raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS,
                                "a reminder was sent less than an hour ago")
        item.remind_count += 1
        item.last_reminded_at = now
    elif payload.action in {"start", "complete"}:
        item.status = "in_progress" if payload.action == "start" else "done"
    else:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "action must be approve, reject, withdraw, remind, "
                            "start or complete")
    item.updated_at = now
    _audit_log(session, org.id, payload.actor, f"work.{payload.action}", "work_item",
               item.id, f"{item.status}: {(payload.reason or '')[:120]}")
    session.commit()
    return {"data": _item_data(item, session)}


class WorkPatch(BaseModel):
    assignee: str | None = Field(default=None, max_length=255)
    due_at: str | None = None
    actor: str = Field(default="system", max_length=255)


@router.patch("/items/{item_id}")
def patch_item(item_id: str, payload: WorkPatch = None,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    item = session.get(models.WorkItem, item_id)
    if item is None or item.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "work item not found")
    changes = []
    if payload.assignee is not None:
        item.assignee = payload.assignee.strip() or None
        changes.append(f"assignee={item.assignee or 'none'}")
    if payload.due_at is not None:
        item.due_at = _parse_ts(payload.due_at, "due_at")
        changes.append("due_at")
    if not changes:
        return {"data": _item_data(item, session), "changed": False}
    item.updated_at = models.utcnow()
    _audit_log(session, org.id, payload.actor, "work.item_updated", "work_item",
               item.id, ", ".join(changes))
    session.commit()
    return {"data": _item_data(item, session), "changed": True}

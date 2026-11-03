"""B1 endpoints: priority rules, SLA policies, remediation tasks."""
import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from backend.app import auth, lifecycle, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1", tags=["lifecycle"])

PRIORITIES = {"P0", "P1", "P2", "P3"}
TASK_OPEN_STATUSES = {"open", "in_progress"}


class PriorityRuleIn(BaseModel):
    position: int = 0
    match_kind: str | None = None
    match_severities: str | None = Field(default=None, max_length=255)
    match_source: str | None = None
    match_intel: str | None = None
    priority: str
    reason: str = Field(min_length=4, max_length=2048)

    @field_validator("priority")
    @classmethod
    def priority_known(cls, value):
        if value not in PRIORITIES:
            raise ValueError(f"priority must be one of {sorted(PRIORITIES)}")
        return value

    @field_validator("match_intel")
    @classmethod
    def intel_known(cls, value):
        allowed = {"kev"}
        if value is not None and value not in allowed:
            raise ValueError(f"match_intel must be one of {sorted(allowed)}")
        return value


class SlaPolicyIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    p0_days: int = Field(ge=1, le=365)
    p1_days: int = Field(ge=1, le=365)
    p2_days: int = Field(ge=1, le=365)
    p3_days: int = Field(ge=1, le=365)
    make_default: bool = False


def _classify_all(session, org_id: str) -> int:
    return lifecycle.reclassify_org(session, org_id)


@router.get("/priority-rules")
def list_rules(org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    rows = (session.query(models.PriorityRule)
            .filter_by(org_id=org.id)
            .order_by(models.PriorityRule.position, models.PriorityRule.created_at).all())
    return {"data": [{
        "id": r.id, "position": r.position, "match_kind": r.match_kind,
        "match_severities": r.match_severities, "match_source": r.match_source,
        "match_intel": r.match_intel, "priority": r.priority, "reason": r.reason,
    } for r in rows], "total": len(rows)}


@router.post("/priority-rules")
def add_rule(payload: PriorityRuleIn = None,
             org: models.Organization = Depends(auth.require_org),
             session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if not (payload.match_kind or payload.match_severities or payload.match_source
            or payload.match_intel):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "at least one match criterion is required")
    rule = models.PriorityRule(
        org_id=org.id, position=payload.position, match_kind=payload.match_kind,
        match_severities=(payload.match_severities.upper() if payload.match_severities else None),
        match_source=payload.match_source, match_intel=payload.match_intel,
        priority=payload.priority,
        reason=payload.reason, created_at=models.utcnow(), updated_at=models.utcnow())
    session.add(rule)
    session.flush()
    changed = _classify_all(session, org.id)
    session.commit()
    return {"data": {"id": rule.id}, "reclassified": changed}


class SlaCreate(SlaPolicyIn):
    pass


@router.get("/sla/policies")
def list_policies(org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    rows = (session.query(models.SlaPolicy).filter_by(org_id=org.id).all())
    return {"data": [{
        "id": r.id, "name": r.name, "p0_days": r.p0_days, "p1_days": r.p1_days,
        "p2_days": r.p2_days, "p3_days": r.p3_days, "is_default": r.is_default,
    } for r in rows], "total": len(rows)}


@router.post("/sla/policies")
def add_policy(payload: SlaCreate = None,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    existing = (session.query(models.SlaPolicy)
                .filter_by(org_id=org.id, name=payload.name).one_or_none())
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "policy name exists")
    now = models.utcnow()
    if payload.make_default:
        for row in session.query(models.SlaPolicy).filter_by(org_id=org.id, is_default=True):
            row.is_default = False
            row.updated_at = now
    policy = models.SlaPolicy(
        org_id=org.id, name=payload.name, p0_days=payload.p0_days,
        p1_days=payload.p1_days, p2_days=payload.p2_days, p3_days=payload.p3_days,
        is_default=payload.make_default, created_at=now, updated_at=now)
    session.add(policy)
    session.flush()
    if payload.make_default or _default_absent(session, org.id):
        _reassign_deadlines(session, org.id, policy if payload.make_default else
                            lifecycle.default_policy(session, org.id))
    session.commit()
    return {"data": {"id": policy.id}, "recomputed_deadlines": True}


def _default_absent(session, org_id):
    return lifecycle.default_policy(session, org_id) is None


def _reassign_deadlines(session, org_id, policy):
    if policy is None:
        return
    now = models.utcnow()
    for finding in session.query(models.Finding).filter_by(org_id=org_id).all():
        if finding.priority is None:
            continue
        days = getattr(policy, _PRIORITY_DAYS[finding.priority])
        base = _aware(finding.created_at or now)
        finding.sla_deadline = base + datetime.timedelta(days=days)
        finding.updated_at = now


def _aware(value):
    from datetime import timezone

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


_PRIORITY_DAYS = {"P0": "p0_days", "P1": "p1_days", "P2": "p2_days", "P3": "p3_days"}


class TaskCreate(BaseModel):
    title: str = Field(min_length=1, max_length=512)
    owner: str | None = Field(default=None, max_length=255)
    actor: str | None = Field(default=None, max_length=255)


class TaskPatch(BaseModel):
    status: str
    owner: str | None = None
    changed_by: str | None = None


class FindingLink(BaseModel):
    finding_id: str
    actor: str | None = None


def _task_data(session, task: models.RemediationTask) -> dict:
    links = (session.query(models.RemediationFinding, models.Finding)
             .join(models.Finding, models.RemediationFinding.finding_id == models.Finding.id)
             .filter(models.RemediationFinding.task_id == task.id,
                     models.RemediationFinding.removed_at.is_(None)).all())
    return {"id": task.id, "title": task.title, "status": task.status,
            "owner": task.owner, "findings": [{
                "id": finding.id, "kind": finding.kind, "severity": finding.severity,
                "title": finding.title, "priority": finding.priority,
                "rule_id": finding.rule_id, "path": finding.path,
            } for _link, finding in links]}


@router.get("/remediation/tasks")
def list_tasks(org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    rows = (session.query(models.RemediationTask)
            .filter_by(org_id=org.id)
            .order_by(models.RemediationTask.created_at.desc()).all())
    return {"data": [_task_data(session, row) for row in rows], "total": len(rows)}


@router.post("/remediation/tasks")
def create_task(payload: TaskCreate = None,
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    task = models.RemediationTask(org_id=org.id, title=payload.title, owner=payload.owner,
                                  created_at=models.utcnow(), updated_at=models.utcnow())
    session.add(task)
    session.flush()
    _audit_log(session, org.id, payload.actor or "system", "remediation.created",
               "remediation_task", task.id, payload.title)
    session.commit()
    return {"data": {"id": task.id, "title": task.title, "status": task.status}}


@router.patch("/remediation/tasks/{task_id}")
def patch_task(task_id: str, payload: TaskPatch = None,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.status not in {"open", "in_progress", "resolved"}:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "status must be open | in_progress | resolved")
    task = session.get(models.RemediationTask, task_id)
    if task is None or task.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "task not found")
    task.status = payload.status
    if payload.owner is not None:
        task.owner = payload.owner
    task.updated_at = models.utcnow()
    _audit_log(session, org.id, payload.changed_by or "system", "remediation.status",
               "remediation_task", task.id, f"-> {payload.status}")
    session.commit()
    return {"data": _task_data(session, task)}


@router.post("/remediation/tasks/{task_id}/findings")
def link_finding(task_id: str, payload: FindingLink = None,
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    task = session.get(models.RemediationTask, task_id)
    if task is None or task.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "task not found")
    if task.status not in TASK_OPEN_STATUSES:
        raise HTTPException(status.HTTP_409_CONFLICT, "closed tasks take no findings")
    finding = session.get(models.Finding, payload.finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    open_link = (session.query(models.RemediationFinding)
                 .join(models.RemediationTask,
                       models.RemediationFinding.task_id == models.RemediationTask.id)
                 .filter(models.RemediationFinding.finding_id == finding.id,
                         models.RemediationFinding.removed_at.is_(None),
                         models.RemediationTask.status.in_(TASK_OPEN_STATUSES))
                 .filter(models.RemediationFinding.task_id != task.id)
                 .one_or_none())
    if open_link is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"finding already in open task {open_link.task_id}")
    existing = (session.query(models.RemediationFinding)
                .filter_by(task_id=task.id, finding_id=finding.id,
                           removed_at=None).one_or_none())
    if existing is not None:
        result = _task_data(session, task)
        session.commit()
        return {"data": result, "already_linked": True}
    session.add(models.RemediationFinding(task_id=task.id, finding_id=finding.id,
                                          added_at=models.utcnow()))
    _audit_log(session, org.id, payload.actor or "system", "remediation.linked",
               "remediation_task", task.id, payload.finding_id[:12])
    session.commit()
    return {"data": _task_data(session, task)}


@router.delete("/remediation/tasks/{task_id}/findings/{finding_id}")
def unlink_finding(task_id: str, finding_id: str,
                   org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    task = session.get(models.RemediationTask, task_id)
    if task is None or task.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "task not found")
    link = (session.query(models.RemediationFinding)
            .filter_by(task_id=task.id, finding_id=finding_id, removed_at=None)
            .one_or_none())
    if link is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "link not found")
    link.removed_at = models.utcnow()
    _audit_log(session, org.id, "system", "remediation.unlinked",
               "remediation_task", task.id, finding_id[:12])
    session.commit()
    return {"data": _task_data(session, task)}

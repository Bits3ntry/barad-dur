"""Named SAST baselines: snapshot, approve, and classify against them.

A PR finding is `new` only when its fingerprint is absent from the *approved*
baseline for its repository. That distinction matters: a draft baseline must
never silence findings, and nobody approves their own baseline.
"""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/code/baselines", tags=["code-baselines"])


class BaselineIn(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    repository_id: str | None = None
    project: str | None = None
    from_pr_id: str | None = None
    note: str | None = Field(default=None, max_length=2000)
    actor: str = Field(min_length=2, max_length=255)


class DecisionIn(BaseModel):
    actor: str = Field(min_length=2, max_length=255)
    note: str | None = Field(default=None, max_length=2000)


def _data(row: models.SastBaseline, include_entries: bool = False) -> dict:
    payload = {
        "id": row.id, "name": row.name, "status": row.status,
        "repository_id": row.repository_id, "project_id": row.project_id,
        "counters": row.counters or {}, "source_pr_id": row.source_pr_id,
        "created_by": row.created_by, "approved_by": row.approved_by,
        "approved_at": row.approved_at.isoformat() if row.approved_at else None,
        "note": row.note,
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }
    if include_entries:
        payload["entries"] = row.entries or []
    return payload


@router.get("")
def list_baselines(org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session),
                   repository_id: str | None = Query(default=None),
                   status_filter: str | None = Query(default=None,
                                                     alias="status")):
    query = session.query(models.SastBaseline).filter_by(org_id=org.id)
    if repository_id:
        query = query.filter_by(repository_id=repository_id)
    if status_filter:
        query = query.filter_by(status=status_filter)
    rows = query.order_by(models.SastBaseline.created_at.desc()).all()
    return {"data": [_data(row) for row in rows]}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_baseline(payload: BaselineIn = None,
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    existing = (session.query(models.SastBaseline)
                .filter_by(org_id=org.id, name=payload.name).one_or_none())
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "a baseline with that name already exists")
    repository = None
    if payload.repository_id:
        repository = session.get(models.Repository, payload.repository_id)
        if repository is None or repository.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "repository not found")
    project = None
    if payload.project:
        project = (session.query(models.Project)
                   .filter_by(org_id=org.id, slug=payload.project).one_or_none())
        if project is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")

    query = session.query(models.Finding).filter_by(org_id=org.id,
                                                   kind="code-weakness")
    if project is not None:
        query = query.filter_by(project_id=project.id)
    if payload.from_pr_id:
        pr = session.get(models.PullRequest, payload.from_pr_id)
        if pr is None or pr.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "pull request not found")
        links = session.query(models.PrFinding).filter_by(pr_id=pr.id).all()
        finding_ids = [link.finding_id for link in links]
        rows = (session.query(models.Finding)
                .filter(models.Finding.id.in_(finding_ids)).all()) if finding_ids else []
    else:
        rows = query.all()

    entries = sorted({row.fingerprint for row in rows if row.fingerprint})
    by_severity: dict[str, int] = {}
    for row in rows:
        by_severity[row.severity] = by_severity.get(row.severity, 0) + 1
    now = models.utcnow()
    record = models.SastBaseline(
        org_id=org.id, name=payload.name,
        repository_id=repository.id if repository else None,
        project_id=project.id if project else None,
        status="draft", entries=entries,
        counters={"entries": len(entries), "by_severity": by_severity},
        source_pr_id=payload.from_pr_id, created_by=payload.actor,
        note=payload.note, created_at=now, updated_at=now)
    session.add(record)
    session.flush()
    _audit_log(session, org.id, payload.actor, "code.baseline_created",
               "sast_baseline", record.id,
               f"{payload.name}: {len(entries)} entries, draft")
    session.commit()
    return {"data": _data(record, include_entries=True)}


@router.post("/{baseline_id}/approve")
def approve_baseline(baseline_id: str, payload: DecisionIn = None,
                     org: models.Organization = Depends(auth.require_org),
                     session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    record = session.get(models.SastBaseline, baseline_id)
    if record is None or record.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "baseline not found")
    if record.status != "draft":
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"baseline is {record.status}, not draft")
    if record.created_by == payload.actor:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "self-approval is not allowed: another reviewer must approve")
    record.status = "approved"
    record.approved_by = payload.actor
    record.approved_at = models.utcnow()
    record.updated_at = record.approved_at
    if payload.note:
        record.note = payload.note
    _audit_log(session, org.id, payload.actor, "code.baseline_approved",
               "sast_baseline", record.id,
               f"{record.name}: {record.counters.get('entries', 0)} entries")
    session.commit()
    return {"data": _data(record)}


@router.post("/{baseline_id}/reject")
def reject_baseline(baseline_id: str, payload: DecisionIn = None,
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    record = session.get(models.SastBaseline, baseline_id)
    if record is None or record.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "baseline not found")
    if record.status != "draft":
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"baseline is {record.status}, not draft")
    record.status = "rejected"
    record.updated_at = models.utcnow()
    if payload.note:
        record.note = payload.note
    _audit_log(session, org.id, payload.actor, "code.baseline_rejected",
               "sast_baseline", record.id, record.note or "")
    session.commit()
    return {"data": _data(record)}


def approved_fingerprints(session: Session, org_id: str,
                          repository_id: str | None,
                          project_id: str | None) -> set[str]:
    """Fingerprints covered by the newest approved baseline for this scope."""
    if not repository_id and not project_id:
        return set()
    query = session.query(models.SastBaseline).filter_by(org_id=org_id,
                                                         status="approved")
    if repository_id:
        query = query.filter_by(repository_id=repository_id)
    elif project_id:
        query = query.filter_by(project_id=project_id)
    record = query.order_by(models.SastBaseline.approved_at.desc()).first()
    if record is None:
        return set()
    return set(record.entries or [])

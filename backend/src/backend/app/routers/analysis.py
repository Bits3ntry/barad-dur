"""Analysis runs: what a tool actually looked at, and what that entitles it to close.

A run is recorded on import or CI receipt. Closing findings is an explicit step
with a preview, because "absent from a scan" only means "fixed" when the scan
covered the whole target.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import analysis, auth, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/analysis", tags=["analysis"])

COVERAGES = models.ANALYSIS_COVERAGES
SOURCES = {"import", "ci", "api", "cli"}


class RunIn(BaseModel):
    project: str = Field(min_length=1, max_length=128)
    version: str | None = Field(default=None, max_length=255)
    tool: str = Field(min_length=1, max_length=64)
    tool_version: str | None = Field(default=None, max_length=64)
    coverage: str = "unknown"
    source: str = "import"
    revision: str | None = Field(default=None, max_length=128)
    branch: str | None = Field(default=None, max_length=255)
    base_revision: str | None = Field(default=None, max_length=128)
    evaluated: dict = Field(default_factory=dict)
    receipt: dict = Field(default_factory=dict)
    findings_seen: int = Field(default=0, ge=0)
    started_at: str | None = None
    finished_at: str | None = None
    actor: str = Field(default="system", max_length=255)


class ClosureIn(BaseModel):
    actor: str = Field(default="system", max_length=255)
    dry_run: bool = True


def _parse_ts(value: str | None, name: str) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"{name} must be ISO-8601") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _data(session: Session, run: models.AnalysisRun) -> dict:
    project = session.get(models.Project, run.project_id)
    version = (session.get(models.ProjectVersion, run.project_version_id)
               if run.project_version_id else None)
    return {
        "id": run.id, "project": project.slug if project else None,
        "version": version.version if version else None,
        "tool": run.tool, "tool_version": run.tool_version,
        "coverage": run.coverage, "closure_eligible": run.coverage in analysis.CLOSABLE_COVERAGES,
        "source": run.source, "revision": run.revision, "branch": run.branch,
        "base_revision": run.base_revision,
        "evaluated": run.evaluated or {}, "receipt": run.receipt or {},
        "findings_seen": run.findings_seen, "actor": run.actor,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "created_at": run.created_at.isoformat(),
    }


@router.get("/runs")
def list_runs(project: str | None = Query(default=None),
              version: str | None = Query(default=None),
              coverage: str | None = Query(default=None),
              limit: int = Query(default=50, ge=1, le=200),
              offset: int = Query(default=0, ge=0),
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    query = session.query(models.AnalysisRun).filter_by(org_id=org.id)
    if project:
        project_row = (session.query(models.Project)
                       .filter_by(org_id=org.id, slug=project).one_or_none())
        if project_row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
        query = query.filter(models.AnalysisRun.project_id == project_row.id)
    if coverage:
        query = query.filter(models.AnalysisRun.coverage == coverage)
    total = query.count()
    rows = (query.order_by(models.AnalysisRun.created_at.desc())
            .offset(offset).limit(limit).all())
    data = [_data(session, row) for row in rows]
    if version:
        data = [row for row in data if row["version"] == version]
    return {"data": data, "total": total, "limit": limit, "offset": offset}


@router.post("/runs", status_code=status.HTTP_201_CREATED)
def record_run(payload: RunIn = None,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """Record what a tool evaluated. Recording never changes a finding."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.coverage not in COVERAGES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"coverage must be one of {sorted(COVERAGES)}")
    if payload.source not in SOURCES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"source must be one of {sorted(SOURCES)}")
    project_row = (session.query(models.Project)
                   .filter_by(org_id=org.id, slug=payload.project).one_or_none())
    if project_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    version_row = None
    if payload.version:
        version_row = (session.query(models.ProjectVersion)
                       .filter_by(project_id=project_row.id,
                                  version=payload.version).one_or_none())
        if version_row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")
    run = models.AnalysisRun(
        org_id=org.id, project_id=project_row.id,
        project_version_id=version_row.id if version_row else None,
        tool=payload.tool, tool_version=payload.tool_version,
        coverage=payload.coverage, source=payload.source,
        revision=payload.revision, branch=payload.branch,
        base_revision=payload.base_revision,
        evaluated=payload.evaluated or {}, receipt=payload.receipt or {},
        findings_seen=payload.findings_seen, actor=payload.actor,
        started_at=_parse_ts(payload.started_at, "started_at"),
        finished_at=_parse_ts(payload.finished_at, "finished_at"))
    session.add(run)
    session.flush()
    _audit_log(session, org.id, payload.actor, "analysis.run_recorded",
               "analysis_run", run.id,
               f"{payload.tool} {payload.coverage} on {project_row.slug}"
               + (f"@{payload.version}" if payload.version else ""))
    session.commit()
    return {"data": _data(session, run)}


@router.get("/runs/{run_id}")
def get_run(run_id: str,
            org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    run = session.get(models.AnalysisRun, run_id)
    if run is None or run.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "analysis run not found")
    plan = analysis.plan_closure(session, run)
    return {"data": {**_data(session, run),
                     "closure": {"eligible": plan["eligible"],
                                 "reason": plan["reason"],
                                 "counts": plan["counts"]}}}


@router.post("/runs/{run_id}/close-unseen")
def close_unseen(run_id: str, payload: ClosureIn = None,
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """Preview (default) or apply closure. Diff/partial runs answer 409."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    run = session.get(models.AnalysisRun, run_id)
    if run is None or run.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "analysis run not found")
    if payload.dry_run:
        plan = analysis.plan_closure(session, run)
        if not plan["eligible"]:
            raise HTTPException(status.HTTP_409_CONFLICT, plan["reason"])
        return {"data": {"dry_run": True, **plan}}
    plan = analysis.apply_closure(session, run, payload.actor)
    if not plan["eligible"]:
        session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, plan["reason"])
    session.commit()
    return {"data": {"dry_run": False, **plan}}

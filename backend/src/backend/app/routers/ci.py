"""CI plane endpoints: pipelines, runs, gate verdicts (read-only registry)."""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, ci, models
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1/ci", tags=["ci"])


class RunRegister(BaseModel):
    provider: str = "github"
    repository: str = Field(min_length=1, max_length=512)
    workflow_path: str | None = None
    ref: str | None = None
    commit_sha: str | None = None
    event: str | None = None
    actor: str | None = None


class RunFinish(BaseModel):
    status: str


def _run_data(run: models.CiRun) -> dict:
    return {"id": run.id, "ref": run.ref, "commit_sha": run.commit_sha,
            "event": run.event, "actor": run.actor, "status": run.status,
            "verdict": run.verdict, "findings_count": run.findings_count,
            "started_at": run.started_at.isoformat(),
            "finished_at": run.finished_at.isoformat() if run.finished_at else None}


@router.post("/runs")
def register(run: RunRegister = None,
             org: models.Organization = Depends(auth.require_org),
             session: Session = Depends(get_session)):
    if run is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    row = ci.register_run(session, org.id, provider=run.provider,
                          repository=run.repository, workflow_path=run.workflow_path,
                          ref=run.ref, commit_sha=run.commit_sha,
                          event=run.event, actor=run.actor)
    session.commit()
    return {"data": _run_data(row)}


@router.post("/runs/{run_id}/finish")
def finish(run_id: str, payload: RunFinish = None,
           org: models.Organization = Depends(auth.require_org),
           session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    row = session.get(models.CiRun, run_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "ci run not found")
    try:
        summary = ci.finish_run(session, row, status=payload.status)
    except ValueError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from None
    session.commit()
    return {"data": _run_data(row) | summary}


@router.get("/pipelines")
def pipelines(org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    rows = (session.query(models.CiPipeline)
            .filter(models.CiPipeline.org_id == org.id)
            .order_by(models.CiPipeline.created_at.desc()).all())
    return {"data": [{
        "id": row.id, "provider": row.provider, "repository": row.repository,
        "workflow_path": row.workflow_path,
        "retired": row.retired_at is not None,
    } for row in rows], "total": len(rows)}


@router.get("/runs")
def runs(org: models.Organization = Depends(auth.require_org),
         session: Session = Depends(get_session)):
    rows = (session.query(models.CiRun)
            .filter_by(org_id=org.id)
            .order_by(models.CiRun.started_at.desc()).all())
    return {"data": [_run_data(row) for row in rows], "total": len(rows)}


@router.get("/runs/{run_id}")
def run_detail(run_id: str, org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    row = session.get(models.CiRun, run_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "ci run not found")
    linked = (session.query(models.Finding)
              .join(models.CiRunFinding,
                    models.CiRunFinding.finding_id == models.Finding.id)
              .filter(models.CiRunFinding.run_id == row.id).all())
    return {"data": _run_data(row) | {
        "verdict_reasons": (row.verdict_detail or "").splitlines(),
        "findings": [{
            "id": finding.id, "kind": finding.kind, "severity": finding.severity,
            "title": finding.title, "rule_id": finding.rule_id, "path": finding.path,
            "status": finding.status,
        } for finding in linked]}}


# Ingest wiring lives in backend/app/routers/findings.py: publish with
# ?run_id=<id> attaches created/refreshed findings to the run, and the run's
# verdict is computed at /finish. Gate override policies come after the POC.

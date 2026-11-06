"""BL-020: orchestration API — the management side of the Shauron contract.

Lifecycle: queued → leased → running → succeeded | failed | cancelled.
Rules pinned here:
  - A job is created from a scanner + targets + capability; creation evaluates
    `authorize()` and stores the decision (policy version included). Denied
    creation → 403, no job row.
  - A worker claiming a job re-evaluates `authorize()`; if the grant was
    revoked or narrowed in the meantime the job fails immediately with the
    denial reason instead of running on a stale permission.
  - Leases expire: an expired lease returns the job to the queue until
    max_attempts, then marks it failed. Workers heartbeat or go offline.
  - Workers have a concurrency ceiling; claims beyond it are rejected.
  - Results are summaries + artifacts only; the management plane never
    executes scanner code.
"""
import datetime
import json

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.versions import pick_version
from backend.app import advisories, auth, authorization, models, scan_flow
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/orchestration", tags=["orchestration"])

LEASE_SECONDS = 900
HEARTBEAT_STALE_SECONDS = 120


def _aware(value: datetime.datetime) -> datetime.datetime:
    return value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)



def _assert_worker_identity(session, worker_token: str, worker_id: str) -> None:
    """A worker credential may only act for the worker it was issued to."""
    if not worker_token:
        return
    principal = auth.resolve_principal(session, worker_token=worker_token)
    if principal.get("worker_id") != worker_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "worker token does not belong to that worker")


def _job_data(row: models.ScanJob) -> dict:
    subject = json.loads(row.subject or "{}")
    return {"id": row.id, "scanner": row.scanner, "capability": row.capability,
            "principal": row.principal, "environment": row.environment,
            # Who asked and where it pointed: the two columns an operator reads
            # before deciding to cancel or retry a run.
            "origin": row.origin, "actor": row.created_by or row.principal,
            "subject": subject, "coverage": scan_flow.coverage(row),
            "targets": json.loads(row.targets or "[]"),
            "profile": json.loads(row.profile or "{}"),
            "status": row.status, "priority": row.priority,
            "attempts": row.attempts, "max_attempts": row.max_attempts,
            "worker_id": row.worker_id,
            "lease_expires_at": row.lease_expires_at.isoformat() if row.lease_expires_at else None,
            "authorization": json.loads(row.authorization) if row.authorization else None,
            "result": json.loads(row.result) if row.result else None,
            "error": row.error, "created_by": row.created_by,
            "created_at": row.created_at.isoformat(),
            "started_at": row.started_at.isoformat() if row.started_at else None,
            "finished_at": row.finished_at.isoformat() if row.finished_at else None}


class ScannerIn(BaseModel):
    name: str = Field(min_length=2, max_length=64)
    display_name: str = Field(min_length=2, max_length=128)
    capability: str
    version: str | None = None
    adapter: str = "cli"
    actor: str = Field(min_length=2, max_length=255)


@router.post("/scanners")
def register_scanner(payload: ScannerIn = None,
                     org: models.Organization = Depends(auth.require_admin),
                     session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.capability not in authorization.CAPABILITIES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"capability must be one of {sorted(authorization.CAPABILITIES)}")
    existing = (session.query(models.Scanner)
                .filter_by(org_id=org.id, name=payload.name).one_or_none())
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "scanner already registered")
    row = models.Scanner(
        org_id=org.id, name=payload.name, display_name=payload.display_name,
        capability=payload.capability, version=payload.version,
        adapter=payload.adapter, enabled=True, created_at=models.utcnow())
    session.add(row)
    session.flush()
    _audit_log(session, org.id, payload.actor, "orchestration.scanner_registered",
               "scanner", row.id, payload.name)
    session.commit()
    return {"data": {"id": row.id, "name": row.name, "capability": row.capability,
                     "version": row.version, "enabled": row.enabled}}


@router.get("/scanners")
def list_scanners(org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    rows = (session.query(models.Scanner).filter_by(org_id=org.id)
            .order_by(models.Scanner.name).all())
    return {"data": [{"id": r.id, "name": r.name, "display_name": r.display_name,
                      "capability": r.capability, "version": r.version,
                      "adapter": r.adapter, "enabled": r.enabled} for r in rows],
            "total": len(rows)}


class WorkerIn(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    capabilities: list[str] = []
    labels: dict[str, str] = {}
    max_concurrent: int = Field(default=1, ge=1, le=32)
    actor: str = Field(min_length=2, max_length=255)


@router.post("/workers")
def register_worker(payload: WorkerIn = None,
                    org: models.Organization = Depends(auth.require_admin),
                    session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    now = models.utcnow()
    row = (session.query(models.Worker)
           .filter_by(org_id=org.id, name=payload.name).one_or_none())
    if row is None:
        row = models.Worker(org_id=org.id, name=payload.name,
                            registered_at=now, last_heartbeat=now)
        session.add(row)
    row.capabilities = json.dumps(payload.capabilities)
    row.labels = json.dumps(payload.labels)
    row.max_concurrent = payload.max_concurrent
    row.status = "online"
    row.last_heartbeat = now
    session.flush()
    _audit_log(session, org.id, payload.actor, "orchestration.worker_registered",
               "worker", row.id, payload.name)
    session.commit()
    return {"data": {"id": row.id, "name": row.name, "status": row.status,
                     "max_concurrent": row.max_concurrent}}


@router.post("/workers/{worker_id}/heartbeat")
def heartbeat(worker_id: str, org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    row = session.get(models.Worker, worker_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "worker not found")
    row.last_heartbeat = models.utcnow()
    if row.status == "offline":
        row.status = "online"
    session.commit()
    return {"data": {"id": row.id, "status": row.status,
                     "last_heartbeat": row.last_heartbeat.isoformat()}}


@router.get("/workers")
def list_workers(org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    rows = (session.query(models.Worker).filter_by(org_id=org.id)
            .order_by(models.Worker.name).all())
    now = _aware(models.utcnow())
    data = []
    for row in rows:
        stale = (now - _aware(row.last_heartbeat)).total_seconds() > HEARTBEAT_STALE_SECONDS
        active = (session.query(models.ScanJob)
                  .filter_by(org_id=org.id, worker_id=row.id)
                  .filter(models.ScanJob.status.in_(["leased", "running"])).count())
        data.append({"id": row.id, "name": row.name,
                     "capabilities": json.loads(row.capabilities or "[]"),
                     "labels": json.loads(row.labels or "{}"),
                     "max_concurrent": row.max_concurrent,
                     "active_jobs": active,
                     "status": "offline" if stale else row.status,
                     "stale": stale,
                     "last_heartbeat": row.last_heartbeat.isoformat()})
    return {"data": data, "total": len(rows)}


class JobIn(BaseModel):
    scanner: str
    capability: str
    principal: str
    targets: list[dict]
    environment: str | None = None
    project: str | None = None
    version: str | None = None
    profile: dict = {}
    priority: int = Field(default=5, ge=1, le=9)
    max_attempts: int = Field(default=3, ge=1, le=10)
    actor: str = Field(min_length=2, max_length=255)


@router.post("/jobs")
def create_job(payload: JobIn = None,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.capability not in authorization.CAPABILITIES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"capability must be one of {sorted(authorization.CAPABILITIES)}")
    scanner = (session.query(models.Scanner)
               .filter_by(org_id=org.id, name=payload.scanner).one_or_none())
    if scanner is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scanner not registered")
    if not scanner.enabled:
        raise HTTPException(status.HTTP_409_CONFLICT, "scanner disabled")
    if scanner.capability != payload.capability:
        # A scanner name never grants capabilities it wasn't registered for.
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"scanner {scanner.name} is registered for "
                            f"'{scanner.capability}', not '{payload.capability}'")
    decision = authorization.authorize(
        session, org.id, payload.principal, payload.capability, payload.targets,
        tool=payload.scanner, environment=payload.environment)
    if decision["decision"] == "deny":
        _audit_log(session, org.id, payload.actor, "orchestration.job_denied",
                   "scan_job", "-", decision["reason"][:300])
        session.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            f"not authorized: {decision['reason']}")
    pv_id = None
    if payload.project:
        project = (session.query(models.Project)
                   .filter_by(org_id=org.id, slug=payload.project).one_or_none())
        if project is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
        if payload.version:
            pv = (pick_version(session, project.id, payload.version))
            if pv is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "version not found")
            pv_id = pv.id
    row = models.ScanJob(
        org_id=org.id, project_version_id=pv_id, scanner=payload.scanner,
        capability=payload.capability, principal=payload.principal,
        environment=payload.environment, targets=json.dumps(payload.targets),
        profile=json.dumps(payload.profile), status="queued",
        priority=payload.priority, attempts=0,
        max_attempts=payload.max_attempts,
        authorization=json.dumps(decision), created_by=payload.actor,
        created_at=models.utcnow())
    session.add(row)
    session.flush()
    _audit_log(session, org.id, payload.actor, "orchestration.job_queued",
               "scan_job", row.id, f"{payload.scanner} {payload.capability}")
    session.commit()
    return {"data": _job_data(row)}


@router.get("/jobs")
def list_jobs(status_filter: str | None = None,
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    # A CI Action is a pipeline row and is read on its own screen; this list is
    # the scanner fleet — what a person started from the CLI or the console.
    query = (session.query(models.ScanJob)
             .filter(models.ScanJob.org_id == org.id,
                     models.ScanJob.origin != "ci"))
    if status_filter:
        query = query.filter_by(status=status_filter)
    rows = (query.order_by(models.ScanJob.priority, models.ScanJob.created_at)
            .limit(200).all())
    return {"data": [_job_data(r) for r in rows], "total": len(rows)}


class ClaimIn(BaseModel):
    worker_id: str
    actor: str = Field(min_length=2, max_length=255)


@router.post("/jobs/claim")
def claim_job(payload: ClaimIn = None,
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session),
              x_worker_token: str = Header(default="", alias="X-Worker-Token")):
    """Lease the next authorized job for a worker, re-validating authorization."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    _assert_worker_identity(session, x_worker_token, payload.worker_id)
    worker = session.get(models.Worker, payload.worker_id)
    if worker is None or worker.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "worker not found")
    now = _aware(models.utcnow())
    if (now - _aware(worker.last_heartbeat)).total_seconds() > HEARTBEAT_STALE_SECONDS:
        raise HTTPException(status.HTTP_409_CONFLICT, "worker heartbeat is stale")
    active = (session.query(models.ScanJob)
              .filter_by(org_id=org.id, worker_id=worker.id)
              .filter(models.ScanJob.status.in_(["leased", "running"])).count())
    if active >= worker.max_concurrent:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"worker at concurrency limit ({worker.max_concurrent})")
    # Recycle expired leases first (attempts ceiling enforced).
    expired = (session.query(models.ScanJob).filter_by(org_id=org.id)
               .filter(models.ScanJob.status.in_(["leased", "running"]))
               .filter(models.ScanJob.lease_expires_at.isnot(None)).all())
    for job in expired:
        if job.lease_expires_at and _aware(job.lease_expires_at) < now:
            if job.attempts >= job.max_attempts:
                job.status = "failed"
                job.error = "lease expired and max attempts reached"
                job.finished_at = models.utcnow()
            else:
                job.status = "queued"
                job.worker_id = None
                job.lease_expires_at = None
    session.flush()

    capabilities = set(json.loads(worker.capabilities or "[]"))
    candidate = None
    for job in (session.query(models.ScanJob).filter_by(org_id=org.id, status="queued")
                .order_by(models.ScanJob.priority, models.ScanJob.created_at).all()):
        if capabilities and job.capability not in capabilities:
            continue
        candidate = job
        break
    if candidate is None:
        return {"data": None}
    decision = authorization.authorize(
        session, org.id, candidate.principal, candidate.capability,
        json.loads(candidate.targets or "[]"), tool=candidate.scanner,
        environment=candidate.environment)
    candidate.attempts += 1
    if decision["decision"] == "deny":
        candidate.status = "failed"
        candidate.error = f"authorization revalidation denied: {decision['reason']}"[:500]
        candidate.finished_at = models.utcnow()
        _audit_log(session, org.id, payload.actor, "orchestration.job_revalidation_denied",
                   "scan_job", candidate.id, decision["reason"][:300])
        session.commit()
        return {"data": None,
                "rejected": {"job_id": candidate.id, "reason": decision["reason"]}}
    candidate.status = "leased"
    candidate.worker_id = worker.id
    candidate.lease_expires_at = now + datetime.timedelta(seconds=LEASE_SECONDS)
    candidate.started_at = models.utcnow()
    candidate.authorization = json.dumps(decision)
    _audit_log(session, org.id, payload.actor, "orchestration.job_leased",
               "scan_job", candidate.id, worker.name)
    session.commit()
    return {"data": _job_data(candidate), "lease_seconds": LEASE_SECONDS}


@router.get("/jobs/{job_id}")
def get_job(job_id: str, org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    row = session.get(models.ScanJob, job_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "job not found")
    artifacts = (session.query(models.JobArtifact).filter_by(job_id=row.id)
                 .order_by(models.JobArtifact.created_at).all())
    return {"data": {**_job_data(row),
                     "artifacts": [{"id": a.id, "kind": a.kind,
                                    "size": len(a.content or "")} for a in artifacts]}}


class ProgressIn(BaseModel):
    actor: str = Field(min_length=2, max_length=255)
    note: str | None = None


@router.post("/jobs/{job_id}/start")
def start_job(job_id: str, payload: ProgressIn = None,
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session),
              x_worker_token: str = Header(default="", alias="X-Worker-Token")):
    """Worker acknowledges the lease; also the cancellation checkpoint."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    row = session.get(models.ScanJob, job_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "job not found")
    if row.status == "cancelled":
        return {"data": _job_data(row), "cancelled": True}
    if row.status != "leased":
        raise HTTPException(status.HTTP_409_CONFLICT, f"cannot start a {row.status} job")
    row.status = "running"
    session.commit()
    return {"data": _job_data(row), "cancelled": False}


class ResultIn(BaseModel):
    actor: str = Field(min_length=2, max_length=255)
    outcome: str = Field(default="succeeded")
    summary: dict = {}
    artifacts: list[dict] = []
    error: str | None = None


@router.post("/jobs/{job_id}/result")
def submit_result(job_id: str, payload: ResultIn = None,
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session),
                  x_worker_token: str = Header(default="", alias="X-Worker-Token")):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.outcome not in {"succeeded", "failed"}:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "outcome must be succeeded | failed")
    row = session.get(models.ScanJob, job_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "job not found")
    if row.status not in {"leased", "running"}:
        raise HTTPException(status.HTTP_409_CONFLICT, f"cannot complete a {row.status} job")
    row.status = payload.outcome
    row.result = json.dumps(payload.summary)
    row.error = payload.error
    row.finished_at = models.utcnow()
    row.lease_expires_at = None
    for artifact in payload.artifacts[:20]:
        session.add(models.JobArtifact(
            org_id=org.id, job_id=row.id, kind=str(artifact.get("kind", "log"))[:32],
            content=str(artifact.get("content", ""))[:200000],
            created_at=models.utcnow()))
    _audit_log(session, org.id, payload.actor, f"orchestration.job_{payload.outcome}",
               "scan_job", row.id, json.dumps(payload.summary)[:300])
    session.commit()
    return {"data": _job_data(row)}


class CancelIn(BaseModel):
    actor: str = Field(min_length=2, max_length=255)
    reason: str | None = None


@router.post("/jobs/{job_id}/cancel")
def cancel_job(job_id: str, payload: CancelIn = None,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    row = session.get(models.ScanJob, job_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "job not found")
    if row.status in {"succeeded", "failed", "cancelled"}:
        raise HTTPException(status.HTTP_409_CONFLICT, f"job already {row.status}")
    row.status = "cancelled"
    row.error = payload.reason
    row.finished_at = models.utcnow()
    row.lease_expires_at = None
    _audit_log(session, org.id, payload.actor, "orchestration.job_cancelled",
               "scan_job", row.id, (payload.reason or "")[:200])
    session.commit()
    return {"data": _job_data(row)}


class RetryIn(BaseModel):
    actor: str = Field(min_length=2, max_length=255)


@router.post("/jobs/{job_id}/retry")
def retry_job(job_id: str, payload: RetryIn = None,
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    row = session.get(models.ScanJob, job_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "job not found")
    if row.status not in {"failed", "cancelled"}:
        raise HTTPException(status.HTTP_409_CONFLICT, "only failed/cancelled jobs retry")
    decision = authorization.authorize(
        session, org.id, row.principal, row.capability,
        json.loads(row.targets or "[]"), tool=row.scanner, environment=row.environment)
    if decision["decision"] == "deny":
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            f"not authorized: {decision['reason']}")
    row.status = "queued"
    row.worker_id = None
    row.lease_expires_at = None
    row.finished_at = None
    row.error = None
    row.authorization = json.dumps(decision)
    _audit_log(session, org.id, payload.actor, "orchestration.job_requeued",
               "scan_job", row.id, row.scanner)
    session.commit()
    return {"data": _job_data(row)}


@router.get("/jobs/{job_id}/artifacts")
def list_artifacts(job_id: str, org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    row = session.get(models.ScanJob, job_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "job not found")
    rows = (session.query(models.JobArtifact).filter_by(job_id=row.id)
            .order_by(models.JobArtifact.created_at).all())
    return {"data": [{"id": a.id, "kind": a.kind, "content": a.content,
                      "created_at": a.created_at.isoformat()} for a in rows],
            "total": len(rows)}


class WorkerTokenIn(BaseModel):
    label: str | None = None
    expires_hours: int | None = Field(default=None, ge=1, le=8760)
    actor: str = Field(min_length=2, max_length=255)


def _token_data(row: models.WorkerToken) -> dict:
    return {"id": row.id, "worker_id": row.worker_id, "label": row.label,
            "created_at": row.created_at.isoformat(),
            "expires_at": row.expires_at.isoformat() if row.expires_at else None,
            "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None,
            "last_used_at": row.last_used_at.isoformat() if row.last_used_at else None}


@router.post("/workers/{worker_id}/tokens")
def issue_worker_token(worker_id: str, payload: WorkerTokenIn = None,
                       org: models.Organization = Depends(auth.require_admin),
                       session: Session = Depends(get_session)):
    """Mint a scoped credential; the raw value is returned exactly once."""
    import datetime as _dt
    import hashlib
    import secrets as _secrets

    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    worker = session.get(models.Worker, worker_id)
    if worker is None or worker.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "worker not found")
    raw = _secrets.token_urlsafe(32)
    now = models.utcnow()
    row = models.WorkerToken(
        org_id=org.id, worker_id=worker.id,
        token_hash=hashlib.sha256(raw.encode()).hexdigest(),
        label=(payload.label or "worker")[:128], created_at=now,
        expires_at=(now + _dt.timedelta(hours=payload.expires_hours)
                    if payload.expires_hours else None))
    session.add(row)
    session.flush()
    _audit_log(session, org.id, payload.actor, "orchestration.worker_token_issued",
               "worker", worker.id, row.label or "")
    session.commit()
    return {"data": {**_token_data(row), "token": raw}}


@router.get("/workers/{worker_id}/tokens")
def list_worker_tokens(worker_id: str,
                       org: models.Organization = Depends(auth.require_admin),
                       session: Session = Depends(get_session)):
    worker = session.get(models.Worker, worker_id)
    if worker is None or worker.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "worker not found")
    rows = (session.query(models.WorkerToken).filter_by(worker_id=worker.id)
            .order_by(models.WorkerToken.created_at.desc()).all())
    return {"data": [_token_data(r) for r in rows], "total": len(rows)}


class TokenRevokeIn(BaseModel):
    actor: str = Field(min_length=2, max_length=255)
    reason: str | None = None


@router.post("/worker-tokens/{token_id}/revoke")
def revoke_worker_token(token_id: str, payload: TokenRevokeIn = None,
                        org: models.Organization = Depends(auth.require_admin),
                        session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    row = session.get(models.WorkerToken, token_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "token not found")
    if row.revoked_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "already revoked")
    row.revoked_at = models.utcnow()
    _audit_log(session, org.id, payload.actor, "orchestration.worker_token_revoked",
               "worker", row.worker_id, (payload.reason or "")[:200])
    session.commit()
    return {"data": _token_data(row)}


# ── internal scans: jobs the platform runs itself ────────────────────────────
# `scan_jobs` is work handed to a worker. The advisory clock runs inside the
# platform, and still needs the same three answers the console asks of a scan:
# what ran, when it runs next, and what it did the last time.

INTERNAL_SCANS = {
    "advisory-clock": {
        "label": "internal-scan",
        "title": "Advisory clock",
        "description": ("Re-asks OSV about every package and NVD about every runtime in the "
                        "current builds, refreshes KEV/EPSS, and announces what is new."),
    },
}


class RunNowIn(BaseModel):
    actor: str = Field(default="console", min_length=2, max_length=255)


def _iso(value) -> str | None:
    return value.isoformat() if value is not None else None


STALE_RUN_MINUTES = 60


def _internal_run_data(row: models.InternalRun, *, with_log: bool = False) -> dict:
    status = row.status
    # A process killed mid-sweep leaves its row "running" forever. Saying so is
    # better than a spinner that never ends; the next run is unaffected.
    if status == "running" and row.started_at is not None:
        started = _aware(row.started_at)
        if (models.utcnow() - started).total_seconds() > STALE_RUN_MINUTES * 60:
            status = "stale"
    data = {"id": row.id, "name": row.name, "trigger": row.trigger, "status": status,
            "started_at": _iso(row.started_at), "finished_at": _iso(row.finished_at),
            "duration_ms": row.duration_ms, "actor": row.actor,
            "counters": json.loads(row.counters or "{}")}
    if with_log:
        data["log"] = row.log or ""
    return data


@router.get("/internal")
def list_internal_scans(org: models.Organization = Depends(auth.require_org),
                        session: Session = Depends(get_session)):
    """The internal jobs, their schedule, their last run and their history."""
    config = advisories.load(session)
    next_due = None
    if config.get("last_tick_at"):
        try:
            last = datetime.datetime.fromisoformat(config["last_tick_at"])
            last = _aware(last)
            next_due = (last + datetime.timedelta(hours=config["interval_hours"])).isoformat()
        except (TypeError, ValueError):
            next_due = None
    rows = (session.query(models.InternalRun)
            .filter_by(org_id=org.id, name="advisory-clock")
            .order_by(models.InternalRun.started_at.desc()).limit(20).all())
    return {"data": [{
        **INTERNAL_SCANS["advisory-clock"],
        "name": "advisory-clock",
        "enabled": config["enabled"],
        "autorun": config["autorun"],
        "sources": {key: config[key] for key in ("osv", "cpe", "kev", "epss")},
        "schedule": {"interval_hours": config["interval_hours"],
                     "last_run_at": config.get("last_tick_at"), "next_due_at": next_due,
                     "max_versions": config["max_versions"]},
        "last_run": _internal_run_data(rows[0]) if rows else None,
        "runs": [_internal_run_data(row) for row in rows],
    }]}


@router.post("/internal/{name}/run")
def run_internal_scan(name: str, payload: RunNowIn = None,
                      org: models.Organization = Depends(auth.require_admin),
                      session: Session = Depends(get_session)):
    """Run an internal job now, whatever the interval says.

    The sweep reaches OSV and NVD, so it is an admin action; the run is recorded
    with `trigger=manual` so the history never confuses a push with the clock.
    """
    if name not in INTERNAL_SCANS:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            f"unknown internal scan; try {sorted(INTERNAL_SCANS)}")
    payload = payload or RunNowIn()
    counters = advisories.run(session, org.id, force=True, trigger="manual",
                              actor=payload.actor)
    session.commit()
    row = (session.query(models.InternalRun)
           .filter_by(org_id=org.id, name=name)
           .order_by(models.InternalRun.started_at.desc()).first())
    _audit_log(session, org.id, payload.actor, "orchestration.internal.run", "internal_run",
               row.id if row else None, f"{name}: {counters.get('status')}")
    session.commit()
    return {"data": {"counters": counters,
                     "run": _internal_run_data(row, with_log=True) if row else None}}


@router.get("/internal/runs/{run_id}")
def internal_run(run_id: str, org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """One run, log included: what it touched and what it could not reach."""
    row = session.get(models.InternalRun, run_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    return {"data": _internal_run_data(row, with_log=True)}

"""The flow: a timeline of events, and `status` as its projection.

Nothing here rewrites history. A flow that was abandoned and later answered keeps
`status=abandoned` forever and gains `revived_at` + one more entry in the
timeline — because the interesting fact is not "it worked", it is "we gave up on
it and the evidence arrived anyway".

Two clocks per event: `at_server` orders, `at_client` is evidence. A laptop with a
wrong clock must not be able to reorder the story.
"""
from __future__ import annotations

import datetime
import json

from sqlalchemy.orm import Session

from backend.app import models

# queued/leased/running belong to the retired claim path; they are still readable
# but nothing writes them from here.
ACTIVE = {"requested", "delivered", "accepted", "running", "cancel_requested"}
TERMINAL = {"finished", "failed", "cancelled", "abandoned", "rejected",
            "undelivered"}
EVIDENCE_KINDS = {"sbom", "misconfig", "secrets", "sast"}
EVIDENCE_STATES = ("none", "partial", "complete")
ALIVE_WINDOW_S = 120

# Event kind → the status it projects. `progress` and `revoked_mid_run` change
# nothing: they are facts to read, not transitions.
EVENT_STATUS = {
    "accepted": "accepted",
    "started": "running",
    "finished": "finished",
    "failed": "failed",
    "cancelled": "cancelled",
    "rejected": "rejected",
    "undelivered": "undelivered",
    # The sweeper's verdict. Unmapped, the sweep would write the event and leave
    # the flow standing — a silent failure that reads as "still running".
    "abandoned": "abandoned",
}


def _now() -> datetime.datetime:
    return models.utcnow()


def aware(value: datetime.datetime | None) -> datetime.datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)


def next_seq(session: Session, job_id: str) -> int:
    row = (session.query(models.ScanEvent.seq)
           .filter(models.ScanEvent.job_id == job_id)
           .order_by(models.ScanEvent.seq.desc()).first())
    return (row[0] + 1) if row and row[0] is not None else 1


def append(session: Session, job: models.ScanJob, kind: str, *,
           source: str = "platform", actor: str | None = None,
           host: str | None = None,
           at_client: datetime.datetime | None = None,
           detail: dict | None = None) -> models.ScanEvent:
    """Append one timeline line. Server time is stamped here, always."""
    event = models.ScanEvent(
        org_id=job.org_id, job_id=job.id, seq=next_seq(session, job.id),
        kind=kind, source=source, actor=actor, host=host,
        at_server=_now(), at_client=at_client,
        detail=json.dumps(detail or {}, sort_keys=True))
    session.add(event)
    job.last_event_at = event.at_server
    session.flush()
    return event


def apply_status(job: models.ScanJob, kind: str,
                 at: datetime.datetime | None = None) -> None:
    """Project a transition; terminal statuses are never overwritten later."""
    new = EVENT_STATUS.get(kind)
    if new is None:
        return
    if job.status in TERMINAL and new != job.status:
        # A late event may revive evidence, never rewrite the verdict.
        return
    job.status = new
    if new == "running" and job.started_at is None:
        job.started_at = at or _now()
    if new in TERMINAL:
        job.finished_at = at or _now()
    if new == "cancelled":
        job.cancelled_at = at or _now()


def recompute_evidence(session: Session, job: models.ScanJob) -> str:
    """`complete` means one artifact per required task — nothing less."""
    required = [t["task"] for t in json.loads(job.tasks or "[]")
                if t.get("required", True)]
    kinds = {row.kind for row in
             session.query(models.JobArtifact).filter_by(job_id=job.id).all()
             if row.kind in EVIDENCE_KINDS}
    if not kinds:
        state = "none"
    elif set(required) <= kinds:
        state = "complete"
    else:
        state = "partial"
    job.evidence_state = state
    return state


def newer_flow_exists(session: Session, job: models.ScanJob) -> bool:
    """A newer flow for the same subject owns the commit; the old one may not
    claim it back. Without this, two flows race to be the reference."""
    subject = json.loads(job.subject or "{}")
    key = (subject.get("project"), subject.get("commit"))
    rows = (session.query(models.ScanJob)
            .filter(models.ScanJob.org_id == job.org_id,
                    models.ScanJob.id != job.id,
                    models.ScanJob.created_at > job.created_at)
            .all())
    for row in rows:
        other = json.loads(row.subject or "{}")
        if (other.get("project"), other.get("commit")) == key:
            return True
    return False


def revive(session: Session, job: models.ScanJob, reason: str) -> bool:
    """Bring an abandoned flow back to life for its evidence, once per cycle."""
    if job.status != "abandoned":
        return False
    if job.revival_count:
        # One revival per flow. A second silent cycle is a new flow, so the
        # timeline can never pretend a single flow was abandoned twice.
        return False
    if newer_flow_exists(session, job):
        return False
    gap = None
    if job.finished_at is not None:
        gap = int((_now() - aware(job.finished_at)).total_seconds())
    job.revived_at = _now()
    job.revival_count = (job.revival_count or 0) + 1
    append(session, job, "revived", source="platform",
           detail={"reason": reason, "abandoned_for_s": gap,
                   "revivals": job.revival_count})
    return True


def sweep(session: Session, org_id: str | None = None,
          limit: int = 500) -> list[dict]:
    """Declare silent flows abandoned. Only the platform may say this: the party
    that vanished cannot testify about itself."""
    now = _now()
    query = session.query(models.ScanJob).filter(
        models.ScanJob.status.in_(sorted(ACTIVE)),
        models.ScanJob.deadline_at.isnot(None))
    if org_id:
        query = query.filter(models.ScanJob.org_id == org_id)
    results = []
    for job in query.order_by(models.ScanJob.created_at).limit(limit).all():
        deadline = aware(job.deadline_at)
        if deadline is None or deadline >= now:
            continue
        last = aware(job.last_event_at) or aware(job.created_at)
        gap = int((now - last).total_seconds()) if last else None
        append(session, job, "lease_expired", source="platform",
               detail={"last_event_at": last.isoformat() if last else None,
                       "gap_s": gap, "deadline_at": deadline.isoformat()})
        apply_status(job, "abandoned", at=now)
        append(session, job, "abandoned", source="platform",
               detail={"reason": "unreachable", "gap_s": gap,
                       "deadline_at": deadline.isoformat()})
        results.append({"job_id": job.id, "gap_s": gap})
    return results


def indicators(job: models.ScanJob, now: datetime.datetime | None = None) -> dict:
    """Three gauges the UI must never collapse into one badge."""
    moment = now or _now()
    last = aware(job.last_event_at)
    deadline = aware(job.deadline_at)
    age = int((moment - aware(job.created_at)).total_seconds()) if job.created_at else None
    since = int((moment - last).total_seconds()) if last else None
    alive = bool(since is not None and since <= ALIVE_WINDOW_S
                 and job.status not in TERMINAL)
    return {
        "alive": alive,
        "seconds_since_event": since,
        "age_s": age,
        "overdue": bool(deadline and deadline < moment
                        and job.status in ACTIVE),
        "killable": job.executor == "shauron" and job.status in ACTIVE,
        "terminal": job.status in TERMINAL,
    }


def to_data(session: Session, job: models.ScanJob) -> dict:
    subject = json.loads(job.subject or "{}")
    authorization = json.loads(job.authorization) if job.authorization else {}
    return {
        "id": job.id,
        "status": job.status,
        "evidence": job.evidence_state,
        "origin": job.origin,
        "executor": job.executor,
        "tasks": json.loads(job.tasks or "[]"),
        "subject": subject,
        "project": subject.get("project"),
        "version": subject.get("version"),
        "daemon": job.daemon_url,
        "scanner": job.scanner,
        "principal": job.principal,
        "environment": job.environment,
        "actor": job.created_by,
        "policy_version": authorization.get("policy_version"),
        "grant_id": (authorization.get("matched") or [None, None])[-1]
        if isinstance(authorization.get("matched"), list) else None,
        "capabilities": sorted({t["capability"] for t in json.loads(job.tasks or "[]")}),
        "deadline_at": aware(job.deadline_at).isoformat() if job.deadline_at else None,
        "last_event_at": aware(job.last_event_at).isoformat() if job.last_event_at else None,
        "revived_at": aware(job.revived_at).isoformat() if job.revived_at else None,
        "revival_count": job.revival_count or 0,
        "created_at": aware(job.created_at).isoformat() if job.created_at else None,
        "started_at": aware(job.started_at).isoformat() if job.started_at else None,
        "finished_at": aware(job.finished_at).isoformat() if job.finished_at else None,
        "error": job.error,
        "indicators": indicators(job),
    }

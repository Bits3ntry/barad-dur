"""v01 scan flows: mint a signed ticket, follow the timeline, ingest evidence.

Two kinds of authentication, deliberately different:

- **Platform routes** (`POST /scans`, list, timeline, cancel, sweep, key) use the
  normal organization credential.
- **Executor routes** (`/scans/{id}/events`, `/scans/{id}/evidence`) authenticate
  with the ticket's own `upload_token`. A daemon holds no API key, and giving it
  one would hand a scanner the whole organization.

Route order matters: `/scans/actions`, `/scans/key` and `/scans/sweep` are
declared before `/scans/{job_id}`, or the path parameter swallows them.
"""
from __future__ import annotations

import datetime
import hashlib
import json
import os
import secrets as pysecrets
import urllib.error
import urllib.request

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import authorization, models, scan_actions, scan_flow, shauron_signing
from backend.app.auth import require_org
from backend.app.db import get_session
from backend.app.projects import by_ref
from backend.app.routers.identity import _audit as _audit_log
from backend.app.versions import pick_version

router = APIRouter(prefix="/api/v1", tags=["scans"])

# Pinned on this side and validated against `shauron/VERSION` in the tests: a
# drift fails a build, never a scan at 3am.
SUPPORTED_CONTRACT = "1.0.0"
DAEMON_ENV = "SHAURON_DAEMON_URL"
TOKEN_HEADER = "X-Ticket-Token"
ORIGINS = {"ci", "cli", "console", "api"}
EXECUTORS = {"shauron", "external"}


def _now() -> datetime.datetime:
    return models.utcnow()


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _parse_ts(value: str | None, field: str) -> datetime.datetime | None:
    if value in (None, ""):
        return None
    try:
        parsed = datetime.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"{field} must be ISO-8601") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=datetime.timezone.utc)


def _post_json(url: str, payload: dict, timeout: float = 5.0) -> tuple[int, dict]:
    """Deliver a ticket. urllib on purpose: the API image must not depend on an
    HTTP client that only the test extra installs."""
    request = urllib.request.Request(
        url, data=json.dumps(payload).encode(), method="POST")
    request.add_header("Content-Type", "application/json")
    request.add_header("Accept", "application/json")
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode() or "{}"
            return response.status, json.loads(body)
    except urllib.error.HTTPError as exc:
        body = exc.read().decode()[:600]
        try:
            return exc.code, json.loads(body)
        except json.JSONDecodeError:
            return exc.code, {"error": "http_error", "reason": body}
    except Exception as exc:  # unreachable daemon, DNS, timeout
        return 0, {"error": "unreachable", "reason": f"{type(exc).__name__}: {exc}"}


def _job_or_404(session: Session, org_id: str, job_id: str) -> models.ScanJob:
    job = session.get(models.ScanJob, job_id)
    if job is None or job.org_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan flow not found")
    return job


def _token_authorized(job: models.ScanJob, token: str) -> bool:
    if not token or not job.upload_token_hash:
        return False
    return pysecrets.compare_digest(job.upload_token_hash, _hash(token))


def _job_by_ticket(session: Session, ticket_id: str, token: str) -> models.ScanJob:
    job = session.get(models.ScanJob, ticket_id)
    if job is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scan flow not found")
    if not _token_authorized(job, token):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            "ticket token missing or not valid for this flow")
    return job


# ── catalog ───────────────────────────────────────────────────────────────


@router.get("/scans/actions")
def list_actions(org: models.Organization = Depends(require_org)) -> dict:
    data = scan_actions.catalog()
    return {"data": data, "total": len(data)}


@router.get("/scans/key")
def signing_key(org: models.Organization = Depends(require_org),
                session: Session = Depends(get_session)) -> dict:
    """The public half only. `source` says where the private key lives so the
    operator can move it out of the database without guessing."""
    return {"data": {
        "key_id": shauron_signing.KEY_ID,
        "public_key": shauron_signing.public_key_b64(session),
        "algorithm": "ed25519",
        "source": shauron_signing.key_source(session),
        "contract_version": SUPPORTED_CONTRACT,
    }}


@router.post("/scans/sweep")
def sweep(org: models.Organization = Depends(require_org),
          session: Session = Depends(get_session),
          limit: int = Query(default=200, ge=1, le=1000)) -> dict:
    """Declare silent flows abandoned. Idempotent, safe from cron."""
    rows = scan_flow.sweep(session, org.id, limit=limit)
    session.commit()
    return {"data": rows, "abandoned": len(rows)}


# ── mint ──────────────────────────────────────────────────────────────────


class ScanIn(BaseModel):
    action: str = Field(min_length=2, max_length=64)
    project: str = Field(min_length=1, max_length=255)
    version: str | None = Field(default=None, max_length=255)
    repository: str | None = Field(default=None, max_length=2048)
    commit: str | None = Field(default=None, max_length=64)
    branch: str | None = Field(default=None, max_length=255)
    pull_request: str | None = Field(default=None, max_length=64)
    base_commit: str | None = Field(default=None, max_length=64)
    paths: list[str] | None = None
    targets: list[dict] | None = None
    origin: str = "console"
    executor: str = "shauron"
    principal: str | None = Field(default=None, max_length=255)
    environment: str | None = Field(default=None, max_length=128)
    coverage: str | None = None
    daemon_url: str | None = Field(default=None, max_length=512)
    actor: str = Field(default="console", min_length=2, max_length=255)


def _resolve_repository(session: Session, org_id: str, ref: str | None,
                        project_id: str) -> models.Repository | None:
    if ref:
        row = session.get(models.Repository, ref)
        if row is None:
            row = (session.query(models.Repository)
                   .filter_by(org_id=org_id, remote_url=ref).one_or_none())
        if row is None or row.org_id != org_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                "repository not found in this organization")
        return row
    link = (session.query(models.ProjectRepository)
            .filter_by(project_id=project_id)
            .filter(models.ProjectRepository.removed_at.is_(None))
            .order_by(models.ProjectRepository.added_at).first())
    return session.get(models.Repository, link.repository_id) if link else None


@router.post("/scans", status_code=status.HTTP_201_CREATED)
def create_scan(payload: ScanIn,
                org: models.Organization = Depends(require_org),
                session: Session = Depends(get_session)) -> dict:
    """Mint one flow: resolve scope, decide authorization once, sign, deliver."""
    action = scan_actions.action(payload.action)
    if action is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"unknown action '{payload.action}'; known: {sorted(scan_actions.ACTIONS)}")
    if payload.origin not in ORIGINS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"origin must be one of {sorted(ORIGINS)}")
    if payload.executor not in EXECUTORS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"executor must be one of {sorted(EXECUTORS)}")

    project = by_ref(session, org.id, payload.project)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    version_row = pick_version(session, project.id, payload.version) \
        if payload.version else None
    if payload.version and version_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")

    repository = _resolve_repository(session, org.id, payload.repository, project.id)
    if action["target"] == "repository" and repository is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"no repository is bound to project '{project.slug}'; bind one before "
            "asking for a code scan")

    commit = (payload.commit or "").strip().lower()
    if not commit and repository is not None:
        commit = (repository.last_commit_sha or "").strip().lower()
    if action["target"] == "repository" and not (len(commit) == 40 and all(
            ch in "0123456789abcdef" for ch in commit)):
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "commit must be a 40-character sha; a scan without an exact commit "
            "would report on code nobody can reopen")

    tasks = scan_actions.build_tasks(payload.action)
    capabilities = scan_actions.capabilities_of(tasks)
    principal = payload.principal or payload.actor

    if payload.targets:
        targets = [{"type": str(t["type"]), "value": str(t["value"])}
                   for t in payload.targets if t.get("type") and t.get("value")]
    elif repository is not None:
        targets = [{"type": "repository", "value": repository.remote_url}]
    else:
        targets = []
    if not targets:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "this action needs at least one target")

    now = _now()
    if payload.origin in {"ci", "cli"}:
        allowed, why = scan_actions.push_allowed(tasks, network=bool(action["network"]))
        if not allowed:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, why)
        decision = {
            "decision": "push", "policy_version": authorization.POLICY_VERSION,
            "capabilities": capabilities, "principal": principal,
            "grant_id": None, "environment": payload.environment,
            "scope": targets, "not_after": None,
            "reason": "push: the caller holds the code; the repository binding "
                      "is the authorization",
        }
    else:
        # `authorize()` evaluates ONE capability per call (its comma support is
        # for revalidation only), so a task set spanning several capabilities is
        # authorized one by one and every one must be allowed. Two grants may
        # legitimately cover two capabilities.
        decisions = [
            authorization.authorize(
                session, org.id, principal, capability, targets,
                environment=payload.environment)
            for capability in capabilities
        ]
        denied = [(capability, item)
                  for capability, item in zip(capabilities, decisions)
                  if item["decision"] == "deny"]
        if denied:
            # Name the capability that is missing: "no grant covers this" without
            # saying which one sends the operator hunting through the wrong grant.
            reason = "; ".join(f"{capability}: {item['reason']}"
                               for capability, item in denied)
            _audit_log(session, org.id, payload.actor, "scan.denied",
                       "scan_job", "-", reason[:300])
            session.commit()
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f"not authorized: {reason}")
        decision = {
            **decisions[0],
            "capabilities": capabilities,
            "decision": "allow",
        }

    deadline_at = now + datetime.timedelta(seconds=int(action["deadline_s"]))
    upload_token = "ut_" + pysecrets.token_hex(16)
    job_id = models.uuid_hex()
    daemon = (payload.daemon_url or os.environ.get(DAEMON_ENV) or "").rstrip("/") \
        if payload.executor == "shauron" else ""
    subject = {
        "project": project.slug, "version": version_row.version if version_row else None,
        "repository": repository.remote_url if repository else None,
        "repository_name": repository.name if repository else None,
        "commit": commit or None, "branch": payload.branch,
        "pull_request": payload.pull_request, "base_commit": payload.base_commit,
        "paths": payload.paths or [], "environment": payload.environment,
    }

    job = models.ScanJob(
        id=job_id, org_id=org.id,
        project_version_id=version_row.id if version_row else None,
        scanner="shaurond", capability=",".join(capabilities)[:64],
        principal=principal, environment=payload.environment,
        targets=json.dumps(targets, sort_keys=True),
        profile=json.dumps({"action": payload.action, "paths": payload.paths or []}),
        status="requested", priority=5, attempts=0, max_attempts=3,
        authorization=json.dumps(decision, sort_keys=True),
        created_by=payload.actor, created_at=now,
        origin=payload.origin, executor=payload.executor,
        tasks=json.dumps(tasks, sort_keys=True),
        subject=json.dumps(subject, sort_keys=True),
        contract_version=SUPPORTED_CONTRACT, deadline_at=deadline_at,
        evidence_state="none", upload_token_hash=_hash(upload_token),
        daemon_url=daemon or None,
    )
    session.add(job)
    session.flush()

    scan_flow.append(session, job, "requested", source="platform",
                     actor=payload.actor,
                     detail={"action": payload.action, "tasks": tasks,
                             "targets": targets, "origin": payload.origin,
                             "principal": principal})
    ticket = shauron_signing.sign_ticket(session, {
        "schema": "barad-ticket-v1",
        "contract_version": SUPPORTED_CONTRACT,
        "ticket_id": job.id,
        "issued_at": now.isoformat(),
        "not_after": deadline_at.isoformat(),
        "origin": payload.origin,
        "project": {"slug": project.slug, "name": project.name},
        "version": version_row.version if version_row else None,
        "target": {
            "kind": action["target"],
            "repository": ({"remote_url": repository.remote_url,
                            "provider": repository.provider} if repository else None),
            "ref": {"commit": commit or ("0" * 40), "branch": payload.branch,
                    "pull_request": payload.pull_request,
                    "base_commit": payload.base_commit},
            "paths": payload.paths or [],
            "environment": payload.environment,
        },
        "tasks": tasks,
        "execution": {
            "deadline_s": int(action["deadline_s"]),
            "hard_timeout_s": int(action["deadline_s"]) * 2,
            "network": bool(action["network"]),
            "isolation": action["isolation"],
            "coverage": payload.coverage or action["coverage"],
        },
        "authorization": {
            "decision": decision["decision"],
            "policy_version": decision["policy_version"],
            "capabilities": capabilities,
            "principal": principal,
            "grant_id": job.id,  # replaced below when a real grant matched
            "environment": payload.environment,
            "scope": targets,
            "not_after": deadline_at.isoformat(),
        },
        "evidence": {
            "sink": f"/api/v1/scans/{job.id}/evidence",
            "upload_token": upload_token,
            "accepted": sorted({t["contract"] for t in tasks} | {"text"}),
        },
        "callback": {"events": f"/api/v1/scans/{job.id}/events",
                     "cancel_token": None},
    })
    matched = decision.get("matched")
    ticket["authorization"]["grant_id"] = (
        matched[1] if isinstance(matched, list) and len(matched) == 2
        and matched[0] == "grant" else None)
    ticket = shauron_signing.sign_ticket(session, ticket)

    job.ticket_json = json.dumps(ticket, sort_keys=True)
    scan_flow.append(session, job, "minted", source="platform",
                     actor=payload.actor,
                     detail={"key_id": shauron_signing.KEY_ID,
                             "not_after": deadline_at.isoformat(),
                             "contract_version": SUPPORTED_CONTRACT})

    delivered = None
    if payload.executor == "shauron" and daemon:
        code, body = _post_json(f"{daemon}/tickets", ticket)
        if code in (200, 201):
            scan_flow.apply_status(job, "accepted", at=_now())
            scan_flow.append(session, job, "delivered", source="platform",
                             detail={"daemon": daemon})
            scan_flow.append(session, job, "accepted", source="shauron",
                             host=daemon,
                             detail=body.get("data") or {})
            delivered = "accepted"
        elif code == 0:
            scan_flow.apply_status(job, "undelivered", at=_now())
            scan_flow.append(session, job, "undelivered", source="platform",
                             detail={"daemon": daemon, **body})
            delivered = "undelivered"
        else:
            scan_flow.apply_status(job, "rejected", at=_now())
            job.error = str(body.get("reason") or body.get("error") or code)[:500]
            scan_flow.append(session, job, "rejected", source="shauron",
                             host=daemon, detail=body)
            delivered = "rejected"

    _audit_log(session, org.id, payload.actor, "scan.requested", "scan_job",
               job.id, f"{payload.action} {payload.origin} {delivered or 'pending'}")
    session.commit()
    return {"data": scan_flow.to_data(session, job), "ticket": ticket,
            "delivery": delivered or "pending"}


# ── read ──────────────────────────────────────────────────────────────────


@router.get("/scans")
def list_scans(status_filter: str | None = Query(default=None, alias="status"),
               project: str | None = Query(default=None),
               active_only: bool = Query(default=False),
               limit: int = Query(default=100, ge=1, le=500),
               org: models.Organization = Depends(require_org),
               session: Session = Depends(get_session)) -> dict:
    query = session.query(models.ScanJob).filter_by(org_id=org.id)
    if status_filter:
        query = query.filter_by(status=status_filter)
    if active_only:
        query = query.filter(models.ScanJob.status.in_(sorted(scan_flow.ACTIVE)))
    rows = query.order_by(models.ScanJob.created_at.desc()).limit(limit).all()
    if project:
        proj = by_ref(session, org.id, project)
        if proj is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
        rows = [r for r in rows
                if json.loads(r.subject or "{}").get("project") == proj.slug]
    data = [scan_flow.to_data(session, row) for row in rows]
    counters = {"total": len(data),
                "alive": sum(1 for item in data if item["indicators"]["alive"]),
                "abandoned": sum(1 for item in data if item["status"] == "abandoned"),
                "running": sum(1 for item in data if item["status"] == "running")}
    return {"data": data, "counters": counters}


@router.get("/scans/{job_id}")
def get_scan(job_id: str, org: models.Organization = Depends(require_org),
             session: Session = Depends(get_session)) -> dict:
    job = _job_or_404(session, org.id, job_id)
    artifacts = (session.query(models.JobArtifact).filter_by(job_id=job.id)
                 .order_by(models.JobArtifact.created_at).all())
    data = scan_flow.to_data(session, job)
    data["evidence_received"] = [
        {"kind": a.kind, "bytes": len(a.content or ""),
         "at": scan_flow.aware(a.created_at).isoformat() if a.created_at else None}
        for a in artifacts]
    data["ticket"] = json.loads(job.ticket_json) if job.ticket_json else None
    return {"data": data}


@router.get("/scans/{job_id}/timeline")
def scan_timeline(job_id: str, org: models.Organization = Depends(require_org),
                  session: Session = Depends(get_session)) -> dict:
    job = _job_or_404(session, org.id, job_id)
    rows = (session.query(models.ScanEvent).filter_by(job_id=job.id)
            .order_by(models.ScanEvent.seq).all())
    data = [{
        "seq": row.seq, "kind": row.kind, "source": row.source,
        "actor": row.actor, "host": row.host,
        "at_server": scan_flow.aware(row.at_server).isoformat(),
        "at_client": (scan_flow.aware(row.at_client).isoformat()
                      if row.at_client else None),
        "detail": json.loads(row.detail or "{}"),
    } for row in rows]
    return {"data": data, "total": len(data), "status": job.status,
            "evidence": job.evidence_state}


# ── executor routes (ticket token, not an API key) ────────────────────────


class EventIn(BaseModel):
    schema: str = "barad-event-v1"
    ticket_id: str
    event: str
    at: str | None = None
    detail: dict = {}


EVENT_KINDS = {"accepted", "started", "progress", "finished", "failed",
               "cancelled"}


@router.post("/scans/{job_id}/events")
def post_event(job_id: str, payload: EventIn,
               x_ticket_token: str = Header(default="", alias=TOKEN_HEADER),
               session: Session = Depends(get_session)) -> dict:
    job = _job_by_ticket(session, job_id, x_ticket_token)
    if payload.event not in EVENT_KINDS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"event must be one of {sorted(EVENT_KINDS)}")
    at_client = _parse_ts(payload.at, "at")
    scan_flow.append(session, job, payload.event, source="executor",
                     actor=(payload.detail or {}).get("actor"),
                     host=(payload.detail or {}).get("host"),
                     at_client=at_client, detail=payload.detail)
    scan_flow.apply_status(job, payload.event, at=at_client or _now())
    if payload.event == "finished":
        scan_flow.recompute_evidence(session, job)
    session.commit()
    return {"data": {"job_id": job.id, "status": job.status,
                     "evidence": job.evidence_state}}


class EvidenceIn(BaseModel):
    schema: str = "barad-evidence-v1"
    ticket_id: str
    kind: str
    tool: dict | None = None
    format: str
    coverage: str | None = None
    content_hash: str
    bytes: int | None = None
    evaluated: dict | None = None
    content: str | None = None


@router.post("/scans/{job_id}/evidence", status_code=status.HTTP_201_CREATED)
def post_evidence(job_id: str, payload: EvidenceIn,
                  x_ticket_token: str = Header(default="", alias=TOKEN_HEADER),
                  session: Session = Depends(get_session)) -> dict:
    """One call per artifact. Bound to the flow, hashed, and never a second
    ingestion implementation: parsing happens in the existing ingest paths."""
    job = _job_by_ticket(session, job_id, x_ticket_token)
    if payload.content is not None:
        actual = "sha256:" + hashlib.sha256(payload.content.encode()).hexdigest()
        if payload.content_hash and actual != payload.content_hash:
            scan_flow.append(session, job, "evidence_rejected", source="platform",
                             detail={"kind": payload.kind, "declared": payload.content_hash,
                                     "actual": actual})
            session.commit()
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                "evidence_corrupt: content_hash does not match the body")
    if payload.kind in scan_flow.EVIDENCE_KINDS and not payload.content:
        # The F1 sink binds and stores; it does not parse. An artifact with no
        # content is a claim, and a claim is not evidence.
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "content is required for an evidence artifact")

    revived = scan_flow.revive(session, job, reason="late_evidence")
    session.add(models.JobArtifact(
        org_id=job.org_id, job_id=job.id, kind=payload.kind,
        content=json.dumps({
            "schema": payload.schema, "format": payload.format,
            "tool": payload.tool, "coverage": payload.coverage,
            "content_hash": payload.content_hash, "bytes": payload.bytes,
            "evaluated": payload.evaluated or {}, "content": payload.content,
        }, sort_keys=True)[:800_000],
        created_at=_now()))
    session.flush()
    state = scan_flow.recompute_evidence(session, job)
    scan_flow.append(session, job, "evidence_received", source="executor",
                     detail={"kind": payload.kind, "format": payload.format,
                             "content_hash": payload.content_hash,
                             "revived": revived})
    if revived:
        _audit_log(session, job.org_id, "shauron", "scan.revived", "scan_job",
                   job.id, f"evidence after abandonment: {payload.kind}")
    session.commit()
    return {"data": {"job_id": job.id, "kind": payload.kind,
                     "evidence": state, "revived": revived,
                     "status": job.status}}


# ── control ───────────────────────────────────────────────────────────────


@router.post("/scans/{job_id}/cancel")
def cancel_scan(job_id: str, org: models.Organization = Depends(require_org),
                session: Session = Depends(get_session),
                actor: str = Query(default="console")) -> dict:
    """A human instruction, never a policy verdict. A revoked grant does not stop
    a run; this does."""
    job = _job_or_404(session, org.id, job_id)
    if job.status in scan_flow.TERMINAL:
        return {"data": scan_flow.to_data(session, job), "cancelled": False,
                "reason": f"already {job.status}"}
    if job.executor != "shauron" or not job.daemon_url:
        scan_flow.append(session, job, "cancelled", source="platform",
                         actor=actor, detail={"cause": "operator"})
        scan_flow.apply_status(job, "cancelled", at=_now())
        confirmed = "cancelled"
    else:
        code, body = _post_json(f"{job.daemon_url}/tickets/{job.id}/cancel", {})
        acknowledged = code in (200, 204) and body.get("cancelled", True) is not False
        scan_flow.append(session, job, "cancel_requested", source="platform",
                         actor=actor, detail={"cause": "operator", "daemon_code": code})
        if acknowledged:
            # The executor answered: that IS the fact. Waiting for a second
            # event it has no reason to send would leave the flow looking alive.
            scan_flow.append(session, job, "cancelled", source="executor",
                             host=job.daemon_url, detail={"cause": "operator"})
            scan_flow.apply_status(job, "cancelled", at=_now())
            confirmed = "confirmed"
        else:
            job.status = "cancel_requested"
            confirmed = "requested_not_confirmed"
    _audit_log(session, org.id, actor, "scan.cancel", "scan_job", job.id, confirmed)
    session.commit()
    return {"data": scan_flow.to_data(session, job), "cancelled": confirmed}

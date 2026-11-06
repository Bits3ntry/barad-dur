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

from fastapi import (APIRouter, Depends, Header, HTTPException, Query, Request,
                     status)
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app import (authorization, models, pipeline, scan_actions, scan_flow,
                         shauron_signing)
from backend.app.routers import findings as findings_router
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
    component: str | None = Field(default=None, max_length=255)
    version: str | None = Field(default=None, max_length=255)
    repository: str | None = Field(default=None, max_length=2048)
    commit: str | None = Field(default=None, max_length=64)
    branch: str | None = Field(default=None, max_length=255)
    pull_request: str | None = Field(default=None, max_length=64)
    # Who opened the pull request. The pusher and the author differ on every
    # fork and on every review re-run, and the console's "who" column is about
    # the person, not the machine that pressed the button.
    pull_request_author: str | None = Field(default=None, max_length=255)
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


class AttributionAssignmentIn(BaseModel):
    component: str = Field(min_length=1, max_length=255)
    version: str | None = Field(default=None, max_length=255)
    note: str | None = Field(default=None, max_length=2000)


def _repository_slug(ref: str | None) -> str | None:
    """`owner/name` out of whatever remote a CI produced.

    The same repository has many remotes: `https://host/owner/name.git`,
    `git@host:owner/name` or a bare `owner/name`. The platform registers ONE
    canonical remote, so a job running against a copy — a sandbox instance, a
    proxy, a mirror host — would be refused for a hostname it never promised.
    Owner and name are the identity; the host is transport.
    """
    value = (ref or "").strip().rstrip("/")
    if not value:
        return None
    if value.endswith(".git"):
        value = value[:-4]
    if "://" in value:
        rest = value.split("://", 1)[1]
        value = rest.split("/", 1)[1] if "/" in rest else ""
    elif "@" in value.split("/", 1)[0] and ":" in value:
        # scp-like: git@host:owner/name
        value = value.partition(":")[2]
    parts = [part for part in value.split("/") if part]
    if len(parts) < 2:
        return None
    return "/".join(parts[-2:])


def _resolve_repository(session: Session, org_id: str, ref: str | None,
                        project_id: str) -> models.Repository | None:
    if ref:
        row = session.get(models.Repository, ref)
        if row is None:
            row = (session.query(models.Repository)
                   .filter_by(org_id=org_id, remote_url=ref).one_or_none())
        if row is None:
            # A different host for the same `owner/name` is the same repository
            # (the sandbox Gitea and the real one are the same code); refusing it
            # on the hostname alone would block every pipeline not cloning from
            # the canonical URL. Ticket and subject still record the platform's
            # own remote_url, so nothing downstream inherits the copy's host.
            slug = _repository_slug(ref)
            if slug:
                row = (session.query(models.Repository)
                       .filter_by(org_id=org_id)
                       .filter(func.lower(models.Repository.name) == slug.lower())
                       .one_or_none())
        if row is None or row.org_id != org_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                f"repository not found in this organization: {ref}")
        return row
    link = (session.query(models.ProjectRepository)
            .filter_by(project_id=project_id)
            .filter(models.ProjectRepository.removed_at.is_(None))
            .order_by(models.ProjectRepository.added_at).first())
    return session.get(models.Repository, link.repository_id) if link else None


@router.post("/scans", status_code=status.HTTP_201_CREATED)
def create_scan(payload: ScanIn,
                org: models.Organization = Depends(require_org),
                session: Session = Depends(get_session)):
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
    repository = _resolve_repository(session, org.id, payload.repository, project.id)
    component = None
    candidates: list[models.ApplicationComponent] = []
    if repository is not None:
        candidates = (session.query(models.ApplicationComponent)
                      .join(models.ComponentRepository,
                            models.ComponentRepository.component_id
                            == models.ApplicationComponent.id)
                      .filter(models.ApplicationComponent.project_id == project.id,
                              models.ComponentRepository.repository_id == repository.id,
                              models.ComponentRepository.removed_at.is_(None)).all())
        if payload.component:
            candidates = [row for row in candidates
                          if row.id == payload.component or row.slug == payload.component
                          or row.name == payload.component]
        if len(candidates) == 1:
            component = candidates[0]
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

    if action["target"] == "repository" and repository is not None and component is None:
        intake = models.ScanAttributionIntake(
            org_id=org.id, project_id=project.id, repository_id=repository.id,
            reason="repository_has_no_unique_component",
            subject=json.dumps({
                "project": project.slug, "repository": repository.remote_url,
                "component": payload.component, "version": payload.version,
                "branch": payload.branch, "commit": payload.commit,
                "base_commit": payload.base_commit, "pull_request": payload.pull_request,
                "paths": payload.paths, "environment": payload.environment,
            }, sort_keys=True),
            candidate_component_ids=json.dumps([row.id for row in candidates]),
            created_by=principal,
        )
        session.add(intake)
        session.commit()
        return JSONResponse(status_code=status.HTTP_202_ACCEPTED, content={"data": {
            "id": intake.id, "status": "needs_attribution", "reason": intake.reason,
            "project": project.slug, "repository": repository.remote_url,
        }})

    version_row = pick_version(session, project.id, payload.version,
                               component.id if component else None) if payload.version else None
    if payload.version and version_row is None:
        if payload.origin in {"ci", "cli"}:
            version_row = models.ProjectVersion(
                project_id=project.id, component_id=component.id if component else None,
                version=payload.version)
            session.add(version_row)
            session.flush()
        else:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")

    deadline_at = now + datetime.timedelta(seconds=int(action["deadline_s"]))
    upload_token = "ut_" + pysecrets.token_hex(16)
    job_id = models.uuid_hex()
    daemon = (payload.daemon_url or os.environ.get(DAEMON_ENV) or "").rstrip("/") \
        if payload.executor == "shauron" else ""
    subject = {
        "project": project.slug, "component": component.slug if component else None,
        "component_id": component.id if component else None,
        "version": version_row.version if version_row else None,
        "repository": repository.remote_url if repository else None,
        "repository_name": repository.name if repository else None,
        "commit": commit or None, "branch": payload.branch,
        "pull_request": payload.pull_request, "base_commit": payload.base_commit,
        "pull_request_author": payload.pull_request_author,
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


@router.get("/scans/attribution-intakes")
def list_attribution_intakes(
        org: models.Organization = Depends(require_org),
        session: Session = Depends(get_session)) -> dict:
    rows = (session.query(models.ScanAttributionIntake)
            .filter(models.ScanAttributionIntake.org_id == org.id)
            .order_by(models.ScanAttributionIntake.created_at.desc()).all())
    return {"data": [{
        "id": row.id,
        "status": row.status,
        "reason": row.reason,
        "subject": json.loads(row.subject),
        "candidates": json.loads(row.candidate_component_ids),
        "created_at": row.created_at.isoformat(),
    } for row in rows]}


@router.post("/scans/attribution-intakes/{intake_id}/assign")
def assign_attribution_intake(
        intake_id: str,
        payload: AttributionAssignmentIn,
        org: models.Organization = Depends(require_org),
        session: Session = Depends(get_session)) -> dict:
    intake = (session.query(models.ScanAttributionIntake)
              .filter_by(id=intake_id, org_id=org.id).one_or_none())
    if intake is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "attribution intake not found")
    if intake.status != "needs_attribution":
        raise HTTPException(status.HTTP_409_CONFLICT, "attribution intake is already assigned")
    component = (session.query(models.ApplicationComponent)
                 .filter(models.ApplicationComponent.project_id == intake.project_id)
                 .filter((models.ApplicationComponent.id == payload.component)
                         | (models.ApplicationComponent.slug == payload.component)
                         | (models.ApplicationComponent.name == payload.component)).one_or_none())
    if component is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "component not found in intake project")
    if intake.repository_id and not (session.query(models.ComponentRepository)
                                     .filter_by(component_id=component.id,
                                                repository_id=intake.repository_id,
                                                removed_at=None).first()):
        session.add(models.ComponentRepository(
            org_id=org.id, component_id=component.id, repository_id=intake.repository_id,
            added_by="manual attribution"))
    version_row = None
    if payload.version:
        version_row = pick_version(session, intake.project_id, payload.version, component.id)
        if version_row is None:
            version_row = models.ProjectVersion(
                project_id=intake.project_id, component_id=component.id, version=payload.version)
            session.add(version_row)
    intake.status = "assigned"
    intake.assigned_at = datetime.datetime.now(datetime.UTC)
    intake.assigned_by = "manual attribution"
    intake.assignment_note = payload.note
    session.commit()
    return {"data": {
        "id": intake.id, "status": intake.status, "component": component.slug,
        "version": version_row.version if version_row else None,
    }}


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


@router.get("/scans/{job_id}/findings")
def scan_findings(job_id: str, limit: int = Query(default=200, ge=1, le=1000),
                  org: models.Organization = Depends(require_org),
                  session: Session = Depends(get_session)) -> dict:
    """What this run produced, by identity.

    A flow owns its artifacts, and every artifact is an analysis run; a finding
    records the run that last evaluated it. So the flow's result is the findings
    whose last evaluation was one of its own runs — no guessing from timestamps.
    """
    job = _job_or_404(session, org.id, job_id)
    run_ids = [row[0] for row in session.query(models.AnalysisRun.id)
               .filter(models.AnalysisRun.scan_job_id == job.id).all()]
    if not run_ids:
        return {"data": [], "counters": {"total": 0, "by_severity": {}}}

    rows = (session.query(models.Finding)
            .filter(models.Finding.org_id == org.id,
                    models.Finding.last_evaluated_run_id.in_(run_ids))
            .order_by(models.Finding.last_seen_at.desc())
            .limit(limit).all())
    data = [findings_router.finding_data(session, row) for row in rows]
    by_severity: dict[str, int] = {}
    for item in data:
        by_severity[item["severity"]] = by_severity.get(item["severity"], 0) + 1
    return {"data": data, "counters": {"total": len(data), "by_severity": by_severity}}


@router.get("/scans/{job_id}/state")
def scan_state(job_id: str,
               x_ticket_token: str = Header(default="", alias=TOKEN_HEADER),
               session: Session = Depends(get_session)) -> dict:
    """Executor-scoped read: the one thing a runner may ask about its own ticket.

    It exists so a CLI can notice a cancellation between tasks without holding
    an organization credential — and it answers nothing else: no finding, no
    target, no project data.
    """
    job = _job_by_ticket(session, job_id, x_ticket_token)
    return {"data": {"job_id": job.id, "status": job.status,
                     "cancelled": job.status in {"cancelled", "cancel_requested"},
                     "deadline_at": (scan_flow.aware(job.deadline_at).isoformat()
                                     if job.deadline_at else None),
                     "evidence": job.evidence_state}}


@router.get("/scans/{job_id}/gate")
def scan_gate(job_id: str,
              x_ticket_token: str = Header(default="", alias=TOKEN_HEADER),
              session: Session = Depends(get_session)) -> dict:
    """The flow's own verdict, so a pipeline can fail its build on it.

    Same decision the console renders (findings of this flow, fail-closed, HIGH
    and above block), read with the ticket token for the same reason `state` is:
    a runner holds no organization credential and must not need one to learn
    whether its run passed. Without this the gate is a badge nobody blocks on.
    """
    job = _job_by_ticket(session, job_id, x_ticket_token)
    found = pipeline.summaries(session, [job.id])
    outcome = pipeline.verdict(job, found.get(job.id))
    return {"data": {"job_id": job.id, "verdict": outcome["verdict"],
                     "reason": outcome["reason"],
                     "status": job.status, "evidence": job.evidence_state}}


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
    # Idempotent on (kind, client timestamp): a retry after a dropped response
    # must not double the timeline.
    if at_client is not None:
        for row in (session.query(models.ScanEvent).filter_by(
                job_id=job.id, kind=payload.event).all()):
            if row.at_client is not None and \
                    scan_flow.aware(row.at_client) == at_client:
                return {"data": {"job_id": job.id, "status": job.status,
                                 "evidence": job.evidence_state,
                                 "duplicate": True}}
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


def _ingest_evidence(session: Session, job: models.ScanJob,
                     payload: "EvidenceIn") -> dict:
    """Hand one artifact to the ingest that already exists.

    One implementation per format, always: a second parser is how the same
    finding ends up with two identities and a count nobody can reconcile.
    """
    from backend.app import ingest as sbom_ingest
    from backend.app.routers import sarif as sarif_router

    subject = json.loads(job.subject or "{}")
    project = by_ref(session, job.org_id, subject.get("project"))
    if project is None:
        return {"skipped": "the flow's project is not inventoried"}
    label = subject.get("version")
    if not label:
        return {"skipped": "the flow carries no version label to attach to"}
    component_slug = subject.get("component")
    pv = (pick_version(session, project.id, label, subject.get("component_id"))
          or pick_version(session, project.id, label))
    if pv is None:
        return {"skipped": f"project version '{label}' does not exist"}

    if payload.kind == "sbom" and payload.format == "cyclonedx-1.6":
        if not payload.content:
            return {"skipped": "no content to ingest"}
        try:
            result = sbom_ingest.ingest_document(
                session, job.org_id, payload.content.encode(), source="cli",
                filename="sbom.cyclonedx.json",
                project_override=project.slug, version_override=label,
                # The ticket already knows which component this code belongs to;
                # without it the BOM lands on a product-wide version row and the
                # project ends up with two 'main' BOMs — the flow's and the
                # document's — which is how `/sbom/version` started answering 500.
                component_override=component_slug)
        except Exception as exc:  # a bad SBOM must not swallow the flow
            return {"error": f"sbom ingest failed: {type(exc).__name__}: {exc}"}
        receipt = session.get(models.SbomImport, result["import_id"])
        if receipt is not None:
            receipt.scan_job_id = job.id
        return {"kind": "sbom", "import_id": result["import_id"],
                "status": result["status"],
                "components": receipt.components_created if receipt else None,
                # The advisories the artifact carried are findings too; reporting
                # only components is what made a 67-CVE run look like an empty one.
                "vulnerabilities_created": receipt.vulnerabilities_created if receipt else None,
                "vulnerabilities_received": receipt.vulnerabilities_received if receipt else None}

    if payload.kind in {"sast", "misconfig", "secrets"} \
            and payload.format == "sarif-2.1.0":
        if not payload.content:
            return {"skipped": "no content to ingest"}
        try:
            document = json.loads(payload.content)
        except json.JSONDecodeError as exc:
            return {"error": f"sarif is not valid JSON: {exc}"}
        runs = document.get("runs") if isinstance(document, dict) else None
        if not runs:
            return {"skipped": "sarif carries no runs"}
        # A merged SARIF carries one run per provider (Trivy and gitleaks for
        # `secrets`); the analysis record names all of them instead of pretending
        # one engine produced both.
        tools: set[str] = set()
        counters = {"received": 0, "created": 0, "existing": 0, "skipped": 0}
        # The analysis record is created FIRST: the findings it ingests are the
        # findings it evaluated, and that link is what lets a flow report its own
        # result instead of the project's whole backlog.
        drivers = {str((run.get("tool") or {}).get("driver", {}).get("name") or "sarif")
                   for run in runs}
        repository_id = None
        remote = subject.get("repository")
        if remote:
            row = (session.query(models.Repository)
                   .filter_by(org_id=job.org_id, remote_url=remote).one_or_none())
            repository_id = row.id if row else None
        analysis_run = models.AnalysisRun(
            org_id=job.org_id, project_id=project.id, project_version_id=pv.id,
            tool=(",".join(sorted(drivers)) if drivers else "sarif")[:64],
            tool_version=(payload.tool or {}).get("version"),
            coverage=payload.coverage or "full", source="scan",
            revision=subject.get("commit"), branch=subject.get("branch"),
            # A diff scan is only legible with its base: "new in this range" is a
            # different claim from "present in this tree".
            base_revision=subject.get("base_commit"),
            repository_id=repository_id, pull_request=subject.get("pull_request"),
            evaluated={"paths": (payload.evaluated or {}).get("paths") or []},
            findings_seen=counters["received"], scan_job_id=job.id,
            actor=job.created_by, receipt={"source": "scan_flow"},
            started_at=job.started_at, finished_at=_now())
        session.add(analysis_run)
        session.flush()

        for run in runs:
            result = sarif_router.ingest_run(
                session, job.org_id, project, pv, run, source="scan", commit=False,
                analysis_run_id=analysis_run.id,
                # The task decides the class: `secrets` produces vulnerabilities,
                # not code weaknesses, whatever binary happened to find them.
                task=payload.kind)
            if result["tool"]:
                tools.add(str(result["tool"]))
            for key in counters:
                counters[key] += result["counts"].get(key, 0)

        # Name the providers the ingest actually resolved, and record how many
        # results were parsed — the record was created before the loop.
        tool_name = ",".join(sorted(tools)) if tools else None
        analysis_run.tool = (tool_name or "sarif")[:64]
        analysis_run.findings_seen = counters["received"]
        return {"kind": payload.kind, "counters": counters, "tool": tool_name}

    return {"kind": payload.kind, "stored_only": True}


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


MAX_EVIDENCE_BYTES = 4 * 1024 * 1024


@router.post("/scans/{job_id}/evidence", status_code=status.HTTP_201_CREATED)
async def post_evidence(job_id: str, request: Request,
                        x_ticket_token: str = Header(default="", alias=TOKEN_HEADER),
                        session: Session = Depends(get_session)) -> dict:
    """One call per artifact. Bound to the flow, hashed, never re-parsed.

    Two transports, one meaning:

    - `application/json` — a `barad-evidence-v1` envelope with the artifact
      inline. Fine for logs, manifests and small reports.
    - anything else — the artifact itself as the request body, with `kind`,
      `format` and `hash` in the query string. A real SARIF from a full ruleset is
      megabytes of rule metadata, and embedding that as a JSON string is how a
      healthy scanner gets refused by its own platform.
    """
    job = _job_by_ticket(session, job_id, x_ticket_token)
    raw = await request.body()
    if len(raw) > MAX_EVIDENCE_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            f"artifact exceeds {MAX_EVIDENCE_BYTES} bytes")
    media = (request.headers.get("content-type") or "").split(";")[0].strip().lower()
    if media == "application/json":
        try:
            payload = EvidenceIn(**json.loads(raw))
        except Exception as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"invalid evidence envelope: {exc}") from None
    else:
        params = request.query_params
        missing = [name for name in ("kind", "format", "hash") if not params.get(name)]
        if missing:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"raw evidence needs {missing} in the query string")
        try:
            payload = EvidenceIn(
                schema="barad-evidence-v1", ticket_id=job_id,
                kind=params["kind"], format=params["format"],
                content_hash=params["hash"], bytes=len(raw),
                tool=json.loads(params["tool"]) if params.get("tool") else None,
                coverage=params.get("coverage"),
                evaluated=(json.loads(params["evaluated"])
                           if params.get("evaluated") else None),
                content=raw.decode("utf-8", errors="replace"))
        except ValueError as exc:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"invalid evidence metadata: {exc}") from None

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
        # The sink binds and stores; it does not parse. An artifact with no
        # content is a claim, and a claim is not evidence.
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "content is required for an evidence artifact")

    # A retried upload is the same evidence, not a second one: the artifact is
    # keyed by (kind, content_hash) inside the flow.
    for artifact in (session.query(models.JobArtifact).filter_by(
            job_id=job.id, kind=payload.kind).all()):
        try:
            stored = json.loads(artifact.content or "{}")
        except json.JSONDecodeError:
            continue
        if stored.get("content_hash") == payload.content_hash:
            return {"data": {"job_id": job.id, "kind": payload.kind,
                             "evidence": job.evidence_state, "revived": False,
                             "status": job.status, "duplicate": True}}

    revived = scan_flow.revive(session, job, reason="late_evidence")
    session.add(models.JobArtifact(
        org_id=job.org_id, job_id=job.id, kind=payload.kind,
        content=json.dumps({
            "schema": payload.schema, "format": payload.format,
            "tool": payload.tool, "coverage": payload.coverage,
            "content_hash": payload.content_hash, "bytes": payload.bytes,
            "evaluated": payload.evaluated or {}, "content": payload.content,
        }, sort_keys=True)[:MAX_EVIDENCE_BYTES],
        created_at=_now()))
    session.flush()
    ingested = _ingest_evidence(session, job, payload)
    state = scan_flow.recompute_evidence(session, job)
    scan_flow.append(session, job, "evidence_received", source="executor",
                     detail={"kind": payload.kind, "format": payload.format,
                             "content_hash": payload.content_hash,
                             "revived": revived, "ingested": ingested})
    if revived:
        _audit_log(session, job.org_id, "shauron", "scan.revived", "scan_job",
                   job.id, f"evidence after abandonment: {payload.kind}")
    session.commit()
    return {"data": {"job_id": job.id, "kind": payload.kind,
                     "evidence": state, "revived": revived,
                     "status": job.status, "ingested": ingested}}


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

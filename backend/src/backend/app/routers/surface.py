"""Surface runs: the plan the platform composes, and the flow it gets back.

Three verbs, one object:

    plan  → resolve a profile against grants, policy and plane; say what would run
    start → freeze that plan into a `ScanJob` (origin/executor say who holds it)
    report→ steps and the manifest come back, one timeline for every plane

The evidence path deliberately reuses what already exists: `POST /observations`
for history and diff, `POST /assets/{id}/snapshots` for the flattened view the
Assets table reads. This router owns only what was missing — the plan and the
step-level trace.
"""
from __future__ import annotations

import datetime
import hashlib
import json

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from typing import Literal

from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import (auth, decisions, models, scan_flow, surface_diff,
                         surface_plan, surface_runtime, surface_workflow)
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1/surface", tags=["surface"])

TERMINAL_STEPS = {"ok", "failed", "dropped"}


def _caller(request: Request, session: Session,
            x_api_key: str = Header(default="", alias="X-API-Key"),
            authorization: str = Header(default=""),
            x_worker_token: str = Header(default="", alias="X-Worker-Token")):
    """Who is asking, and whether they may run a scan without a grant.

    A human owner/admin scanning from their own laptop is not the collector: the
    grant governs *workers*, and an operator typing a hostname is the same act as
    running nmap by hand. That is recorded in the plan as `basis` so the audit
    trail says which of the two it was.
    """
    principal = auth.resolve_principal(session, x_api_key, authorization,
                                       x_worker_token)
    auth._enforce(principal, request, None)
    org = auth._organization_from(principal, session)
    human = principal["kind"] in {"user", "api_key"}
    elevated = human and principal.get("role") in {"owner", "admin"}
    actor = principal.get("email") or ("api-key" if human else principal["kind"])
    return principal, org, elevated, actor


class TargetIn(BaseModel):
    type: str = "domain"
    value: str = Field(min_length=1, max_length=253)


class PlanIn(BaseModel):
    #: A catalog profile, or one of the organisation's own workflows. Exactly one
    #: of the two: a request that names neither cannot be planned, and one that
    #: names both is a question about which the operator meant.
    profile: str | None = None
    workflow_id: str | None = None
    targets: list[TargetIn] = Field(min_length=1, max_length=100)
    plane: str = "cli"
    engagement: str | None = Field(default=None, max_length=200)


def _profile_for(session: Session, org: models.Organization,
                 payload: PlanIn) -> tuple[str, dict | None]:
    """The name the plan will carry, and the document when it is not the catalog."""
    if payload.workflow_id:
        row = (session.query(models.ScanWorkflow)
               .filter_by(id=payload.workflow_id, org_id=org.id, archived=False).first())
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "unknown workflow")
        return row.slug, surface_workflow.document_for(row)
    if not payload.profile:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            {"code": "workflow.profile_required"})
    return payload.profile, None


class StepIn(BaseModel):
    step: str
    stage: str | None = None
    tool: str | None = None
    state: str = "allow"
    status: str = "ok"
    reason: str = ""
    items_in: int = 0
    items_out: int = 0
    counters: dict = Field(default_factory=dict)
    coverage: str = "unknown"
    artifacts: list[dict] = Field(default_factory=list)
    error: str | None = None
    started_at: str | None = None
    finished_at: str | None = None


class StepsIn(BaseModel):
    steps: list[StepIn] = Field(min_length=1, max_length=200)


class FinishIn(BaseModel):
    ok: bool = True
    manifest: dict = Field(default_factory=dict)
    error: str | None = None
    evidence_note: str | None = None


def _targets_payload(targets: list[TargetIn]) -> list[dict]:
    return [{"type": target.type, "value": target.value.strip().lower()}
            for target in targets]


@router.get("/catalog")
def surface_catalog(session: Session = Depends(get_session),
                    x_api_key: str = Header(default="", alias="X-API-Key"),
                    authorization: str = Header(default=""),
                    x_worker_token: str = Header(default="", alias="X-Worker-Token"),
                    request: Request = None,
                    target_type: str | None = Query(default=None),
                    plane: str = Query(default="cli")):
    """The profiles this caller could use, and what each one answers.

    No verdict here: a profile's state depends on the target, so the console asks
    `/plan` once a domain is chosen. This is the list that fills the modal.
    """
    _principal, org, elevated, _actor = _caller(
        request, session, x_api_key, authorization, x_worker_token)
    document = surface_plan.catalog()
    rows = []
    for name, profile in sorted(document["profiles"].items()):
        if target_type and profile.get("target_kind") != target_type:
            continue
        rows.append({
            "name": name, "label": profile.get("label"),
            "question": profile.get("question"), "level": profile.get("level"),
            "plane": profile.get("plane"), "target_kind": profile.get("target_kind"),
            "stages": [{"id": stage["id"], "tools": stage.get("tools")}
                       for stage in profile.get("stages", [])],
            "runnable_here": plane in (profile.get("plane") or []),
            "tools": [{"name": tool,
                       "state": "disabled" if tool in surface_plan.policy_disabled(
                           session, org.id) else "declared",
                       "image": (document["tools"].get(tool) or {}).get("image"),
                       "capability": (document["tools"].get(tool) or {}).get("capability")}
                      for stage in profile.get("stages", [])
                      for tool in stage.get("tools", [])],
        })
    return {"catalog_hash": surface_plan.catalog_hash(), "profiles": rows,
            "plane": plane, "no_grant_needed": elevated,
            "tools_total": len(document["tools"])}


class RuntimeIn(BaseModel):
    per_zone: int = Field(default=2, ge=1, le=8)
    per_org: int = Field(default=4, ge=1, le=32)
    per_worker: int = Field(default=1, ge=1, le=4)
    queue_ceiling: int = Field(default=500, ge=50, le=20000)
    min_workers: int = Field(default=1, ge=1, le=4)
    max_workers: int = Field(default=6, ge=1, le=16)
    scale_down_after_s: int = Field(default=600, ge=30, le=3600)
    actor: str = Field(default="console", max_length=320)


@router.get("/runtime")
def surface_runtime_state(session: Session = Depends(get_session),
                          org: models.Organization = Depends(auth.require_org)):
    """The concurrency limits and the state they are acting on.

    Settings shows both because a cap without a queue is a number nobody can
    judge: "2 per zone" only means something next to "200 queued, 2 in flight".
    """
    return {"policy": surface_runtime.policy(session),
            "state": surface_runtime.snapshot(session, org.id),
            "bounds": surface_runtime.BOUNDS}


@router.put("/runtime")
def surface_runtime_update(payload: RuntimeIn = None,
                           session: Session = Depends(get_session),
                           org: models.Organization = Depends(auth.require_admin)):
    """Change the limits. Audited like a grant, applied on the next claim."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    try:
        saved = surface_runtime.save(session, payload.model_dump(exclude={"actor"}),
                                     payload.actor, org.id)
    except ValueError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from None
    return {"policy": saved, "state": surface_runtime.snapshot(session, org.id)}


@router.post("/plan")
def surface_resolve(payload: PlanIn = None,
                    session: Session = Depends(get_session),
                    x_api_key: str = Header(default="", alias="X-API-Key"),
                    authorization: str = Header(default=""),
                    x_worker_token: str = Header(default="", alias="X-Worker-Token"),
                    request: Request = None):
    """Resolve, dry. The CLI's `plan pull` and the modal's preview both land here."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    _principal, org, elevated, actor = _caller(
        request, session, x_api_key, authorization, x_worker_token)
    if payload.plane == "cli" and not elevated:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "the CLI is for owners and admins; workers run from the platform")
    name, custom = _profile_for(session, org, payload)
    try:
        plan = surface_plan.resolve(
            session, org, name, _targets_payload(payload.targets),
            plane=payload.plane, check_grants=not elevated, actor=actor, custom=custom)
    except KeyError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc).strip("'\"")) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc
    return {"plan": plan, "verdict": surface_plan.verdict(plan),
            "states": surface_plan.states(plan)}


@router.post("/runs", status_code=status.HTTP_201_CREATED)
def surface_start(payload: PlanIn = None,
                  session: Session = Depends(get_session),
                  x_api_key: str = Header(default="", alias="X-API-Key"),
                  authorization: str = Header(default=""),
                  x_worker_token: str = Header(default="", alias="X-Worker-Token"),
                  request: Request = None):
    """Freeze the plan into a run. A refused or blocked plan is never a job."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    _principal, org, elevated, actor = _caller(
        request, session, x_api_key, authorization, x_worker_token)
    if payload.plane == "cli" and not elevated:
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            "the CLI is for owners and admins; workers run from the platform")
    name, custom = _profile_for(session, org, payload)
    try:
        plan = surface_plan.resolve(
            session, org, name, _targets_payload(payload.targets),
            plane=payload.plane, check_grants=not elevated, actor=actor, custom=custom)
    except KeyError as exc:
        raise HTTPException(status.HTTP_404_NOT_FOUND, str(exc).strip("'\"")) from exc
    except ValueError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    if plan.get("refused"):
        raise HTTPException(status.HTTP_409_CONFLICT, plan["reason"])
    if plan.get("blocked_targets"):
        blocked = plan["blocked_targets"][0]
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"{blocked['value']} is excluded from scope: {blocked['reason']}")
    if surface_plan.states(plan).get("allow", 0) == 0:
        raise HTTPException(status.HTTP_409_CONFLICT, surface_plan.verdict(plan))

    # Concurrency limits are enforced twice on purpose: the ceiling refuses here,
    # so an operator learns immediately instead of watching a run that will never
    # start; the per-zone and per-org caps wait at the claim, where "not yet" is
    # the honest answer and the run keeps its place in the queue.
    admitted, why = surface_runtime.admission(session, org.id, plan["targets"])
    if not admitted:
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, why)

    # The job advertises the capabilities its steps actually need, not a coarse
    # "network": the claim re-validates this string against the grant, so a label
    # nobody granted made every grant-checked run fail its own claim.
    required = sorted({step["capability"] for stage in plan["stages"]
                       for step in stage["steps"]
                       if step.get("state") == "allow" and step.get("capability")})
    limits = plan.get("limits") or {}
    job = models.ScanJob(
        org_id=org.id, scanner="shauron-surface",
        capability=",".join(required) or "passive_discovery",
        # The engine's principal, not the human's: a worker-path run is judged as
        # the collector, so the job must carry the same name the grant was issued
        # to. Recording the operator here made every grant-checked run fail its
        # own claim with "default deny".
        principal=plan.get("principal") or actor,
        targets=json.dumps(plan["targets"]),
        profile=json.dumps({"name": plan["profile"], "label": plan.get("label"),
                            "level": plan.get("level"),
                            "hash": plan["hash"],
                            "catalog_hash": plan.get("catalog_hash")}),
        status="queued", origin=payload.plane,
        # A cloud run is held by a worker; a CLI run is held by the terminal that
        # started it. Recording "cli" for both made the console claim a laptop ran
        # something a Swarm service executed.
        executor="shauron" if payload.plane != "cli" else "cli",
        tasks=json.dumps([{"profile": plan["profile"],
                           "stages": [stage["id"] for stage in plan["stages"]]}]),
        subject=json.dumps({"targets": plan["targets"], "profile": plan["profile"],
                            "engagement": payload.engagement}),
        created_by=actor,
        deadline_at=models.utcnow() + datetime.timedelta(
            seconds=int(limits.get("timeout_s") or 300) + 120),
        authorization=json.dumps({"basis": plan["basis"],
                                  "principal": plan["principal"],
                                  "engagement": payload.engagement}),
    )
    session.add(job)
    session.flush()
    plan["run_id"] = job.id
    # The frozen plan is the ticket: it must name its own run so a spooled
    # directory can be uploaded later without guessing which job it belongs to.
    job.ticket_json = json.dumps(plan)
    canary = {
        "step": "plan.resolve", "stage": "plan", "tool": "barad",
        "state": "allow", "status": "ok", "items_in": len(plan["targets"]),
        "items_out": len(plan["targets"]),
        "counters": surface_plan.states(plan),
        "coverage": "full",
        "reason": (f"{plan['profile']} · {plan['basis']}"
                   + (f" · {payload.engagement}" if payload.engagement else "")),
    }
    scan_flow.append(session, job, "accepted", source="platform", actor=actor,
                     detail={"plan_hash": plan["hash"], "profile": plan["profile"],
                             "basis": plan["basis"], "steps": canary["counters"]})
    scan_flow.append(session, job, "step", source="platform", actor=actor,
                     detail=canary)
    session.commit()
    return {"run_id": job.id, "plan": plan, "verdict": surface_plan.verdict(plan)}


def _job(session: Session, org: models.Organization, run_id: str) -> models.ScanJob:
    job = session.get(models.ScanJob, run_id)
    if job is None or job.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "run not found")
    return job


def _step_events(job: models.ScanJob, session: Session) -> list[dict]:
    """One row per step: the last thing that happened wins.

    A requeued run writes a second set of step events, and keeping both made the
    console show a failure that a later attempt had already fixed — the verdict
    said "1 step failed" while the run had finished clean. The events are the
    history; this is the state.
    """
    rows = (session.query(models.ScanEvent)
            .filter_by(job_id=job.id, kind="step")
            .order_by(models.ScanEvent.seq).all())
    latest: dict[str, dict] = {}
    for row in rows:
        try:
            detail = json.loads(row.detail or "{}")
        except (TypeError, ValueError):
            detail = {}
        entry = {**detail, "seq": row.seq, "at_server":
                 row.at_server.isoformat() if row.at_server else None,
                 "at_client": row.at_client.isoformat() if row.at_client else None}
        name = str(entry.get("step") or "")
        if not name:
            continue
        # Dict preserves insertion order: a step keeps its place, its payload moves.
        latest[name] = {**latest.get(name, {}), **entry}
    return list(latest.values())


@router.post("/runs/{run_id}/steps")
def surface_steps(run_id: str, payload: StepsIn = None,
                  session: Session = Depends(get_session),
                  x_api_key: str = Header(default="", alias="X-API-Key"),
                  authorization: str = Header(default=""),
                  x_worker_token: str = Header(default="", alias="X-Worker-Token"),
                  request: Request = None):
    """Report settled steps. Last write wins; a re-run has to be able to fix a step.

    "Idempotent per step name" was implemented as "first write wins", so after a
    requeue the second attempt's success was dropped on the floor and the console
    kept showing the failure of an attempt that no longer existed.
    """
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    _principal, org, _elevated, actor = _caller(
        request, session, x_api_key, authorization, x_worker_token)
    job = _job(session, org, run_id)
    if job.status in {"cancelled", "rejected"}:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"run is {job.status}; nothing else will be recorded")
    accepted, skipped = 0, 0
    previous = {entry.get("step"): entry for entry in _step_events(job, session)}
    for step in payload.steps:
        detail = step.model_dump()
        prior = previous.get(step.step) or {}
        if (prior.get("status") == detail.get("status")
                and (prior.get("counters") or {}) == (detail.get("counters") or {})
                and (prior.get("error") or "") == (detail.get("error") or "")):
            # The same report twice is not new information.
            skipped += 1
            continue
        detail["at"] = detail.get("finished_at") or detail.get("started_at")
        scan_flow.append(session, job, "step", source="executor", actor=actor,
                         detail=detail)
        accepted += 1
    if job.status == "queued" and accepted:
        scan_flow.apply_status(job, "started")
        job.started_at = job.started_at or models.utcnow()
    session.commit()
    return {"run_id": job.id, "accepted": accepted, "skipped": skipped}


@router.post("/runs/{run_id}/finish")
def surface_finish(run_id: str, payload: FinishIn = None,
                   session: Session = Depends(get_session),
                   x_api_key: str = Header(default="", alias="X-API-Key"),
                   authorization: str = Header(default=""),
                   x_worker_token: str = Header(default="", alias="X-Worker-Token"),
                   request: Request = None):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    _principal, org, _elevated, actor = _caller(
        request, session, x_api_key, authorization, x_worker_token)
    job = _job(session, org, run_id)
    manifest = payload.manifest or {}
    summary = {
        "profile": manifest.get("profile"),
        "counters": manifest.get("counters") or {},
        "coverage": manifest.get("coverage"),
        "observations": manifest.get("observations", 0),
        "duration_s": manifest.get("duration_s"),
        "egress_ip": manifest.get("egress_ip"),
        "plan_hash": manifest.get("plan_hash"),
        "normalizer_version": manifest.get("normalizer_version"),
        "artifacts": len(manifest.get("artifacts") or []),
        "actor": manifest.get("actor"),
    }
    job.result = json.dumps(summary)
    # A run that did not manage to upload its evidence is closed anyway, with the
    # reason on it: an open run keeps the lease, and a lease held by a worker that
    # has moved on is indistinguishable from a scan that never started.
    job.error = payload.error or payload.evidence_note
    kind = "finished" if payload.ok else "failed"
    scan_flow.apply_status(job, kind)
    job.finished_at = models.utcnow()
    job.evidence_state = ("complete" if payload.ok and not payload.evidence_note
                          else "partial")
    scan_flow.append(session, job, kind, source="executor", actor=actor,
                     detail=summary)
    session.commit()
    return {"run_id": job.id, "status": job.status, "summary": summary}


class ObservationsIn(BaseModel):
    observations: list[dict] = Field(min_length=1, max_length=1000)
    snapshots: dict[str, dict] = Field(default_factory=dict)
    findings: list[dict] = Field(default_factory=list, max_length=500)
    actor: str = Field(default="cli", max_length=255)


@router.post("/runs/{run_id}/observations")
def surface_observations(run_id: str, payload: ObservationsIn = None,
                         session: Session = Depends(get_session),
                         org: models.Organization = Depends(auth.require_org)):
    """Ingest a run's facts: history through the exposure engine, and the folded
    snapshot the Assets table reads.

    Two writes on purpose. `observations` is what makes \"this changed\" and \"this
    condition appeared\" computable; the snapshot is the flattened view a table can
    read without parsing history. A collector that writes only one of them leaves
    either the diff or the screen empty — that trap is already in this codebase.
    """
    import json as _json

    from backend.app.routers import exposures as exposures_router

    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    job = _job(session, org, run_id)

    items = []
    for observation in payload.observations:
        kind = observation.get("kind")
        if kind not in models.OBSERVATION_KINDS:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"kind must be one of {sorted(models.OBSERVATION_KINDS)}")
        coverage = observation.get("coverage") or "full"
        if coverage not in models.OBSERVATION_COVERAGES:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"coverage must be one of "
                                f"{sorted(models.OBSERVATION_COVERAGES)}")
        # A URL subject is a url asset, not a domain whose value happens to start
        # with http:// — that mismatch is what created a second asset per host.
        subject = str(observation.get("subject") or "")
        guessed = "url" if subject.startswith(("http://", "https://")) else "domain"
        items.append(exposures_router.ObservationIn(
            asset=exposures_router.AssetRef(
                type=observation.get("asset_type") or guessed,
                value=subject),
            kind=kind, subject=observation.get("subject"),
            port=observation.get("port") or None,
            protocol=observation.get("protocol"),
            value=observation.get("value") or {},
            source=(observation.get("source") or "shauron")[:64],
            coverage=coverage,
            observed_at=observation.get("observed_at") or observation.get("at")))

    # A name the run discovered under one of its own targets is a real host, and it
    # is the operator's to claim: file it as its own asset, `pending`, so it shows
    # up for association instead of arriving unclassified or being dropped. The
    # parent edge is derived from the names (`_domain_parents`), so nothing is
    # stored for it; what ingestion adds is the intent. An asset that already
    # exists is never touched — a confirmed host is not downgraded by a scan.
    targets = [str(item.get("value") or "").strip().lower()
               for item in _json.loads(job.targets or "[]")
               if str(item.get("type") or "") == "domain"]
    discovered = 0
    now_pre = models.utcnow()
    if targets:
        known = {row.value: row for row in
                 session.query(models.Asset)
                 .filter_by(org_id=org.id, type="domain").all()}
        for item in items:
            value = (item.asset.value or "").strip().lower()
            if not value or value in known:
                continue
            if not any(value.endswith("." + target) for target in targets if target):
                continue
            asset = models.Asset(org_id=org.id, type="domain", value=value,
                                 source=(item.source or "shauron")[:64],
                                 classification_status="pending",
                                 discovered_at=now_pre, last_seen_at=now_pre)
            session.add(asset)
            known[value] = asset
            discovered += 1
        if discovered:
            session.flush()

    ingested = exposures_router.import_observations(
        payload=exposures_router.ObservationImportIn(
            observations=items, actor=payload.actor),
        org=org, session=session)

    snapshotted = 0
    now = models.utcnow()
    for target, document in (payload.snapshots or {}).items():
        kind = "url" if target.startswith(("http://", "https://")) else "domain"
        asset = (session.query(models.Asset)
                 .filter_by(org_id=org.id, type=kind, value=target.lower())
                 .one_or_none())
        if asset is None:
            asset = models.Asset(org_id=org.id, type=kind,
                                 value=target.lower(), source="shauron")
            session.add(asset)
            session.flush()
        session.add(models.AssetSnapshot(
            org_id=org.id, asset_id=asset.id, observed_at=now, source="shauron",
            data=_json.dumps(document, sort_keys=True), created_at=now))
        asset.last_seen_at = now
        snapshotted += 1
    # A run's findings are claims, not facts, and they are written for every
    # target. Dropping the ones on a host nobody has claimed is how a deep recon of
    # this estate produced no rows at all (261 of 274 assets carry no project). The
    # row hangs off the run — and off the cycle, when the run declared one — and the
    # asset link is the promotion step a human performs, not something ingest
    # decides on the operator's behalf.
    created = duplicates = cycle_linked = 0
    claimed_without_asset: list[str] = []
    cycle = session.get(models.Cycle, job.cycle_id) if job.cycle_id else None
    for finding in payload.findings:
        target = (finding.get("matched_at") or "").strip()
        asset = None
        for candidate in (target, target.split("//")[-1].split("/")[0] if "//" in target else ""):
            if not candidate:
                continue
            asset = (session.query(models.Asset)
                     .filter(models.Asset.org_id == org.id)
                     .filter(models.Asset.value == candidate.lower())
                     .one_or_none())
            if asset is not None:
                break
        if asset is None and target:
            # A finding names a path ("…/metrics") while the asset names the origin;
            # a prefix match is what "this finding belongs to that asset" means.
            for row in (session.query(models.Asset)
                        .filter(models.Asset.org_id == org.id).all()):
                if row.value and target.lower().startswith(row.value.lower()):
                    asset = row
                    break
        rule = str(finding.get("rule_id") or "unknown")[:120]
        where = (finding.get("matched_at") or "")[:1024]
        # The identity needs an owner even when the asset is unknown: a claim is
        # "this target has this rule at this location", deduped per target, so a
        # second run of the same profile does not mint a second row.
        owner = asset.project_id if asset is not None else f"target:{target.lower()}"
        fingerprint = hashlib.sha256(
            f"{org.id}|{owner}|{rule}|{where}".encode()).hexdigest()
        existing = (session.query(models.Finding)
                    .filter_by(org_id=org.id, fingerprint=fingerprint).one_or_none())
        if existing is not None:
            existing.status = "open" if existing.status == "resolved" else existing.status
            duplicates += 1
            continue
        claim = models.Finding(
            org_id=org.id, project_id=asset.project_id if asset is not None else None,
            asset_id=None, origin_run_id=job.id, kind="vulnerability",
            vector="network", fingerprint=fingerprint,
            source=f"shauron:{finding.get('tool') or 'surface'}",
            title=(finding.get("name") or rule)[:1024],
            detail=_json.dumps(finding, sort_keys=True)[:8000],
            severity=finding.get("severity"), url=where or None, status="open",
            # Unvalidated by design: the machine saw it, nobody confirmed it, so it
            # is outside COUNTED_TRIAGE until a person decides.
            triage_status="new", evidence_level="observed", origin="scanner")
        session.add(claim)
        session.flush()
        if cycle is not None and cycle.state != "closed":
            session.add(models.CycleFinding(
                org_id=org.id, cycle_id=cycle.id, finding_id=claim.id, source="run"))
            cycle_linked += 1
        if asset is None or asset.project_id is None:
            # No owner in the inventory: the claim is real, but nobody has filed
            # this host, so no project can carry it. Named in the receipt instead
            # of being dropped on the floor.
            claimed_without_asset.append(rule)
        created += 1

    job.evidence_state = "partial"
    session.commit()
    return {"run_id": job.id, "observations": ingested, "snapshots": snapshotted,
            "assets_discovered": discovered,
            "findings": {"created": created, "duplicates": duplicates,
                         "cycle_linked": cycle_linked,
                         "unattached": claimed_without_asset[:20]}}


class TriageIn(BaseModel):
    decision: Literal["validate", "dismiss", "accept_risk"] = "validate"
    reason: str = Field(default="", max_length=2000)
    actor: str = Field(default="console", max_length=255)


# The human half of the two keys lives in `app.decisions`, so a run's triage and a
# cycle's ledger cannot drift into two vocabularies.


@router.post("/runs/{run_id}/findings/{finding_id}")
def surface_triage(run_id: str, finding_id: str, payload: TriageIn = None,
                   session: Session = Depends(get_session),
                   org: models.Organization = Depends(auth.require_org)):
    """Validate a finding *from the run that produced it*.

    Triage that happens somewhere else loses the link between the claim and the
    evidence. Here the decision lands on the finding **and** on the run's timeline,
    so six months later the run still says who looked at it and what they concluded.

    This is the human key: `evidence_level` is untouched (a person cannot manufacture
    proof), `triage_status` moves off `new` — which is what puts the row into the
    counted posture — and only `validate` attaches the asset the claim named.
    """
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    job = _job(session, org, run_id)
    finding = session.get(models.Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    outcome = decisions.apply(session, org, finding, payload.decision,
                              payload.actor, payload.reason)
    scan_flow.append(session, job, "decision", source="console",
                     actor=payload.actor,
                     detail={"step": "triage", "finding_id": finding.id,
                             "status": finding.status,
                             "triage_status": finding.triage_status,
                             "attached_asset": outcome["attached_asset"],
                             "title": finding.title,
                             "severity": finding.severity,
                             "reason": payload.reason})
    session.commit()
    return {"finding": {"id": finding.id, "status": finding.status,
                        "triage_status": finding.triage_status,
                        "asset_id": finding.asset_id,
                        "title": finding.title, "severity": finding.severity},
            "attached_asset": outcome["attached_asset"],
            "run_id": job.id}


@router.get("/runs")
def surface_runs(limit: int = Query(default=25, ge=1, le=200),
                 session: Session = Depends(get_session),
                 org: models.Organization = Depends(auth.require_org)):
    rows = (session.query(models.ScanJob)
            .filter_by(org_id=org.id, scanner="shauron-surface")
            .order_by(models.ScanJob.created_at.desc()).limit(limit).all())
    return {"runs": [{"id": row.id, "status": row.status, "origin": row.origin,
                      "executor": row.executor, "principal": row.principal,
                      "created_at": row.created_at.isoformat() if row.created_at else None,
                      "finished_at": row.finished_at.isoformat() if row.finished_at else None,
                      "profile": json.loads(row.profile or "{}").get("name"),
                      "targets": json.loads(row.targets or "[]"),
                      "summary": json.loads(row.result) if row.result else None}
                     for row in rows]}


@router.get("/runs/{run_id}")
def surface_run(run_id: str, session: Session = Depends(get_session),
                org: models.Organization = Depends(auth.require_org)):
    """The flow: the plan, every settled step, the timeline and the verdict."""
    job = _job(session, org, run_id)
    plan = json.loads(job.ticket_json or "{}") or {}
    steps = _step_events(job, session)
    events = (session.query(models.ScanEvent)
              .filter_by(job_id=job.id)
              .order_by(models.ScanEvent.seq).all())
    planned = [step for stage in plan.get("stages", [])
               for step in stage.get("steps", [])]
    settled = {step.get("step") for step in steps
               if step.get("status") in TERMINAL_STEPS}
    pending = [step["step"] for step in planned
               if step.get("state") == "allow" and step["step"] not in settled]
    failed = [step for step in steps if step.get("status") == "failed"]
    skipped = [step for step in steps if step.get("status") == "dropped"]
    result = json.loads(job.result) if job.result else None

    if job.status in {"queued", "accepted"}:
        headline = surface_plan.verdict(plan) if plan else "waiting for an executor"
    elif job.status == "running":
        done = len(settled)
        headline = (f"{done} of {len(planned)} step(s) settled"
                    + (f"; {len(failed)} failed" if failed else "")
                    + (f"; {len(skipped)} skipped" if skipped else ""))
    elif failed:
        headline = (f"{len(failed)} step(s) failed"
                    + (f": {failed[0].get('error')}" if failed[0].get("error") else ""))
    elif result:
        counters = result.get("counters") or {}
        headline = (f"{counters.get('ok', 0)} step(s) ok, {counters.get('dropped', 0)} "
                    f"skipped · {result.get('observations', 0)} observations · "
                    f"coverage {result.get('coverage')}")
    else:
        headline = f"run is {job.status}"

    changes = surface_diff.build(session, job)
    window_start = job.started_at or job.created_at
    window_end = job.finished_at or models.utcnow()
    findings = (session.query(models.Finding)
                .filter(models.Finding.org_id == org.id)
                .filter(models.Finding.source.like("shauron:%"))
                .filter(models.Finding.created_at >= window_start)
                .filter(models.Finding.created_at <= window_end)
                .order_by(models.Finding.created_at).limit(200).all())

    return {
        "diff": changes,
        "findings": [{"id": row.id, "title": row.title, "severity": row.severity,
                      "status": row.status, "source": row.source, "url": row.url,
                      "created_at": row.created_at.isoformat() if row.created_at else None}
                     for row in findings],
        "run": {"id": job.id, "status": job.status, "origin": job.origin,
                "executor": job.executor, "principal": job.principal,
                "created_at": job.created_at.isoformat() if job.created_at else None,
                "started_at": job.started_at.isoformat() if job.started_at else None,
                "finished_at": job.finished_at.isoformat() if job.finished_at else None,
                "deadline_at": job.deadline_at.isoformat() if job.deadline_at else None,
                "evidence_state": job.evidence_state,
                "profile": json.loads(job.profile or "{}"),
                "targets": json.loads(job.targets or "[]"),
                "authorization": json.loads(job.authorization or "{}")},
        "verdict": headline,
        "plan": plan,
        "steps": steps,
        "pending": pending,
        "summary": result,
        "events": [{"seq": row.seq, "kind": row.kind, "source": row.source,
                    "actor": row.actor,
                    "at_server": row.at_server.isoformat() if row.at_server else None,
                    "at_client": row.at_client.isoformat() if row.at_client else None,
                    "detail": json.loads(row.detail or "{}")}
                   for row in events],
    }

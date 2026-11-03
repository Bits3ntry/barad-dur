"""Recurring scans: schedules plus the tick that materializes due jobs.

Design: the platform never runs a background thread. A tick endpoint advances
due schedules, queues jobs through the same `authorize()` path as manual
queues, and is safe to call from cron/systemd every minute — `next_run_at`
moves forward before the job is created, so a double tick cannot duplicate a
run. A denied schedule is recorded with its denial reason and its clock still
advances (no tight retry loop against an unauthorized target).
"""
import datetime
import json

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, auth_local, authorization, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log
from backend.app.routers.orchestration import _job_data

router = APIRouter(prefix="/api/v1/orchestration/schedules", tags=["orchestration"])


def _schedule_data(row: models.ScanSchedule, now: datetime.datetime | None = None) -> dict:
    now = auth_local.ensure_aware(now or models.utcnow())
    due = auth_local.ensure_aware(row.next_run_at) <= now
    return {"id": row.id, "name": row.name, "kind": row.kind,
            "asset_id": row.asset_id, "scanner": row.scanner,
            "capability": row.capability, "principal": row.principal,
            "targets": json.loads(row.targets or "[]"),
            "environment": row.environment,
            "profile": json.loads(row.profile or "{}"),
            "interval_minutes": row.interval_minutes, "enabled": row.enabled,
            "next_run_at": row.next_run_at.isoformat(),
            "last_run_at": row.last_run_at.isoformat() if row.last_run_at else None,
            "last_job_id": row.last_job_id, "last_error": row.last_error,
            "due": due}


class ScheduleIn(BaseModel):
    name: str = Field(min_length=2, max_length=128)
    kind: str = "scan"
    asset_id: str | None = None
    scanner: str = ""
    capability: str = ""
    principal: str = Field(min_length=2, max_length=255)
    targets: list[dict] = []
    environment: str | None = None
    profile: dict = {}
    interval_minutes: int = Field(default=1440, ge=15, le=525600)
    enabled: bool = True
    actor: str = Field(min_length=2, max_length=255)


@router.post("")
def create_schedule(payload: ScheduleIn = None,
                    org: models.Organization = Depends(auth.require_admin),
                    session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.kind not in {"scan", "easm"}:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "kind must be scan | easm")
    if payload.kind == "scan":
        if payload.capability not in authorization.CAPABILITIES:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"capability must be one of "
                                f"{sorted(authorization.CAPABILITIES)}")
        scanner = (session.query(models.Scanner)
                   .filter_by(org_id=org.id, name=payload.scanner).one_or_none())
        if scanner is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "scanner not registered")
        if scanner.capability != payload.capability:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"scanner {scanner.name} is registered for "
                                f"'{scanner.capability}'")
    else:
        if not payload.asset_id:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                "easm schedules need an asset_id")
        asset = session.get(models.Asset, payload.asset_id)
        if asset is None or asset.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
        if asset.type not in {"domain", "subdomain"}:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                "easm schedules support domain assets only")
    if session.query(models.ScanSchedule).filter_by(org_id=org.id,
                                                    name=payload.name).first():
        raise HTTPException(status.HTTP_409_CONFLICT, "schedule name already used")
    now = models.utcnow()
    row = models.ScanSchedule(
        org_id=org.id, name=payload.name, scanner=payload.scanner,
        capability=payload.capability, principal=payload.principal,
        targets=json.dumps(payload.targets), environment=payload.environment,
        profile=json.dumps(payload.profile),
        kind=payload.kind, asset_id=payload.asset_id,
        interval_minutes=payload.interval_minutes, enabled=payload.enabled,
        next_run_at=now, created_by=payload.actor,
        created_at=now, updated_at=now)
    session.add(row)
    session.flush()
    _audit_log(session, org.id, payload.actor, "orchestration.schedule_created",
               "scan_schedule", row.id, payload.name)
    session.commit()
    return {"data": _schedule_data(row)}


@router.get("")
def list_schedules(org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    rows = (session.query(models.ScanSchedule).filter_by(org_id=org.id)
            .order_by(models.ScanSchedule.next_run_at).all())
    return {"data": [_schedule_data(row) for row in rows], "total": len(rows)}


class SchedulePatch(BaseModel):
    enabled: bool | None = None
    interval_minutes: int | None = Field(default=None, ge=15, le=525600)
    actor: str = Field(min_length=2, max_length=255)


@router.patch("/{schedule_id}")
def patch_schedule(schedule_id: str, payload: SchedulePatch = None,
                   org: models.Organization = Depends(auth.require_admin),
                   session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    row = session.get(models.ScanSchedule, schedule_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    if payload.enabled is not None:
        row.enabled = payload.enabled
    if payload.interval_minutes is not None:
        row.interval_minutes = payload.interval_minutes
    row.updated_at = models.utcnow()
    _audit_log(session, org.id, payload.actor, "orchestration.schedule_updated",
               "scan_schedule", row.id,
               f"enabled={row.enabled} interval={row.interval_minutes}")
    session.commit()
    return {"data": _schedule_data(row)}


class TickIn(BaseModel):
    actor: str = Field(default="scheduler", min_length=2, max_length=255)
    limit: int = Field(default=25, ge=1, le=200)


@router.post("/tick")
def tick(payload: TickIn = None,
         session: Session = Depends(get_session),
         x_api_key: str = Header(default="", alias="X-API-Key"),
         authorization_header: str = Header(default="", alias="Authorization")):
    """Queue jobs for due schedules. Idempotent per interval; safe from cron.

    Authentication is explicit here because one tick may span several orgs
    (the scheduler is a platform-level actor). A caller restricted to one org
    only ticks that org.
    """
    payload = payload or TickIn()
    principal = auth.resolve_principal(session, x_api_key, authorization_header)
    query = session.query(models.ScanSchedule).filter_by(enabled=True)
    if principal["kind"] == "user":
        query = query.filter_by(org_id=principal["org_id"])
    now = models.utcnow()
    due_rows = [row for row in query.all()
                if auth_local.ensure_aware(row.next_run_at) <= now][:payload.limit]
    results = []
    for row in due_rows:
        # Advance first: a crash after queueing must not duplicate the run.
        row.next_run_at = now + datetime.timedelta(minutes=row.interval_minutes)
        row.last_run_at = now
        row.updated_at = now
        if row.kind == "easm":
            from backend.app.routers.easm import _dns_lookup

            asset = session.get(models.Asset, row.asset_id) if row.asset_id else None
            if asset is None:
                row.last_error = "asset missing"
                results.append({"schedule": row.name, "result": "skipped",
                                "reason": "asset missing"})
                continue
            decision = authorization.authorize(
                session, row.org_id, row.principal, "passive_discovery",
                [{"type": "domain", "value": asset.value}], tool="dns-collector")
            if decision["decision"] == "deny":
                row.last_error = f"denied: {decision['reason']}"[:500]
                results.append({"schedule": row.name, "result": "denied",
                                "reason": decision["reason"][:200]})
                _audit_log(session, row.org_id, payload.actor,
                           "orchestration.schedule_denied", "scan_schedule",
                           row.id, decision["reason"][:300])
                continue
            try:
                observation = {"dns": _dns_lookup(asset.value)}
            except HTTPException as exc:
                row.last_error = str(exc.detail)[:500]
                results.append({"schedule": row.name, "result": "error",
                                "reason": str(exc.detail)[:200]})
                continue
            snapshot = models.AssetSnapshot(
                org_id=row.org_id, asset_id=asset.id, observed_at=now,
                source="scheduled-collector",
                data=json.dumps(observation, sort_keys=True), created_at=now)
            session.add(snapshot)
            asset.last_seen_at = now
            row.last_error = None
            results.append({"schedule": row.name, "result": "collected",
                            "asset": asset.value,
                            "ipv4": len(observation["dns"]["ipv4"])})
            _audit_log(session, row.org_id, payload.actor,
                       "orchestration.schedule_collected", "scan_schedule",
                       row.id, asset.value)
            continue
        decision = authorization.authorize(
            session, row.org_id, row.principal, row.capability,
            json.loads(row.targets or "[]"), tool=row.scanner,
            environment=row.environment)
        if decision["decision"] == "deny":
            row.last_error = f"denied: {decision['reason']}"[:500]
            results.append({"schedule": row.name, "result": "denied",
                            "reason": decision["reason"][:200]})
            _audit_log(session, row.org_id, payload.actor,
                       "orchestration.schedule_denied", "scan_schedule", row.id,
                       decision["reason"][:300])
            continue
        job = models.ScanJob(
            org_id=row.org_id, scanner=row.scanner, capability=row.capability,
            principal=row.principal, environment=row.environment,
            targets=row.targets, profile=row.profile, status="queued",
            priority=5, attempts=0, max_attempts=3,
            authorization=json.dumps(decision), created_by=payload.actor,
            created_at=now)
        session.add(job)
        session.flush()
        row.last_job_id = job.id
        row.last_error = None
        results.append({"schedule": row.name, "result": "queued",
                        "job_id": job.id})
        _audit_log(session, row.org_id, payload.actor,
                   "orchestration.schedule_fired", "scan_schedule", row.id,
                   job.id)
    session.commit()
    return {"data": {"processed": len(results), "results": results}}

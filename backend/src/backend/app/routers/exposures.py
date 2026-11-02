"""Attack surface and exposures.

Two different things live here on purpose:

  * **Changes** — the technical chronology, derived on read from observations of
    equal coverage. Nothing is stored twice and opening the screen never touches
    the network.
  * **Exposures** — the condition that needs a decision, with a stable identity,
    a decision history and an explicit reopen policy. Repeated observations bump
    `occurrences`; they do not duplicate the event.

Secrets / code weaknesses / misconfigurations / vulnerabilities are *filtered
summaries over findings*, not separate records: `/exposures/summary/findings`
counts them by kind and links to the same finding ids.
"""
import hashlib
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models, severity as severity_vocab, surface
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1", tags=["exposures"])

DECISIONS = {"resolve": "resolved", "accept": "accepted",
             "false_positive": "false_positive", "reopen": "open"}


class AssetRef(BaseModel):
    id: str | None = None
    type: str | None = None
    value: str | None = None


class ObservationIn(BaseModel):
    asset: AssetRef
    kind: str = "host"
    subject: str | None = Field(default=None, max_length=1024)
    port: int | None = Field(default=None, ge=1, le=65535)
    protocol: str | None = Field(default=None, max_length=16)
    value: dict = Field(default_factory=dict)
    source: str = Field(default="import", max_length=64)
    coverage: str = "full"
    observed_at: str | None = None


class ObservationImportIn(BaseModel):
    observations: list[ObservationIn] = Field(min_length=1, max_length=1000)
    actor: str = Field(default="import", max_length=255)


class DecisionIn(BaseModel):
    action: str
    reason: str | None = Field(default=None, max_length=4096)
    valid_until: str | None = None
    actor: str = Field(default="console", max_length=255)


def _parse_ts(value: str | None) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "timestamps must be ISO-8601") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _resolve_asset(session: Session, org: models.Organization,
                   ref: AssetRef) -> models.Asset:
    if ref.id:
        asset = session.get(models.Asset, ref.id)
        if asset is None or asset.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
        return asset
    if not ref.value:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "each observation needs asset.id or asset.value")
    asset_type = ref.type or "domain"
    if asset_type not in models.ASSET_TYPES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"asset.type must be one of {sorted(models.ASSET_TYPES)}")
    asset = (session.query(models.Asset)
             .filter_by(org_id=org.id, type=asset_type, value=ref.value.strip().lower())
             .one_or_none())
    if asset is None:
        asset = models.Asset(org_id=org.id, type=asset_type,
                             value=ref.value.strip().lower(), source="import")
        session.add(asset)
        session.flush()
    return asset


def _event_data(row: models.ExposureEvent, session: Session) -> dict:
    asset = session.get(models.Asset, row.asset_id) if row.asset_id else None
    return {"id": row.id, "kind": row.kind, "title": row.title,
            "severity": row.severity, "source": row.source,
            "state": row.state, "occurrences": row.occurrences,
            "first_seen_at": row.first_seen_at.isoformat(),
            "last_seen_at": row.last_seen_at.isoformat(),
            "decision_reason": row.decision_reason,
            "decided_by": row.decided_by,
            "decided_at": row.decided_at.isoformat() if row.decided_at else None,
            "accepted_until": row.accepted_until.isoformat() if row.accepted_until else None,
            "reopen_policy": row.reopen_policy,
            "evidence": row.evidence or {},
            "asset": {"id": asset.id, "type": asset.type, "value": asset.value}
            if asset else None}


def _event_key(asset: models.Asset, category: str, condition: dict) -> str:
    return hashlib.sha256(
        "|".join([category, asset.id, condition.get("subject") or "",
                  str(condition.get("port") or "")]).encode()).hexdigest()


def _upsert_event(session: Session, org: models.Organization, asset: models.Asset,
                  category: str, condition: dict, source: str, now: datetime) -> dict:
    key = _event_key(asset, category, condition)
    event = (session.query(models.ExposureEvent)
             .filter_by(org_id=org.id, stable_key=key).one_or_none())
    created = False
    reopened = False
    if event is None:
        event = models.ExposureEvent(
            org_id=org.id, asset_id=asset.id, stable_key=key, kind=category,
            title=condition.get("detail") or category,
            severity=condition.get("severity") or surface.event_severity(category),
            source=source, first_seen_at=now, last_seen_at=now,
            state="open", evidence=condition, occurrences=1)
        session.add(event)
        created = True
    else:
        event.last_seen_at = now
        event.occurrences += 1
        event.evidence = condition
        event.source = source
        expired_acceptance = (event.state == "accepted" and event.accepted_until
                              and _aware(event.accepted_until) <= now)
        if (event.state in {"resolved", "false_positive"}
                and event.reopen_policy == "on_new_observation") or expired_acceptance:
            previous = event.state
            event.state = "open"
            event.decision_reason = None
            event.decided_by = None
            event.decided_at = None
            event.accepted_until = None
            session.add(models.ExposureDecision(
                org_id=org.id, event_id=event.id, action="reopened_by_observation",
                from_state=previous, to_state="open",
                reason="a new observation still shows the condition"))
            reopened = True
    return {"created": created, "reopened": reopened, "event": event}


def _aware(value):
    return None if value is None else (
        value if value.tzinfo else value.replace(tzinfo=timezone.utc))


@router.post("/observations")
def import_observations(payload: ObservationImportIn = None,
                        org: models.Organization = Depends(auth.require_org),
                        session: Session = Depends(get_session)):
    """Import observations, derive changes and manage exposure events.

    A change is only reported when both observations have `coverage=full`; a
    failed or partial collection is reported as a coverage note instead. The same
    condition seen twice bumps the event's `occurrences` — it does not create a
    second event.
    """
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    now = models.utcnow()
    counters = {"received": 0, "assets": 0, "observations": 0,
                "changes": 0, "events_created": 0, "events_updated": 0,
                "events_reopened": 0, "coverage_notes": 0}
    changes_out, notes_out = [], []
    for item in payload.observations:
        if item.kind not in models.OBSERVATION_KINDS:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"kind must be one of {sorted(models.OBSERVATION_KINDS)}")
        if item.coverage not in models.OBSERVATION_COVERAGES:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"coverage must be one of {sorted(models.OBSERVATION_COVERAGES)}")
        asset = _resolve_asset(session, org, item.asset)
        counters["assets"] += 1
        observed_at = _parse_ts(item.observed_at) or now
        previous = (session.query(models.Observation)
                    .filter_by(org_id=org.id, asset_id=asset.id, kind=item.kind)
                    .order_by(models.Observation.observed_at.desc()).first())
        observation = models.Observation(
            org_id=org.id, asset_id=asset.id, kind=item.kind,
            subject=(item.subject or asset.value)[:1024], port=item.port,
            protocol=item.protocol, value=item.value or {},
            source=item.source, coverage=item.coverage,
            observed_at=observed_at, received_at=now)
        session.add(observation)
        session.flush()
        counters["observations"] += 1
        outcome = surface.diff(previous, observation)
        if previous is None and item.kind == "host":
            new_host = {"category": "new_host", "subject": observation.subject,
                        "detail": "asset observed for the first time",
                        "severity": "LOW"}
            result = _upsert_event(session, org, asset, "new_host", new_host,
                                   item.source, now)
            counters["events_created" if result["created"] else "events_updated"] += 1
            counters["events_reopened"] += 1 if result["reopened"] else 0
        counters["changes"] += len(outcome["changes"])
        counters["coverage_notes"] += len(outcome["coverage_notes"])
        for change in outcome["changes"]:
            change["asset"] = {"id": asset.id, "value": asset.value}
            change["observed_at"] = observed_at.isoformat()
            changes_out.append(change)
            if change["category"] in {"open_port", "closed_port", "host_disappeared"}:
                result = _upsert_event(session, org, asset, change["category"],
                                       change, item.source, now)
                if result["created"]:
                    counters["events_created"] += 1
                else:
                    counters["events_updated"] += 1
                counters["events_reopened"] += 1 if result["reopened"] else 0
        # A condition that is still true keeps its event alive even when nothing
        # changed in this observation: occurrences bump and a resolved/accepted
        # event reopens under its policy. Ports only refresh events that exist —
        # a long-standing 443 is not an exposure just because it is open.
        current_value = item.value if isinstance(item.value, dict) else {}
        for port in (surface._ports(current_value) if item.kind == "host" else set()):
            condition = {"category": "open_port", "subject": observation.subject,
                         "port": port, "detail": f"port {port} is reachable"}
            key = _event_key(asset, "open_port", condition)
            existing = (session.query(models.ExposureEvent)
                        .filter_by(org_id=org.id, stable_key=key).one_or_none())
            if existing is None:
                continue
            result = _upsert_event(session, org, asset, "open_port", condition,
                                   item.source, now)
            counters["events_updated"] += 1
            counters["events_reopened"] += 1 if result["reopened"] else 0
        for condition in outcome["current_conditions"]:
            result = _upsert_event(session, org, asset, condition["category"],
                                   condition, item.source, now)
            if result["created"]:
                counters["events_created"] += 1
            else:
                counters["events_updated"] += 1
                counters["events_reopened"] += 1 if result["reopened"] else 0
        for note in outcome["coverage_notes"]:
            notes_out.append({"asset": asset.value, "kind": item.kind, "note": note})
        asset.last_seen_at = now
    _audit_log(session, org.id, payload.actor, "surface.observations_imported",
               "observation", None,
               f"{counters['observations']} observations, "
               f"{counters['changes']} changes, "
               f"{counters['events_created']} exposure events")
    session.commit()
    return {"data": {"counters": counters, "changes": changes_out,
                     "coverage_notes": notes_out}}


@router.get("/attack-surface/changes")
def changes(days: int = Query(default=14, ge=1, le=365),
            category: str | None = Query(default=None),
            asset: str | None = Query(default=None),
            limit: int = Query(default=200, ge=1, le=1000),
            org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    """Technical chronology, derived from observations — never from a scan run."""
    since = models.utcnow() - timedelta(days=days)
    query = (session.query(models.Observation)
             .filter(models.Observation.org_id == org.id)
             .order_by(models.Observation.asset_id,
                       models.Observation.kind,
                       models.Observation.observed_at))
    rows = query.all()
    if asset:
        needle = asset.lower()
        rows = [row for row in rows
                if needle in row.subject.lower()]
    grouped: dict[tuple, list] = {}
    for row in rows:
        grouped.setdefault((row.asset_id, row.kind), []).append(row)
    out, notes = [], []
    for (asset_id, kind), series in grouped.items():
        for previous, current in zip(series, series[1:]):
            if _aware(current.observed_at) < since:
                continue
            outcome = surface.diff(previous, current)
            for note in outcome["coverage_notes"]:
                notes.append({"asset_id": asset_id, "kind": kind, "note": note,
                              "observed_at": current.observed_at.isoformat()})
            for change in outcome["changes"]:
                change["observed_at"] = current.observed_at.isoformat()
                change["asset_id"] = asset_id
                change["source"] = current.source
                out.append(change)
    if category:
        out = [item for item in out if item["category"] == category]
    counts: dict[str, int] = {}
    for item in out:
        counts[item["category"]] = counts.get(item["category"], 0) + 1
    out.sort(key=lambda item: item["observed_at"], reverse=True)
    return {"data": out[:limit], "total": len(out), "counts": counts,
            "coverage_notes": notes[:50],
            "window_days": days}


@router.get("/attack-surface/summary")
def surface_summary(days: int = Query(default=7, ge=1, le=365),
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    listing = changes(days=days, category=None, asset=None, limit=1000,
                      org=org, session=session)
    open_events = (session.query(models.ExposureEvent)
                   .filter_by(org_id=org.id, state="open").count())
    return {"data": {"changes": listing["counts"],
                     "total_changes": listing["total"],
                     "open_exposures": open_events,
                     "coverage_notes": len(listing["coverage_notes"]),
                     "window_days": days}}


@router.get("/exposures")
def list_exposures(state_filter: str | None = Query(default=None, alias="state"),
                   kind: str | None = Query(default=None),
                   severity: str | None = Query(default=None),
                   asset: str | None = Query(default=None),
                   org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    query = session.query(models.ExposureEvent).filter_by(org_id=org.id)
    if state_filter:
        query = query.filter(models.ExposureEvent.state == state_filter)
    if kind:
        query = query.filter(models.ExposureEvent.kind == kind)
    if severity:
        query = query.filter(models.ExposureEvent.severity == severity_vocab.canonical(
            severity))
    if asset:
        asset_row = (session.query(models.Asset)
                     .filter_by(org_id=org.id, value=asset.lower()).one_or_none())
        if asset_row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
        query = query.filter(models.ExposureEvent.asset_id == asset_row.id)
    rows = (query.order_by(models.ExposureEvent.state,
                           models.ExposureEvent.last_seen_at.desc()).all())
    data = [_event_data(row, session) for row in rows]
    return {"data": data, "total": len(data),
            "counts": {state: sum(1 for row in data if row["state"] == state)
                       for state in models.EXPOSURE_STATES}}


@router.get("/exposures/summary/findings")
def findings_summary(org: models.Organization = Depends(auth.require_org),
                     session: Session = Depends(get_session)):
    """Secrets / code weaknesses / misconfigurations / vulnerabilities as filtered
    summaries over the same findings, never as copies."""
    rows = (session.query(models.Finding)
            .filter(models.Finding.org_id == org.id,
                    models.Finding.status != "suppressed").all())
    buckets: dict[str, dict] = {}
    for row in rows:
        bucket = buckets.setdefault(row.kind, {"kind": row.kind, "total": 0,
                                               "open": 0, "severity": {},
                                               "finding_ids": []})
        bucket["total"] += 1
        if row.status in {"open", "acknowledged"}:
            bucket["open"] += 1
        key = severity_vocab.canonical(row.severity)
        bucket["severity"][key] = bucket["severity"].get(key, 0) + 1
        if len(bucket["finding_ids"]) < 50:
            bucket["finding_ids"].append(row.id)
    return {"data": sorted(buckets.values(), key=lambda item: -item["total"]),
            "total": len(rows)}


@router.get("/exposures/{event_id}")
def get_exposure(event_id: str,
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    event = session.get(models.ExposureEvent, event_id)
    if event is None or event.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "exposure event not found")
    decisions = (session.query(models.ExposureDecision)
                 .filter_by(event_id=event.id)
                 .order_by(models.ExposureDecision.created_at.desc()).all())
    return {"data": {**_event_data(event, session),
                     "decisions": [{"action": row.action, "from": row.from_state,
                                    "to": row.to_state, "reason": row.reason,
                                    "actor": row.actor,
                                    "valid_until": row.valid_until.isoformat()
                                    if row.valid_until else None,
                                    "at": row.created_at.isoformat()}
                                   for row in decisions]}}


@router.post("/exposures/{event_id}/decide")
def decide(event_id: str, payload: DecisionIn = None,
           org: models.Organization = Depends(auth.require_org),
           session: Session = Depends(get_session)):
    """Resolve, accept (with reason + validity), mark false positive, or reopen."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.action not in DECISIONS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"action must be one of {sorted(DECISIONS)}")
    event = session.get(models.ExposureEvent, event_id)
    if event is None or event.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "exposure event not found")
    if payload.action in {"resolve", "accept", "false_positive"} and not payload.reason:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "a decision needs a reason")
    valid_until = _parse_ts(payload.valid_until)
    if payload.action == "accept" and valid_until is not None \
            and valid_until <= models.utcnow():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "valid_until must be in the future")
    previous = event.state
    target = DECISIONS[payload.action]
    if previous == target:
        return {"data": _event_data(event, session), "changed": False}
    event.state = target
    event.decision_reason = payload.reason
    event.decided_by = payload.actor
    event.decided_at = models.utcnow()
    event.accepted_until = valid_until if payload.action == "accept" else None
    session.add(models.ExposureDecision(
        org_id=org.id, event_id=event.id, action=payload.action,
        from_state=previous, to_state=target, reason=payload.reason,
        actor=payload.actor, valid_until=valid_until))
    _audit_log(session, org.id, payload.actor, f"exposure.{payload.action}",
               "exposure_event", event.id, f"{previous} -> {target}: "
                                           f"{(payload.reason or '')[:120]}")
    session.commit()
    return {"data": _event_data(event, session), "changed": True}

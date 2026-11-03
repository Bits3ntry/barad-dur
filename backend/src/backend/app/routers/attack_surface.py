"""Web surface, lookalikes, review and the weekly summary.

The three lists share one rule: the platform shows what it observed with the
coverage it had, and never upgrades an observation into a claim.

  * a path returning 200 is `observed`, not vulnerable; only a linked finding
    makes it `confirmed_finding`;
  * an excluded origin is `not_evaluated`, never "safe";
  * a lookalike is an external observed domain — DNS resolving proves neither
    registration nor malice, and nothing here authorizes active testing;
  * confirming that an asset is ours never grants a scan; that still needs a
    scope entry and a scan grant.
"""
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models, projects as projects_ref, scoping
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/attack-surface", tags=["attack-surface"])

SENSITIVE_HINTS = ("admin", "internal", "debug", "backup", ".env", "config",
                   "private", "graphql", "actuator", "swagger")


def _parse_ts(value: str | None) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "timestamps must be ISO-8601") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _origin_host(origin: str) -> str:
    value = origin.split("://")[-1]
    return value.split("/")[0].split(":")[0].lower()


def _excluded_hosts(session: Session, org_id: str) -> list:
    return (session.query(models.ScopeExclusion)
            .filter_by(org_id=org_id, status="active").all())


def _host_excluded(session: Session, org_id: str, origin: str) -> dict | None:
    host = _origin_host(origin)
    for row in _excluded_hosts(session, org_id):
        try:
            if scoping.covers(scoping.normalize(row.target_type, row.value), "domain", host):
                return {"id": row.id, "value": row.value, "reason": row.reason}
        except scoping.ScopeValueError:
            continue
    return None


def _endpoint_data(row: models.WebEndpoint) -> dict:
    return {"id": row.id, "origin": row.origin, "path": row.path,
            "method": row.method, "state": row.state,
            "status_code": row.status_code, "evidence": row.evidence,
            "source": row.discovery_source, "finding_id": row.finding_id,
            "last_observed_at": row.last_observed_at.isoformat(),
            "asset_id": row.asset_id}


class EndpointIn(BaseModel):
    origin: str = Field(min_length=3, max_length=512)
    path: str = Field(min_length=1, max_length=1024)
    method: str = Field(default="GET", max_length=16)
    status_code: int | None = Field(default=None, ge=100, le=599)
    evidence: str | None = Field(default=None, max_length=4096)
    source: str | None = Field(default=None, max_length=64)
    asset: str | None = Field(default=None, max_length=1024)
    observed_at: str | None = None


class EndpointImportIn(BaseModel):
    endpoints: list[EndpointIn] = Field(min_length=1, max_length=2000)
    actor: str = Field(default="import", max_length=255)


@router.post("/web-endpoints")
def import_endpoints(payload: EndpointImportIn = None,
                     org: models.Organization = Depends(auth.require_org),
                     session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    counters = {"received": 0, "created": 0, "updated": 0,
                "excluded": 0, "sensitive": 0}
    data = []
    now = models.utcnow()
    for item in payload.endpoints:
        counters["received"] += 1
        origin = item.origin.rstrip("/").lower()
        exclusion = _host_excluded(session, org.id, origin)
        asset = None
        if item.asset:
            asset = (session.query(models.Asset)
                     .filter_by(org_id=org.id, value=item.asset.lower()).one_or_none())
        else:
            host = _origin_host(origin)
            asset = (session.query(models.Asset)
                     .filter_by(org_id=org.id, type="domain", value=host).one_or_none())
        # An excluded origin was never evaluated; saying otherwise would read as
        # "safe" or as a vulnerability, and both are wrong.
        state = "not_evaluated" if exclusion else (
            "observed" if item.status_code is not None else "candidate")
        row = (session.query(models.WebEndpoint)
               .filter_by(org_id=org.id, origin=origin, path=item.path,
                          method=item.method.upper()).one_or_none())
        evidence = item.evidence
        if exclusion:
            evidence = (f"excluded by scope: {exclusion['value']} ({exclusion['reason']})"
                        + (f"; {evidence}" if evidence else ""))
            counters["excluded"] += 1
        sensitive = any(hint in item.path.lower() for hint in SENSITIVE_HINTS)
        if sensitive:
            counters["sensitive"] += 1
        if row is None:
            row = models.WebEndpoint(
                org_id=org.id, asset_id=asset.id if asset else None,
                origin=origin, path=item.path, method=item.method.upper(),
                state=state, status_code=item.status_code, evidence=evidence,
                discovery_source=item.source,
                last_observed_at=_parse_ts(item.observed_at) or now,
                created_at=now, updated_at=now)
            session.add(row)
            counters["created"] += 1
        else:
            row.status_code = item.status_code
            row.evidence = evidence or row.evidence
            row.last_observed_at = _parse_ts(item.observed_at) or now
            row.state = state
            row.discovery_source = item.source or row.discovery_source
            row.updated_at = now
            counters["updated"] += 1
        session.add(row)
        data.append(row)
    session.flush()
    _audit_log(session, org.id, payload.actor, "surface.web_endpoints_imported",
               "web_endpoint", None,
               f"{counters['created']} created, {counters['excluded']} not evaluated")
    session.commit()
    return {"data": {"counters": counters,
                     "endpoints": [_endpoint_data(row) for row in data]}}


@router.get("/web-endpoints")
def list_endpoints(origin: str | None = Query(default=None),
                   state_filter: str | None = Query(default=None, alias="state"),
                   org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    query = session.query(models.WebEndpoint).filter_by(org_id=org.id)
    if origin:
        query = query.filter(models.WebEndpoint.origin == origin.lower())
    if state_filter:
        query = query.filter(models.WebEndpoint.state == state_filter)
    rows = query.order_by(models.WebEndpoint.origin,
                          models.WebEndpoint.path).all()
    week_ago = models.utcnow() - timedelta(days=7)
    new_paths = [row for row in rows
                 if (row.last_observed_at if row.last_observed_at.tzinfo
                     else row.last_observed_at.replace(tzinfo=timezone.utc)) >= week_ago]
    origins = sorted({row.origin for row in rows})
    counters = {"endpoints": len(rows), "origins": len(origins),
                "new_last_7d": len(new_paths),
                "not_evaluated": sum(1 for row in rows
                                     if row.state in {"excluded", "not_evaluated"}),
                "confirmed": sum(1 for row in rows
                                 if row.state == "confirmed_finding"),
                "sensitive_observed": sum(
                    1 for row in rows
                    if row.state == "observed" and row.status_code == 200
                    and any(hint in row.path.lower() for hint in SENSITIVE_HINTS))}
    return {"data": [_endpoint_data(row) for row in rows], "total": len(rows),
            "origins": origins, "counters": counters,
            "note": ("a 200 is an observed response, not a vulnerability; "
                     "excluded paths were not evaluated")}


class EndpointStateIn(BaseModel):
    state: str
    finding_id: str | None = None
    reason: str | None = Field(default=None, max_length=4096)
    actor: str = Field(default="console", max_length=255)


@router.post("/web-endpoints/{endpoint_id}/state")
def set_endpoint_state(endpoint_id: str, payload: EndpointStateIn = None,
                       org: models.Organization = Depends(auth.require_org),
                       session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.state not in models.WEB_ENDPOINT_STATES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"state must be one of {sorted(models.WEB_ENDPOINT_STATES)}")
    row = session.get(models.WebEndpoint, endpoint_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "endpoint not found")
    if payload.state == "confirmed_finding":
        finding = session.get(models.Finding, payload.finding_id) \
            if payload.finding_id else None
        if finding is None or finding.org_id != org.id:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                "confirmed_finding needs a finding_id of this organization")
        row.finding_id = finding.id
    if payload.state in {"excluded", "not_evaluated"} and not payload.reason:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "excluding a path needs a reason")
    row.state = payload.state
    row.updated_at = models.utcnow()
    _audit_log(session, org.id, payload.actor, "surface.web_endpoint_state",
               "web_endpoint", row.id,
               f"{row.origin}{row.path} -> {payload.state}" +
               (f" ({payload.reason})" if payload.reason else ""))
    session.commit()
    return {"data": _endpoint_data(row)}


class LookalikeCandidate(BaseModel):
    candidate: str = Field(min_length=3, max_length=255)
    similarity: str | None = Field(default=None, max_length=32)
    dns: dict = Field(default_factory=dict)
    mx: dict = Field(default_factory=dict)
    certificates: dict = Field(default_factory=dict)
    registration_evidence: dict = Field(default_factory=dict)
    registration_state: str = "unknown"
    last_checked_at: str | None = None


class LookalikeImportIn(BaseModel):
    root_domain: str = Field(min_length=3, max_length=255)
    watch_root: bool = True
    candidates: list[LookalikeCandidate] = Field(default_factory=list, max_length=1000)
    actor: str = Field(default="import", max_length=255)


def _lookalike_data(row: models.LookalikeDomain) -> dict:
    return {"id": row.id, "root_domain": row.root_domain, "candidate": row.candidate,
            "similarity": row.similarity, "state": row.state,
            "registration_state": row.registration_state,
            "registration_evidence": row.registration_evidence or {},
            "dns": row.dns or {}, "mx": row.mx or {},
            "certificates": row.certificates or {},
            "review_reason": row.review_reason,
            "last_checked_at": row.last_checked_at.isoformat()
            if row.last_checked_at else None,
            "updated_at": row.updated_at.isoformat(),
            "authorization": "none: an impersonating domain is never a scan target"}


@router.post("/lookalikes")
def import_lookalikes(payload: LookalikeImportIn = None,
                      org: models.Organization = Depends(auth.require_org),
                      session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    root = payload.root_domain.strip().lower()
    now = models.utcnow()
    counters = {"created": 0, "updated": 0}
    rows = []

    def upsert(candidate: str, **fields):
        row = (session.query(models.LookalikeDomain)
               .filter_by(org_id=org.id, root_domain=root, candidate=candidate)
               .one_or_none())
        if row is None:
            row = models.LookalikeDomain(
                org_id=org.id, root_domain=root, candidate=candidate,
                created_at=now, updated_at=now, **fields)
            session.add(row)
            counters["created"] += 1
        else:
            for key, value in fields.items():
                setattr(row, key, value)
            row.updated_at = now
            counters["updated"] += 1
        session.add(row)
        rows.append(row)
        return row

    if payload.watch_root:
        upsert(root, state="confirmed", similarity="subdomain",
               registration_state="confirmed",
               registration_evidence={"watched": True, "source": "manual"})
    for item in payload.candidates:
        candidate = item.candidate.strip().lower()
        if candidate == root:
            continue
        upsert(candidate,
               similarity=item.similarity if item.similarity in
               models.LOOKALIKE_SIMILARITY else "other",
               dns=item.dns or {}, mx=item.mx or {},
               certificates=item.certificates or {},
               registration_evidence=item.registration_evidence or {},
               registration_state=(item.registration_state
                                   if item.registration_state in
                                   {"confirmed", "unconfirmed", "unknown"}
                                   else "unknown"),
               last_checked_at=_parse_ts(item.last_checked_at))
    session.flush()
    _audit_log(session, org.id, payload.actor, "surface.lookalikes_imported",
               "lookalike_domain", None,
               f"root {root}: {counters['created']} new candidates")
    session.commit()
    return {"data": {"counters": counters,
                     "rows": [_lookalike_data(row) for row in rows],
                     "cadence": ("daily for registered candidates, weekly for the rest "
                                 "once a passive collector runs; no scheduled check is "
                                 "recorded here")}}


@router.get("/lookalikes")
def list_lookalikes(state_filter: str | None = Query(default=None, alias="state"),
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    query = session.query(models.LookalikeDomain).filter_by(org_id=org.id)
    if state_filter:
        query = query.filter(models.LookalikeDomain.state == state_filter)
    rows = query.order_by(models.LookalikeDomain.root_domain,
                          models.LookalikeDomain.state,
                          models.LookalikeDomain.candidate).all()
    data = [_lookalike_data(row) for row in rows]
    return {"data": data, "total": len(data),
            "counts": {state: sum(1 for row in data if row["state"] == state)
                       for state in models.LOOKALIKE_STATES}}


class LookalikeDecideIn(BaseModel):
    action: str
    reason: str | None = Field(default=None, max_length=4096)
    evidence: dict | None = None
    actor: str = Field(default="console", max_length=255)


@router.post("/lookalikes/{lookalike_id}/decide")
def decide_lookalike(lookalike_id: str, payload: LookalikeDecideIn = None,
                     org: models.Organization = Depends(auth.require_org),
                     session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    mapping = {"confirm": "confirmed", "external": "external", "dismiss": "dismissed"}
    if payload.action not in mapping:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"action must be one of {sorted(mapping)}")
    if payload.action in {"external", "dismiss"} and not payload.reason:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "this decision needs a reason")
    row = session.get(models.LookalikeDomain, lookalike_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "lookalike not found")
    row.state = mapping[payload.action]
    row.review_reason = payload.reason
    if payload.evidence:
        row.registration_evidence = {**(row.registration_evidence or {}),
                                     **payload.evidence}
    row.updated_at = models.utcnow()
    _audit_log(session, org.id, payload.actor, "surface.lookalike_decided",
               "lookalike_domain", row.id,
               f"{row.candidate} -> {row.state}")
    session.commit()
    return {"data": _lookalike_data(row)}


@router.get("/review")
def review_queue(org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """Assets whose ownership is not settled. Confirming ownership is not a grant."""
    rows = (session.query(models.Asset)
            .filter_by(org_id=org.id)
            .filter(models.Asset.archived_at.is_(None))
            .filter(models.Asset.classification_status.in_(
                ["unclassified", "pending"]))
            .order_by(models.Asset.value).all())
    data = []
    for asset in rows:
        observations = (session.query(models.Observation)
                        .filter_by(org_id=org.id, asset_id=asset.id)
                        .order_by(models.Observation.observed_at.desc()).count())
        data.append({"asset": {"id": asset.id, "type": asset.type,
                               "value": asset.value, "source": asset.source,
                               "owner": asset.owner,
                               "classification_status": asset.classification_status},
                     "project_id": asset.project_id,
                     "observations": observations})
    return {"data": data, "total": len(data),
            "note": ("a resolved IP may belong to a CDN or provider; "
                     "ownership confirmation never grants active testing")}


class ReviewDecisionIn(BaseModel):
    action: str
    project: str | None = Field(default=None, max_length=128)
    owner: str | None = Field(default=None, max_length=255)
    reason: str | None = Field(default=None, max_length=4096)
    actor: str = Field(default="console", max_length=255)


@router.post("/review/{asset_id}")
def decide_review(asset_id: str, payload: ReviewDecisionIn = None,
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    mapping = {"confirm": "confirmed", "external": "external", "discard": "discarded"}
    if payload.action not in mapping:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"action must be one of {sorted(mapping)}")
    if payload.action in {"external", "discard"} and not payload.reason:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "this decision needs a reason")
    asset = session.get(models.Asset, asset_id)
    if asset is None or asset.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    changes = [f"classification={mapping[payload.action]}"]
    asset.classification_status = mapping[payload.action]
    if payload.owner:
        asset.owner = payload.owner.strip()
        changes.append(f"owner={asset.owner}")
    if payload.project:
        project_row = projects_ref.by_ref(session, org.id, payload.project)
        if project_row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
        asset.project_id = project_row.id
        changes.append(f"project={project_row.slug}")
    _audit_log(session, org.id, payload.actor, "asset.reviewed", "asset", asset.id,
               ", ".join(changes) + (f" ({payload.reason})" if payload.reason else ""))
    session.commit()
    return {"data": {"id": asset.id, "value": asset.value,
                     "classification_status": asset.classification_status,
                     "owner": asset.owner,
                     "authorization": "unchanged: ownership is not a scan grant"}}


@router.get("/summary/weekly")
def weekly_summary(org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    """The weekly digest as a query. Delivery is declared not configured: there is
    no scheduler wired for it, and a scheduled date is never a performed check."""
    from backend.app.routers.exposures import changes as changes_endpoint
    listing = changes_endpoint(days=7, category=None, asset=None, limit=1000,
                               org=org, session=session)
    week_ago = models.utcnow() - timedelta(days=7)
    endpoints = (session.query(models.WebEndpoint)
                 .filter_by(org_id=org.id).all())
    new_paths = [row for row in endpoints
                 if (row.last_observed_at if row.last_observed_at.tzinfo
                     else row.last_observed_at.replace(tzinfo=timezone.utc)) >= week_ago]
    lookalikes = (session.query(models.LookalikeDomain)
                  .filter_by(org_id=org.id, state="candidate").count())
    open_events = (session.query(models.ExposureEvent)
                   .filter_by(org_id=org.id, state="open").count())
    return {"data": {"window_days": 7,
                     "changes": listing["counts"],
                     "total_changes": listing["total"],
                     "new_paths": len(new_paths),
                     "lookalike_candidates": lookalikes,
                     "open_exposures": open_events,
                     "coverage_notes": len(listing["coverage_notes"]),
                     "delivery": {"configured": False,
                                  "reason": ("no notification channel and no scheduler "
                                             "are wired for the digest; this endpoint is "
                                             "a query, not a delivery")}}}

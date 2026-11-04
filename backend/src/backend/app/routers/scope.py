"""Scope: the declared limits of what may be assessed.

Two things live here and must not be confused:
  * `scope_targets` — positive declarations (domain, pattern, IP, CIDR, URL,
    repository, service, API, cloud account reference), each with validity,
    owner, capabilities and a reason;
  * `scan_grants` (elsewhere) — the authorization a collector actually checks.

A scope row never runs anything. A wildcard row is a rule, not a host: it does
not create an asset and does not expand into names. A concrete row creates or
links the canonical asset with provenance `scope`.
"""
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models, scoping
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/scope", tags=["scope"])

SCOPE_TYPES = scoping.SCOPE_TYPES
STATUSES = {"active", "disabled"}


def _parse_ts(value: str | None, field_name: str) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"{field_name} must be an ISO-8601 timestamp") from None
    if parsed.tzinfo is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"{field_name} must include a timezone")
    return parsed


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _validity(row) -> str:
    now = models.utcnow()
    if row.status != "active":
        return row.status
    valid_until = scoping._aware(row.valid_until)
    if valid_until is not None and valid_until <= now:
        return "expired"
    valid_from = scoping._aware(row.valid_from)
    if valid_from is not None and valid_from > now:
        return "scheduled"
    return "active"


def _target_data(session: Session, row: models.ScopeTarget) -> dict:
    asset = session.get(models.Asset, row.asset_id) if row.asset_id else None
    return {"id": row.id, "target_type": row.target_type, "value": row.value,
            "status": _validity(row), "note": row.note, "reason": row.reason,
            "owner": row.owner, "source": row.source,
            "valid_from": _iso(row.valid_from), "valid_until": _iso(row.valid_until),
            "restrictions": row.restrictions or [],
            "capabilities": row.capabilities or [],
            "include_apex": bool(row.include_apex),
            "is_pattern": row.value.startswith("*.") or "://*." in row.value,
            "asset": {"id": asset.id, "type": asset.type, "value": asset.value,
                      "source": asset.source} if asset else None,
            "created_at": row.created_at.isoformat()}


def _exclusion_data(row: models.ScopeExclusion) -> dict:
    now = models.utcnow()
    state = "active"
    if row.status != "active":
        state = row.status
    elif scoping._aware(row.expires_at) is not None and scoping._aware(row.expires_at) <= now:
        state = "expired"
    return {"id": row.id, "target_type": row.target_type, "value": row.value,
            "reason": row.reason, "owner": row.owner, "source": row.source,
            "status": state, "expires_at": _iso(row.expires_at),
            "created_at": row.created_at.isoformat()}


def _link_asset(session: Session, org: models.Organization, row: models.ScopeTarget,
                norm: scoping.Normalized) -> None:
    """Create or link the canonical asset for a concrete target.

    A pattern returns None from `concrete_asset`, so `*.example.com` can never
    invent a host. An asset that already exists keeps its original provenance;
    scope only adds the link.
    """
    concrete = scoping.concrete_asset(norm)
    if concrete is None:
        return
    asset_type, value = concrete
    asset = (session.query(models.Asset)
             .filter_by(org_id=org.id, type=asset_type, value=value).one_or_none())
    if asset is None:
        asset = models.Asset(org_id=org.id, type=asset_type, value=value,
                             source="scope", discovered_at=models.utcnow(),
                             last_seen_at=models.utcnow())
        session.add(asset)
        session.flush()
    row.asset_id = asset.id


class ScopeEntry(BaseModel):
    target_type: str
    value: str = Field(min_length=1, max_length=1024)
    note: str | None = Field(default=None, max_length=4096)
    reason: str | None = Field(default=None, max_length=4096)
    owner: str | None = Field(default=None, max_length=255)
    valid_from: str | None = None
    valid_until: str | None = None
    restrictions: list[str] = Field(default_factory=list)
    capabilities: list[str] | None = None
    include_apex: bool = False
    actor: str | None = Field(default=None, max_length=255)


class ScopePatch(BaseModel):
    reason: str | None = Field(default=None, max_length=4096)
    owner: str | None = Field(default=None, max_length=255)
    note: str | None = Field(default=None, max_length=4096)
    valid_from: str | None = None
    valid_until: str | None = None
    restrictions: list[str] | None = None
    capabilities: list[str] | None = None
    include_apex: bool | None = None
    status: str | None = None
    actor: str | None = Field(default=None, max_length=255)


class ExclusionPatch(BaseModel):
    reason: str | None = Field(default=None, max_length=4096)
    owner: str | None = Field(default=None, max_length=255)
    expires_at: str | None = None
    status: str | None = None
    actor: str | None = Field(default=None, max_length=255)


class CheckIn(BaseModel):
    target_type: str | None = None
    value: str = Field(min_length=1, max_length=1024)
    capability: str | None = None


def _normalized_or_422(target_type: str, value: str, include_apex: bool = False):
    try:
        return scoping.normalize(target_type, value, include_apex)
    except scoping.ScopeValueError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from None


def _capabilities_or_422(target_type: str, capabilities):
    try:
        return scoping.effective_capabilities(target_type, capabilities)
    except scoping.ScopeValueError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from None


@router.get("/targets")
def targets(target_type: str | None = Query(default=None),
            status_filter: str | None = Query(default=None, alias="status"),
            q: str | None = Query(default=None),
            org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    query = session.query(models.ScopeTarget).filter_by(org_id=org.id)
    if target_type:
        query = query.filter(models.ScopeTarget.target_type == target_type)
    if q:
        query = query.filter(models.ScopeTarget.value.ilike(f"%{q.strip()}%"))
    rows = query.order_by(models.ScopeTarget.target_type,
                          models.ScopeTarget.value).all()
    data = [_target_data(session, row) for row in rows]
    if status_filter:
        data = [row for row in data if row["status"] == status_filter]
    return {"data": data, "total": len(data)}


@router.post("/targets")
def add_target(payload: ScopeEntry = None,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    norm = _normalized_or_422(payload.target_type, payload.value, payload.include_apex)
    capabilities = _capabilities_or_422(payload.target_type, payload.capabilities)
    existing = (session.query(models.ScopeTarget)
                .filter_by(org_id=org.id, target_type=payload.target_type,
                           value=norm.value).one_or_none())
    if existing is not None:
        return {"data": _target_data(session, existing), "already_known": True}
    row = models.ScopeTarget(
        org_id=org.id, target_type=payload.target_type, value=norm.value,
        note=payload.note, reason=payload.reason, owner=payload.owner,
        source="manual", capabilities=capabilities,
        restrictions=list(payload.restrictions or []),
        include_apex=payload.include_apex,
        valid_from=_parse_ts(payload.valid_from, "valid_from"),
        valid_until=_parse_ts(payload.valid_until, "valid_until"),
        created_at=models.utcnow(), updated_at=models.utcnow())
    session.add(row)
    session.flush()
    _link_asset(session, org, row, norm)
    _audit_log(session, org.id, payload.actor or "system", "scope.target_added",
               "scope_target", row.id,
               f"{payload.target_type}:{row.value}" + (" (pattern)" if norm.pattern else ""))
    session.commit()
    return {"data": _target_data(session, row), "already_known": False}


@router.patch("/targets/{target_id}")
def patch_target(target_id: str, payload: ScopePatch = None,
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """Edit validity, owner, capabilities or status. Value and type are identity:
    a different value is a different declaration, so create a new row."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    row = session.get(models.ScopeTarget, target_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scope target not found")
    changes = []
    if payload.reason is not None:
        row.reason = payload.reason
        changes.append("reason")
    if payload.owner is not None:
        row.owner = payload.owner.strip() or None
        changes.append(f"owner={row.owner or 'none'}")
    if payload.note is not None:
        row.note = payload.note
        changes.append("note")
    for field_name in ("valid_from", "valid_until"):
        value = getattr(payload, field_name)
        if value is not None:
            setattr(row, field_name, _parse_ts(value, field_name))
            changes.append(f"{field_name}={value or 'none'}")
    if payload.restrictions is not None:
        row.restrictions = list(payload.restrictions)
        changes.append("restrictions")
    if payload.capabilities is not None:
        row.capabilities = _capabilities_or_422(row.target_type, payload.capabilities)
        changes.append(f"capabilities={','.join(row.capabilities) or 'none'}")
    if payload.include_apex is not None:
        row.include_apex = payload.include_apex
        changes.append(f"include_apex={payload.include_apex}")
    if payload.status is not None:
        if payload.status not in STATUSES:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"status must be one of {sorted(STATUSES)}")
        row.status = payload.status
        changes.append(f"status={payload.status}")
    if not changes:
        return {"data": _target_data(session, row), "changed": False}
    row.updated_at = models.utcnow()
    _audit_log(session, org.id, payload.actor or "system", "scope.target_updated",
               "scope_target", row.id, ", ".join(changes))
    session.commit()
    return {"data": _target_data(session, row), "changed": True}


@router.delete("/targets/{target_id}")
def delete_target(target_id: str, actor: str | None = Query(default=None),
                  hard: bool = Query(default=False),
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    """Default is disable: the declaration stops authorizing but the record,
    its asset link and the audit trail stay. `hard=true` is explicit."""
    row = session.get(models.ScopeTarget, target_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scope target not found")
    if hard:
        value = row.value
        session.delete(row)
        _audit_log(session, org.id, actor or "system", "scope.target_deleted",
                   "scope_target", target_id, value)
        session.commit()
        return {"deleted": target_id, "value": value}
    if row.status == "disabled":
        return {"data": _target_data(session, row), "changed": False}
    row.status = "disabled"
    row.updated_at = models.utcnow()
    _audit_log(session, org.id, actor or "system", "scope.target_disabled",
               "scope_target", row.id, row.value)
    session.commit()
    return {"data": _target_data(session, row), "changed": True}


@router.get("/exclusions")
def exclusions(org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    rows = (session.query(models.ScopeExclusion)
            .filter_by(org_id=org.id)
            .order_by(models.ScopeExclusion.target_type,
                      models.ScopeExclusion.value).all())
    return {"data": [_exclusion_data(row) for row in rows], "total": len(rows)}


@router.post("/exclusions")
def add_exclusion(payload: ScopeEntry = None,
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if not payload.reason:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "reason required")
    norm = _normalized_or_422(payload.target_type, payload.value, payload.include_apex)
    existing = (session.query(models.ScopeExclusion)
                .filter_by(org_id=org.id, target_type=payload.target_type,
                           value=norm.value).one_or_none())
    if existing is not None:
        # Re-declaring a disabled exclusion re-arms it: the row survives so the
        # audit trail keeps both decisions, but the control must come back on.
        if existing.status != "active":
            existing.status = "active"
            existing.updated_at = models.utcnow()
            _audit_log(session, org.id, payload.actor or "system",
                       "scope.exclusion_restored", "scope_exclusion", existing.id,
                       f"{existing.target_type}:{existing.value} (re-declared)")
            session.commit()
            return {"data": _exclusion_data(existing), "already_known": False,
                    "restored": True}
        return {"data": _exclusion_data(existing), "already_known": True}
    row = models.ScopeExclusion(
        org_id=org.id, target_type=payload.target_type, value=norm.value,
        reason=payload.reason, owner=payload.owner, source="manual",
        expires_at=_parse_ts(payload.valid_until, "valid_until"),
        created_at=models.utcnow(), updated_at=models.utcnow())
    session.add(row)
    session.flush()
    _audit_log(session, org.id, payload.actor or "system", "scope.exclusion_added",
               "scope_exclusion", row.id,
               f"{payload.target_type}:{row.value} ({payload.reason[:80]})")
    session.commit()
    return {"data": _exclusion_data(row), "already_known": False}


@router.patch("/exclusions/{exclusion_id}")
def patch_exclusion(exclusion_id: str, payload: ExclusionPatch = None,
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    row = session.get(models.ScopeExclusion, exclusion_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "scope exclusion not found")
    changes = []
    if payload.reason is not None:
        row.reason = payload.reason
        changes.append("reason")
    if payload.owner is not None:
        row.owner = payload.owner.strip() or None
        changes.append("owner")
    if payload.expires_at is not None:
        row.expires_at = _parse_ts(payload.expires_at, "expires_at")
        changes.append("expires_at")
    if payload.status is not None:
        if payload.status not in STATUSES:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"status must be one of {sorted(STATUSES)}")
        row.status = payload.status
        changes.append(f"status={payload.status}")
    if not changes:
        return {"data": _exclusion_data(row), "changed": False}
    row.updated_at = models.utcnow()
    _audit_log(session, org.id, payload.actor or "system", "scope.exclusion_updated",
               "scope_exclusion", row.id, ", ".join(changes))
    session.commit()
    return {"data": _exclusion_data(row), "changed": True}


@router.post("/check")
def check(payload: CheckIn = None,
          org: models.Organization = Depends(auth.require_org),
          session: Session = Depends(get_session)):
    """Answer "may this value be acted on?" without touching anything.

    Exclusions win; an expired or disabled target grants nothing; a capability
    that is not listed is denied. Unknown capability names are a 422, not an
    allow.
    """
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    target_type = payload.target_type
    if target_type is None:
        target_type = _guess_type(payload.value)
    _normalized_or_422(target_type, payload.value)
    targets_rows = (session.query(models.ScopeTarget)
                    .filter_by(org_id=org.id).all())
    exclusions_rows = (session.query(models.ScopeExclusion)
                       .filter_by(org_id=org.id).all())
    try:
        decision = scoping.decide(targets_rows, exclusions_rows, target_type,
                                  payload.value, payload.capability)
    except scoping.ScopeValueError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from None
    return {"data": {"target_type": target_type, "value": payload.value,
                     "capability": payload.capability, **decision.as_dict()}}


def _guess_type(value: str) -> str:
    if "://" in value:
        return "url"
    if "/" in value:
        return "cidr" if value.split("/")[0].count(".") == 3 else "repository"
    try:
        import ipaddress
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        return "domain"


@router.get("/resolved")
def resolved(org: models.Organization = Depends(auth.require_org),
             session: Session = Depends(get_session)):
    """Active, in-validity targets minus everything an exclusion covers.

    Matching uses the same engine as `/check`; an exclusion of a pattern removes
    the concrete targets it covers, not just an identical row.
    """
    rows = (session.query(models.ScopeTarget)
            .filter_by(org_id=org.id).all())
    excluded_rows = (session.query(models.ScopeExclusion)
                     .filter_by(org_id=org.id).all())
    got, dropped = [], []
    for row in rows:
        if _validity(row) != "active":
            continue
        try:
            norm = scoping.normalize(row.target_type, row.value, bool(row.include_apex))
        except scoping.ScopeValueError:
            dropped.append({**_target_data(session, row), "dropped_because": "invalid value"})
            continue
        blocked = None
        for exclusion in excluded_rows:
            # The engine already handles pattern-vs-concrete (an excluded
            # *.example.com drops api.example.com); a pattern target itself is
            # not "covered" by another pattern, which is a policy question.
            if scoping._row_covers(exclusion, row.target_type, row.value):
                blocked = _exclusion_data(exclusion)
                break
        if blocked is not None:
            dropped.append({**_target_data(session, row), "dropped_because": "excluded",
                            "excluded_by": blocked})
            continue
        got.append(_target_data(session, row))
    return {"data": got, "total": len(got),
            "excluded": [_exclusion_data(row) for row in excluded_rows],
            "excluded_count": len(excluded_rows),
            "dropped": dropped, "dropped_count": len(dropped)}

"""B4 endpoints: externally observable assets, crt.sh subdomain sweep."""
import datetime
import json
import urllib.request
from email.utils import parsedate_to_datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1", tags=["easm"])

CRTSH_CTLOG = "https://crt.sh/?q=%25.{domain}&output=json"


def _parse_cert_date(value) -> str | None:
    """TLS dates arrive in RFC-822 form ("Dec 20 14:00:30 2026 GMT")."""
    if not isinstance(value, str) or not value:
        return None
    try:
        return parsedate_to_datetime(value).isoformat()
    except (TypeError, ValueError):
        return None


def _latest_observation(session: Session, asset: models.Asset) -> dict | None:
    """Newest snapshot, flattened enough for a table: addresses and certificate."""
    snapshot = (session.query(models.AssetSnapshot)
                .filter_by(asset_id=asset.id)
                .order_by(models.AssetSnapshot.observed_at.desc()).first())
    if snapshot is None:
        return None
    try:
        data = json.loads(snapshot.data)
    except (TypeError, ValueError):
        return {"observed_at": snapshot.observed_at.isoformat(), "error": "unreadable"}
    dns = data.get("dns") or {}
    tls = data.get("tls") or {}
    not_after = _parse_cert_date(tls.get("not_after"))
    days_left = None
    if not_after:
        days_left = (datetime.datetime.fromisoformat(not_after)
                     - datetime.datetime.now(datetime.timezone.utc)).days
    return {
        "observed_at": snapshot.observed_at.isoformat(),
        "source": snapshot.source,
        "ipv4": dns.get("ipv4") or [],
        "ipv6": dns.get("ipv6") or [],
        "certificate": {
            "subject": (tls.get("subject") or {}).get("commonName"),
            "issuer": (tls.get("issuer") or {}).get("organizationName"),
            "not_after": not_after,
            "days_left": days_left,
            "tls_version": tls.get("tls_version"),
        } if tls else None,
        "tech": data.get("tech") or [],
    }



def crtsh_subdomains(domain: str, timeout: float = 25.0) -> list[str]:
    """Certificate-transparency sweep for the domain (public crt.sh JSON)."""
    url = CRTSH_CTLOG.format(domain=domain)
    with urllib.request.urlopen(url, timeout=timeout) as response:
        payload = json.load(response)
    found: set[str] = set()
    for entry in payload:
        name_value = entry.get("name_value") or ""
        for name in name_value.splitlines():
            name = name.strip().lower().lstrip("*.")
            if name.endswith(domain) and name != domain:
                found.add(name)
        common_name = (entry.get("common_name") or "").strip().lower().lstrip("*.")
        if common_name.endswith(domain) and common_name != domain:
            found.add(common_name)
    return sorted(found)


def _asset_data(session: Session, asset: models.Asset) -> dict:
    project = session.get(models.Project, asset.project_id) if asset.project_id else None
    groups = (session.query(models.InventoryGroup)
              .join(models.InventoryGroupMember,
                    models.InventoryGroupMember.group_id == models.InventoryGroup.id)
              .filter(models.InventoryGroupMember.asset_id == asset.id,
                      models.InventoryGroupMember.removed_at.is_(None)).all())
    return {"id": asset.id, "type": asset.type, "value": asset.value,
            "source": asset.source, "detail": asset.detail,
            "project": project.slug if project else None,
            "owner": asset.owner,
            "classification_status": asset.classification_status,
            "notes": asset.notes,
            "archived_at": asset.archived_at.isoformat() if asset.archived_at else None,
            "groups": [{"id": g.id, "name": g.name} for g in groups],
            "discovered_at": asset.discovered_at.isoformat(),
            "last_seen_at": asset.last_seen_at.isoformat(),
            "latest": _latest_observation(session, asset)}


@router.get("/assets")
def list_assets(type: str | None = None,
                project: str | None = None,
                group_id: str | None = None,
                owner: str | None = None,
                classification: str | None = None,
                q: str | None = None,
                include_archived: bool = False,
                limit: int = Query(default=100, ge=1, le=500),
                offset: int = Query(default=0, ge=0),
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    """Inventory paging/filtering. `total` counts the filtered set, not the page."""
    query = session.query(models.Asset).filter_by(org_id=org.id)
    if type is not None:
        query = query.filter_by(type=type)
    if not include_archived:
        query = query.filter(models.Asset.archived_at.is_(None))
    if owner is not None:
        query = query.filter(models.Asset.owner == owner)
    if classification is not None:
        query = query.filter(models.Asset.classification_status == classification)
    if project is not None:
        project_row = (session.query(models.Project)
                       .filter_by(org_id=org.id, slug=project).one_or_none())
        if project_row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
        query = query.filter(models.Asset.project_id == project_row.id)
    if group_id is not None:
        query = (query.join(models.InventoryGroupMember,
                            models.InventoryGroupMember.asset_id == models.Asset.id)
                 .filter(models.InventoryGroupMember.group_id == group_id,
                         models.InventoryGroupMember.removed_at.is_(None)))
    if q:
        needle = f"%{q.strip()}%"
        query = query.filter(models.Asset.value.ilike(needle))
    total = query.count()
    rows = (query.order_by(models.Asset.last_seen_at.desc())
            .offset(offset).limit(limit).all())
    return {"data": [_asset_data(session, r) for r in rows], "total": total,
            "limit": limit, "offset": offset}


@router.get("/assets/needs-attention")
def needs_attention(limit: int = Query(default=100, ge=1, le=500),
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    """Computed queue: each row says what is missing and which action fixes it.

    Every reason is a rule that is actually implemented here; "not observed" is
    reported as a coverage gap, never as "does not exist".
    """
    rows = (session.query(models.Asset)
            .filter_by(org_id=org.id)
            .filter(models.Asset.archived_at.is_(None))
            .order_by(models.Asset.last_seen_at.asc()).all())
    items = []
    now = models.utcnow()
    for asset in rows:
        reasons = []
        if not asset.owner:
            reasons.append({"code": "no_owner", "what": "no accountable owner",
                            "action": "assign an owner"})
        if asset.project_id is None:
            reasons.append({"code": "no_project", "what": "not attached to a project",
                            "action": "link it to a project or mark it external"})
        if asset.classification_status in {"unclassified", "pending"}:
            reasons.append({"code": "ownership_unconfirmed",
                            "what": f"classification is {asset.classification_status}",
                            "action": "confirm ownership, mark external, or discard"})
        last = asset.last_seen_at
        if last is not None and last.tzinfo is None:
            last = last.replace(tzinfo=datetime.timezone.utc)
        if last is None or (now - last).days >= 30:
            reasons.append({"code": "stale", "what": "no observation in 30+ days",
                            "action": "re-collect, or record that it is retired"})
        groups = (session.query(models.InventoryGroupMember)
                  .filter_by(asset_id=asset.id, removed_at=None).count())
        deployments = (session.query(models.AssetLink)
                       .filter_by(asset_id=asset.id, entity_type="deployment",
                                  removed_at=None).count())
        if deployments == 0:
            reasons.append({"code": "no_deployment",
                            "what": "no deployment relation recorded",
                            "action": "link it to the deployment that serves it"})
        if not reasons:
            continue
        items.append({"asset": _asset_data(session, asset), "groups": groups,
                      "reasons": reasons,
                      "observation": "observed" if last else "never observed"})
    items.sort(key=lambda row: (-len(row["reasons"]), row["asset"]["value"]))
    return {"data": items[:limit], "total": len(items)}


class AssetPatch(BaseModel):
    owner: str | None = Field(default=None, max_length=255)
    project: str | None = Field(default=None, max_length=128)
    classification_status: str | None = None
    notes: str | None = Field(default=None, max_length=8192)
    detail: str | None = Field(default=None, max_length=4096)
    actor: str | None = Field(default=None, max_length=255)


@router.patch("/assets/{asset_id}")
def patch_asset(asset_id: str, payload: AssetPatch = None,
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    """Ownership and classification only. Scope authorization is a separate
    decision and is never granted by confirming that an asset is ours."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    asset = session.get(models.Asset, asset_id)
    if asset is None or asset.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    changes = []
    if payload.owner is not None:
        asset.owner = payload.owner.strip() or None
        changes.append(f"owner={asset.owner or 'none'}")
    if payload.project is not None:
        if payload.project == "":
            asset.project_id = None
            changes.append("project=none")
        else:
            project_row = (session.query(models.Project)
                           .filter_by(org_id=org.id, slug=payload.project).one_or_none())
            if project_row is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
            asset.project_id = project_row.id
            changes.append(f"project={project_row.slug}")
    if payload.classification_status is not None:
        if payload.classification_status not in models.ASSET_CLASSIFICATION:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"classification_status must be one of "
                                f"{sorted(models.ASSET_CLASSIFICATION)}")
        asset.classification_status = payload.classification_status
        changes.append(f"classification={payload.classification_status}")
    if payload.notes is not None:
        asset.notes = payload.notes
        changes.append("notes")
    if payload.detail is not None:
        asset.detail = payload.detail
        changes.append("detail")
    if not changes:
        return {"data": _asset_data(session, asset), "changed": False}
    _audit_log(session, org.id, payload.actor or "system", "asset.updated",
               "asset", asset.id, ", ".join(changes))
    session.commit()
    return {"data": _asset_data(session, asset), "changed": True}


def _set_archived(asset_id: str, actor: str | None, archived: bool, org, session):
    asset = session.get(models.Asset, asset_id)
    if asset is None or asset.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    if (asset.archived_at is not None) == archived:
        return {"data": _asset_data(session, asset), "changed": False}
    asset.archived_at = models.utcnow() if archived else None
    _audit_log(session, org.id, actor or "system",
               "asset.archived" if archived else "asset.unarchived",
               "asset", asset.id, asset.value)
    session.commit()
    return {"data": _asset_data(session, asset), "changed": True}


@router.post("/assets/{asset_id}/archive")
def archive_asset(asset_id: str, actor: str | None = Query(default=None),
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    """Archive keeps every relation and the whole history; it only leaves the
    default inventory view."""
    return _set_archived(asset_id, actor, True, org, session)


@router.post("/assets/{asset_id}/unarchive")
def unarchive_asset(asset_id: str, actor: str | None = Query(default=None),
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    return _set_archived(asset_id, actor, False, org, session)


class AssetIn(BaseModel):
    type: str
    value: str = Field(min_length=1, max_length=1024)
    detail: str | None = Field(default=None, max_length=4096)
    actor: str | None = None


@router.post("/assets")
def add_asset(payload: AssetIn = None,
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.type not in models.ASSET_TYPES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"type must be one of {sorted(models.ASSET_TYPES)}")
    existing = (session.query(models.Asset)
                .filter_by(org_id=org.id, type=payload.type, value=payload.value)
                .one_or_none())
    if existing is not None:
        existing.last_seen_at = models.utcnow()
        if payload.detail:
            existing.detail = payload.detail
        session.commit()
        return {"data": {"id": existing.id, "type": existing.type,
                         "value": existing.value}, "already_known": True}
    asset = models.Asset(org_id=org.id, type=payload.type, value=payload.value,
                         source="manual", detail=payload.detail,
                         discovered_at=models.utcnow(),
                         last_seen_at=models.utcnow())
    session.add(asset)
    session.flush()
    _audit_log(session, org.id, payload.actor or "system", "asset.added",
               "asset", asset.id, f"{payload.type}:{payload.value}")
    session.commit()
    return {"data": {"id": asset.id, "type": asset.type, "value": asset.value}}


class DiscoveryIn(BaseModel):
    domain: str = Field(min_length=3, max_length=255)
    actor: str | None = None


@router.post("/assets/discover")
def discover(payload: DiscoveryIn = None,
             org: models.Organization = Depends(auth.require_org),
             session: Session = Depends(get_session)):
    """Certificate-transparency sweep; dedupes against the asset table."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    now = models.utcnow()
    created = refreshed = 0
    try:
        found = crtsh_subdomains(payload.domain)
    except Exception as error:  # noqa: BLE001 — catalog outages surface honestly
        raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                            f"crt.sh sweep failed: {type(error).__name__}") from None
    for subdomain in found:
        existing = (session.query(models.Asset)
                    .filter_by(org_id=org.id, type="domain", value=subdomain)
                    .one_or_none())
        if existing is not None:
            existing.last_seen_at = now
            refreshed += 1
            continue
        session.add(models.Asset(org_id=org.id, type="domain", value=subdomain,
                                 source="crtsh", discovered_at=now, last_seen_at=now))
        created += 1
    seed = (session.query(models.Asset)
            .filter_by(org_id=org.id, type="domain", value=payload.domain)
            .one_or_none())
    if seed is not None:
        seed.last_seen_at = now
        seed.source = "seed" if seed.source == "seed" else seed.source
    else:
        session.add(models.Asset(org_id=org.id, type="domain", value=payload.domain,
                                 source="seed", discovered_at=now, last_seen_at=now))
        created += 0  # seed row: inventory point, not a subdomain discovery
    _audit_log(session, org.id, payload.actor or "system", "easm.sweep",
               None, None, f"{payload.domain}: {created} new / {refreshed} refreshed")
    session.commit()
    return {"data": {"domain": payload.domain, "created": created,
                     "refreshed": refreshed, "total_known": created + refreshed + 1}}


class SnapshotIn(BaseModel):
    data: dict
    source: str = Field(default="manual", max_length=64)
    actor: str | None = None


def _snapshot_data(row: models.AssetSnapshot) -> dict:
    import json as _json

    return {"id": row.id, "observed_at": row.observed_at.isoformat(),
            "source": row.source, "data": _json.loads(row.data)}


def _diff(previous: dict, current: dict) -> list[dict]:
    """Flat key diff over the structured observation (nested dicts compare
    via their JSON rendering — honest for this payload shape)."""
    import json as _json

    changes = []
    keys = sorted(set(previous) | set(current))
    for key in keys:
        before, after = previous.get(key), current.get(key)
        if before != after:
            changes.append({"field": key,
                            "before": _json.dumps(before, sort_keys=True)
                            if isinstance(before, (dict, list)) else before,
                            "after": _json.dumps(after, sort_keys=True)
                            if isinstance(after, (dict, list)) else after})
    return changes


@router.post("/assets/{asset_id}/snapshots")
def add_snapshot(asset_id: str, payload: SnapshotIn = None,
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """Record an observation (passive DNS/TLS/tech metadata supplied by a
    passive collector or entered manually). Snapshotting never authorizes
    active testing."""
    import json as _json

    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    asset = session.get(models.Asset, asset_id)
    if asset is None or asset.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    now = models.utcnow()
    row = models.AssetSnapshot(
        org_id=org.id, asset_id=asset.id, observed_at=now,
        source=payload.source, data=_json.dumps(payload.data, sort_keys=True),
        created_at=now)
    session.add(row)
    asset.last_seen_at = now
    session.flush()
    _audit_log(session, org.id, payload.actor or "system", "asset.snapshot",
               "asset", asset.id, f"{payload.source}: {len(payload.data)} fields")
    session.commit()
    return {"data": _snapshot_data(row)}


@router.get("/assets/{asset_id}/snapshots")
def list_snapshots(asset_id: str,
                   org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    asset = session.get(models.Asset, asset_id)
    if asset is None or asset.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    rows = (session.query(models.AssetSnapshot)
            .filter_by(org_id=org.id, asset_id=asset.id)
            .order_by(models.AssetSnapshot.observed_at.desc()).all())
    return {"data": [_snapshot_data(r) for r in rows], "total": len(rows)}


@router.get("/assets/{asset_id}/changes")
def asset_changes(asset_id: str,
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    """Diff of the two most recent snapshots (plus the full change history)."""
    asset = session.get(models.Asset, asset_id)
    if asset is None or asset.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    rows = (session.query(models.AssetSnapshot)
            .filter_by(org_id=org.id, asset_id=asset.id)
            .order_by(models.AssetSnapshot.observed_at).all())
    if len(rows) < 2:
        return {"data": {"asset": asset.value, "snapshots": len(rows),
                         "latest_changes": [], "history": []}}
    import json as _json

    history = []
    latest_changes = []
    for previous, current in zip(rows, rows[1:]):
        changes = _diff(_json.loads(previous.data), _json.loads(current.data))
        entry = {"from": previous.observed_at.isoformat(),
                 "to": current.observed_at.isoformat(), "changes": changes}
        history.append(entry)
    latest_changes = history[-1]["changes"] if history else []
    return {"data": {"asset": asset.value, "snapshots": len(rows),
                     "latest_changes": latest_changes, "history": history}}


def _dns_lookup(host: str) -> dict:
    """Resolve A/AAAA records. DNS resolution is discovery, not authorization."""
    import socket

    addresses = {"ipv4": [], "ipv6": []}
    try:
        for family, _type, _proto, _canon, sockaddr in socket.getaddrinfo(
                host, None, proto=socket.IPPROTO_TCP):
            ip = sockaddr[0]
            bucket = "ipv6" if ":" in ip else "ipv4"
            if ip not in addresses[bucket]:
                addresses[bucket].append(ip)
    except socket.gaierror as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                            f"dns resolution failed: {exc}") from exc
    return addresses


def _tls_probe(host: str, port: int = 443, timeout: float = 6.0) -> dict:
    """Fetch the presented certificate metadata (an active connection)."""
    import socket
    import ssl

    context = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=host) as tls:
                cert = tls.getpeercert() or {}
                return {"issuer": dict(x[0] for x in cert.get("issuer", [])),
                        "subject": dict(x[0] for x in cert.get("subject", [])),
                        "not_before": cert.get("notBefore"),
                        "not_after": cert.get("notAfter"),
                        "tls_version": tls.version(),
                        "cipher": (tls.cipher() or [None])[0]}
    except ssl.SSLCertVerificationError as exc:
        return {"error": f"certificate verification failed: {exc.verify_message}"}
    except (socket.timeout, OSError) as exc:
        return {"error": f"tls probe failed: {exc}"}


class CollectIn(BaseModel):
    tls: bool = False
    port: int = Field(default=443, ge=1, le=65535)
    actor: str = Field(min_length=2, max_length=255)


@router.post("/assets/{asset_id}/collect")
def collect(asset_id: str, payload: CollectIn = None,
            org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    """Passive DNS discovery plus optional active TLS probe.

    DNS stays discovery: it needs `passive_discovery` authorization. Opening
    a TLS connection is active verification and needs `active_verification`
    for that exact domain — discovering a host never authorizes touching it.
    """
    from backend.app import authorization

    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    asset = session.get(models.Asset, asset_id)
    if asset is None or asset.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    if asset.type not in {"domain", "subdomain"}:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "collection supports domain assets only")
    target = [{"type": "domain", "value": asset.value}]
    decision = authorization.authorize(
        session, org.id, payload.actor, "passive_discovery", target,
        tool="dns-collector")
    if decision["decision"] == "deny":
        _audit_log(session, org.id, payload.actor, "easm.collect_denied",
                   "asset", asset.id, decision["reason"][:300])
        session.commit()
        raise HTTPException(status.HTTP_403_FORBIDDEN,
                            f"not authorized: {decision['reason']}")
    observation: dict = {"dns": _dns_lookup(asset.value)}
    if payload.tls:
        tls_decision = authorization.authorize(
            session, org.id, payload.actor, "active_verification", target,
            tool="tls-probe")
        if tls_decision["decision"] == "deny":
            _audit_log(session, org.id, payload.actor, "easm.tls_denied",
                       "asset", asset.id, tls_decision["reason"][:300])
            session.commit()
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                                f"tls probe not authorized: {tls_decision['reason']}")
        observation["tls"] = _tls_probe(asset.value, payload.port)

    now = models.utcnow()
    row = models.AssetSnapshot(
        org_id=org.id, asset_id=asset.id, observed_at=now,
        source="dns-collector" if not payload.tls else "dns+tls-collector",
        data=json.dumps(observation, sort_keys=True), created_at=now)
    session.add(row)
    asset.last_seen_at = now
    session.flush()
    _audit_log(session, org.id, payload.actor, "easm.collected", "asset",
               asset.id, f"{len(observation['dns']['ipv4'])} ipv4"
                         + (" +tls" if payload.tls else ""))
    session.commit()
    return {"data": {"snapshot_id": row.id, "observed_at": now.isoformat(),
                     "observation": observation}}


class ScheduleIn(BaseModel):
    strategy: str = Field(default="cron", max_length=32)
    expression: str = Field(min_length=1, max_length=255)
    enabled: bool = True
    actor: str | None = None


@router.get("/schedules")
def list_schedules(org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    """List EASM scan schedules for the organization."""
    schedules = (session.query(models.ScanSchedule)
                 .filter_by(org_id=org.id)
                 .order_by(models.ScanSchedule.enabled.desc(),
                          models.ScanSchedule.created_at.desc()).all())
    return {"data": [{"id": s.id, "strategy": s.strategy,
                      "expression": s.expression, "enabled": s.enabled,
                      "next_run": s.next_run.isoformat() if s.next_run else None,
                      "created_at": s.created_at.isoformat()} for s in schedules]}


@router.post("/schedules", status_code=status.HTTP_201_CREATED)
def create_schedule(payload: ScheduleIn = None,
                   org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    """Create an EASM scan schedule."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.strategy not in {"cron", "interval"}:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "strategy must be 'cron' or 'interval'")
    schedule = models.ScanSchedule(
        org_id=org.id, strategy=payload.strategy,
        expression=payload.expression, enabled=payload.enabled,
        actor=payload.actor or "system", created_at=models.utcnow())
    session.add(schedule)
    session.flush()
    _audit_log(session, org.id, payload.actor or "system", "easm.schedule.added",
               "schedule", schedule.id, payload.expression)
    session.commit()
    return {"data": {"id": schedule.id, "strategy": schedule.strategy,
                      "expression": schedule.expression, "enabled": schedule.enabled}}


@router.patch("/schedules/{schedule_id}", status_code=status.HTTP_200_OK)
def update_schedule(schedule_id: str, payload: ScheduleIn = None,
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    """Update an EASM scan schedule."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    schedule = session.get(models.ScanSchedule, schedule_id)
    if schedule is None or schedule.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    if payload.strategy:
        schedule.strategy = payload.strategy
    if payload.expression:
        schedule.expression = payload.expression
    if payload.enabled is not None:
        schedule.enabled = payload.enabled
    session.commit()
    return {"data": {"id": schedule.id, "strategy": schedule.strategy,
                      "expression": schedule.expression, "enabled": schedule.enabled}}


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_schedule(schedule_id: str,
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    """Delete an EASM scan schedule."""
    schedule = session.get(models.ScanSchedule, schedule_id)
    if schedule is None or schedule.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "schedule not found")
    session.delete(schedule)
    session.commit()
    return None


class SweepTrigger(BaseModel):
    actor: str | None = None
    domain: str | None = None
    asset_id: str | None = None


@router.post("/schedules/trigger")
def trigger_schedule(payload: SweepTrigger = None,
                     org: models.Organization = Depends(auth.require_org),
                     session: Session = Depends(get_session)):
    """Trigger a manual EASM sweep for testing."""
    from backend.app import authorization

    targets = []
    if payload.domain:
        targets.append({"type": "domain", "value": payload.domain})
    elif payload.asset_id:
        asset = session.get(models.Asset, payload.asset_id)
        if asset is None or asset.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
        targets.append({"type": "domain", "value": asset.value})

    if not targets:
        assets = session.query(models.Asset).filter_by(org_id=org.id).all()
        targets = [{"type": a.type, "value": a.value} for a in assets]

    for target in targets:
        decision = authorization.authorize(
            session, org.id, payload.actor or "system",
            "passive_discovery" if target["type"] == "domain" else "asset.collection",
            target, tool="easm-scheduler")
        if decision["decision"] == "deny":
            _audit_log(session, org.id, payload.actor or "system",
                       "easm.trigger_denied", "asset", None, decision["reason"][:300])
            raise HTTPException(status.HTTP_403_FORBIDDEN,
                               f"not authorized: {decision['reason']}")

    result = {"sweeps": [], "total": len(targets), "denied": 0}
    for target in targets:
        domain = target["value"]
        try:
            found = crtsh_subdomains(domain)
            result["sweeps"].append({"domain": domain, "subdomains_found": len(found)})
        except Exception as e:
            result["sweeps"].append({"domain": domain, "error": str(e)})
            result["denied"] += 1

    _audit_log(session, org.id, payload.actor or "system",
               "easm.sweep.triggered", "asset", None,
               f"{len(targets)} targets, {result['denied']} denied")
    session.commit()
    return {"data": result}

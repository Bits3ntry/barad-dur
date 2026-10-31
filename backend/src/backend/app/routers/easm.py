"""B4 endpoints: externally observable assets, crt.sh subdomain sweep."""
import datetime
import json
import urllib.request

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1", tags=["easm"])

CRTSH_CTLOG = "https://crt.sh/?q=%25.{domain}&output=json"


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


@router.get("/assets")
def list_assets(type: str | None = None,
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    query = session.query(models.Asset).filter_by(org_id=org.id)
    if type is not None:
        query = query.filter_by(type=type)
    rows = query.order_by(models.Asset.last_seen_at.desc()).all()
    return {"data": [{"id": r.id, "type": r.type, "value": r.value,
                      "source": r.source, "detail": r.detail,
                      "discovered_at": r.discovered_at.isoformat(),
                      "last_seen_at": r.last_seen_at.isoformat()} for r in rows],
            "total": len(rows)}


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

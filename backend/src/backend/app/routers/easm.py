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

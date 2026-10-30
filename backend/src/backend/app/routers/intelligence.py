"""B3: intelligence — KEV/EPSS feeds, VEX statements, advisory reconcile."""
import csv
import datetime
import io
import json
import urllib.request

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models
from backend.app.db import get_session
from backend.app.vulns import vulnerability_fingerprint
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1", tags=["intelligence"])

KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/main/kev.json"
EPSS_URL = "https://api.first.org/data/v1/epss"

VEX_STATUSES = {"not_affected", "affected", "fixed", "under_investigation"}


def fetch_kev(timeout: float = 15.0) -> list[dict]:
    """Pull the CISA KEV catalog (direct stderr | failure raises)."""
    with urllib.request.urlopen(KEV_URL, timeout=timeout) as response:
        payload = json.load(response)
    rows = []
    for entry in payload.get("vulnerabilities", []):
        rows.append({
            "cve_id": entry.get("cveID"),
            "title": entry.get("title"),
            "date_added": entry.get("dateAdded"),
            "due_date": entry.get("dueDate"),
            "source": entry.get("source"),
        })
    return [row for row in rows if row["cve_id"]]


def fetch_epss(timeout: float = 15.0) -> list[dict]:
    """Pull EPSS scores from the FIRST public API (no key supported)."""
    url = f"{EPSS_URL}?limit=500"
    with urllib.request.urlopen(url, timeout=timeout) as response:
        payload = json.load(response)
    rows = []
    for entry in payload.get("data", []):
        rows.append({
            "cve_id": entry.get("cve"),
            "epss": f"{float(entry.get('epss', 0)):.6f}",
            "percentile": f"{float(entry.get('percentile', 0)):.6f}",
        })
    return rows


def _reconcile_fingerprints(session, org, project=None):
    """Re-key vulnerability findings to the CVE when one is (now) known.
    Grouped pass: findings that would collide on the canonical fingerprint
    collapse onto the oldest row (its history absorbs the rest). Idempotent."""
    candidates = (session.query(models.Finding)
                  .filter_by(org_id=org.id, kind="vulnerability")).all()
    if project is not None:
        candidates = [row for row in candidates if row.project_id == project.id]

    grouped: dict[tuple, list] = {}
    for finding in candidates:
        if finding.vulnerability_id is None or finding.component_id is None:
            continue
        advisory = session.get(models.Vulnerability, finding.vulnerability_id)
        component = session.get(models.Component, finding.component_id)
        if advisory is None or component is None:
            continue
        canonical_key = advisory.cve_id or advisory.source_id
        canonical = vulnerability_fingerprint(
            org.id, finding.project_id, component.identity_key, canonical_key)
        if canonical == finding.fingerprint:
            continue
        grouped.setdefault((finding.project_id, canonical, canonical_key), []) \
               .append((finding, advisory))

    changed = 0
    for (_project_id, canonical, canonical_key), members in grouped.items():
        members.sort(key=lambda pair: pair[0].first_seen_at or models.utcnow())
        keeper, keeper_advisory = members[0]
        keeper.fingerprint = canonical
        keeper.vulnerability_id = keeper_advisory.id
        changed += 1
        for extra, _advisory in members[1:]:
            keeper.last_seen_at = max(keeper.last_seen_at, extra.last_seen_at)
            keeper.last_seen_version_id = extra.last_seen_version_id or keeper.last_seen_version_id
            session.delete(extra)
            changed += 1
    return changed


@router.get("/intel/kev/{cve_id}")
def kev_for(cve_id: str, org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    row = session.get(models.KevEntry, cve_id)
    if row is None:
        return {"data": None, "known_exploited": False}
    return {"data": {"cve_id": row.cve_id, "title": row.title,
                     "date_added": row.date_added, "due_date": row.due_date},
            "known_exploited": True}


@router.get("/intel/epss/{cve_id}")
def epss_for(cve_id: str, org: models.Organization = Depends(auth.require_org),
             session: Session = Depends(get_session)):
    row = session.get(models.EpssScore, cve_id)
    if row is None:
        return {"data": None, "epss": None}
    return {"data": {"cve_id": row.cve_id, "epss": row.epss,
                     "percentile": row.percentile}}


class SyncResult(BaseModel):
    kev_fetched: int = 0
    epss_fetched: int = 0


@router.post("/intel/sync")
def sync_feeds(org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """Refresh the local KEV/EPSS tables from the public catalogs."""
    now = models.utcnow()
    kev_n = epss_n = 0
    try:
        rows = fetch_kev()
    except Exception as error:  # noqa: BLE001 — report catalog outages honestly
        raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                            f"KEV sync failed: {type(error).__name__}") from None
    for row in rows:
        session.merge(models.KevEntry(**row, fetched_at=now))
        kev_n += 1
    try:
        rows = fetch_epss()
    except Exception as error:  # noqa: BLE001
        raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                            f"EPSS sync failed: {type(error).__name__}") from None
    for row in rows:
        session.merge(models.EpssScore(**row, fetched_at=now))
        epss_n += 1
    _audit_log(session, org.id, "platform", "intel.synced", None, None,
               f"kev={kev_n} epss={epss_n}")
    session.commit()
    return {"data": {"kev_fetched": kev_n, "epss_fetched": epss_n}}


class VexIn(BaseModel):
    finding_id: str
    status: str
    statement: str = Field(min_length=4, max_length=8192)
    author: str | None = Field(default=None, max_length=255)


class VexOut(BaseModel):
    id: str
    status: str


@router.get("/vex")
def list_vex(org: models.Organization = Depends(auth.require_org),
             session: Session = Depends(get_session)):
    rows = (session.query(models.VexStatement)
            .filter_by(org_id=org.id)
            .order_by(models.VexStatement.created_at.desc()).all())
    return {"data": [{"id": r.id, "finding_id": r.finding_id, "status": r.status,
                      "statement": r.statement, "author": r.author} for r in rows],
            "total": len(rows)}


@router.post("/vex")
def add_vex(payload: VexIn = None,
            org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.status not in VEX_STATUSES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"status must be one of {sorted(VEX_STATUSES)}")
    finding = session.get(models.Finding, payload.finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    statement = models.VexStatement(
        org_id=org.id, finding_id=finding.id, status=payload.status,
        statement=payload.statement, author=payload.author,
        created_at=models.utcnow(), updated_at=models.utcnow())
    session.add(statement)
    session.flush()
    _audit_log(session, org.id, payload.author or "system", "vex.added",
               "vex_statement", statement.id, f"{finding.id[:12]} -> {payload.status}")
    session.commit()
    return {"data": {"id": statement.id, "status": statement.status}}


@router.post("/intelligence/reconcile")
def reconcile(org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    """Collapse advisory-split findings onto CVE-anchored fingerprints."""
    changed = _reconcile_fingerprints(session, org)
    session.commit()
    return {"data": {"reconciled": changed}}

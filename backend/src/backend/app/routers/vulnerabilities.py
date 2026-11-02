"""Vulnerabilities: the CVEs that actually affect this organization's inventory.

This is an aggregate over visible findings, never the global advisory catalog.
A CVE with no finding behind it is not "affecting the organization", and a
finding without a CVE (a manual IDOR) never appears here.

Honest fields: `affected_versions`/`fixed_versions` are reported as unknown
because v0 stores no advisory version ranges; enrichment says `known: false`
with the reason instead of showing a blank that reads like zero.
"""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models, severity as severity_vocab
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1", tags=["vulnerabilities"])

OPEN_STATUSES = {"open", "acknowledged"}
CLOSED_STATUSES = {"resolved", "false_positive", "accepted_risk", "suppressed"}
PRIORITY_ORDER = ["P0", "P1", "P2", "P3", "P4", None]


def _worst_severity(values) -> str:
    best = "UNKNOWN"
    for value in values:
        if severity_vocab.rank(value) < severity_vocab.rank(best):
            best = severity_vocab.canonical(value)
    return best


def _worst_priority(values) -> str | None:
    known = [value for value in values if value in PRIORITY_ORDER]
    if not known:
        return None
    return min(known, key=PRIORITY_ORDER.index)


def _asset_ids_for_project(session: Session, org_id: str, project_id: str) -> set[str]:
    """Assets attached to a project, directly or through a typed link."""
    direct = {row.id for row in session.query(models.Asset)
              .filter_by(org_id=org_id, project_id=project_id).all()}
    linked = {row.asset_id for row in session.query(models.AssetLink)
              .filter_by(org_id=org_id, entity_type="project", entity_id=project_id)
              .filter(models.AssetLink.removed_at.is_(None)).all()}
    return direct | linked


def _enrichment(session: Session, cve_id: str) -> dict:
    kev = session.get(models.KevEntry, cve_id)
    epss = session.get(models.EpssScore, cve_id)
    return {
        "kev": {"known": kev is not None, "listed": kev is not None,
                "date_added": kev.date_added if kev else None,
                "due_date": kev.due_date if kev else None,
                "source": kev.source if kev else None,
                "fetched_at": kev.fetched_at.isoformat() if kev else None},
        "epss": {"known": epss is not None,
                 "score": epss.epss if epss else None,
                 "percentile": epss.percentile if epss else None,
                 "source": "first.org/epss" if epss else None,
                 "fetched_at": epss.fetched_at.isoformat() if epss else None},
        # No exploit feed is wired in v0; saying so is the honest answer.
        "exploit": {"known": False, "available": None,
                    "reason": "no exploit feed connected"},
    }


def _group_rows(session: Session, org: models.Organization,
                include_suppressed: bool) -> list[dict]:
    query = (session.query(models.Finding)
             .filter(models.Finding.org_id == org.id,
                     models.Finding.vulnerability_id.is_not(None)))
    if not include_suppressed:
        query = query.filter(models.Finding.status != "suppressed")
    findings = query.all()
    by_cve: dict[str, dict] = {}
    for finding in findings:
        vulnerability = session.get(models.Vulnerability, finding.vulnerability_id)
        if vulnerability is None:
            continue
        cve_id = vulnerability.cve_id or vulnerability.source_id
        group = by_cve.setdefault(cve_id, {"cve_id": cve_id,
                                           "source_ids": set(),
                                           "titles": set(),
                                           "findings": []})
        group["source_ids"].add(vulnerability.source_id)
        if vulnerability.title:
            group["titles"].add(vulnerability.title)
        group["findings"].append(finding)

    rows = []
    for cve_id, group in by_cve.items():
        findings = group["findings"]
        asset_ids: set[str] = set()
        projects: list[dict] = []
        for finding in findings:
            asset_ids |= _asset_ids_for_project(session, org.id, finding.project_id)
            project = session.get(models.Project, finding.project_id)
            if project is not None and project.slug not in {p["slug"] for p in projects}:
                projects.append({"slug": project.slug, "name": project.name})
        assets = [session.get(models.Asset, asset_id) for asset_id in asset_ids]
        assets = [asset for asset in assets if asset is not None]
        details = [finding for finding in findings]
        rows.append({
            "cve_id": cve_id,
            "source_ids": sorted(group["source_ids"]),
            "title": next(iter(group["titles"]), None),
            "severity": _worst_severity([row.severity for row in details]),
            "priority": _worst_priority([row.priority for row in details]),
            "findings": len(findings),
            "open_findings": sum(1 for row in findings if row.status in OPEN_STATUSES),
            "statuses": sorted({row.status for row in findings}),
            "projects": projects,
            "assets": {
                "count": len(assets),
                "sample": [{"id": asset.id, "type": asset.type,
                            "value": asset.value} for asset in assets[:5]],
                "coverage": ("complete" if assets else
                             "no asset is linked to the affected projects"),
            },
            "affected_versions": [],
            "fixed_versions": [],
            "versions_known": False,
            "versions_reason": ("v0 stores no advisory version ranges; "
                                "affected/fixed versions are unknown, not empty"),
            "enrichment": _enrichment(session, cve_id),
        })
    rows.sort(key=lambda row: (severity_vocab.rank(row["severity"]),
                               -row["findings"], row["cve_id"]))
    return rows


@router.get("/vulnerabilities")
def list_vulnerabilities(project: str | None = Query(default=None),
                         severity: str | None = Query(default=None),
                         kev_only: bool = Query(default=False),
                         q: str | None = Query(default=None),
                         include_suppressed: bool = Query(default=False),
                         limit: int = Query(default=100, ge=1, le=500),
                         offset: int = Query(default=0, ge=0),
                         org: models.Organization = Depends(auth.require_org),
                         session: Session = Depends(get_session)):
    """CVEs grouped over the visible findings of this organization."""
    rows = _group_rows(session, org, include_suppressed)
    if project:
        project_row = (session.query(models.Project)
                       .filter_by(org_id=org.id, slug=project).one_or_none())
        if project_row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
        rows = [row for row in rows
                if project in {p["slug"] for p in row["projects"]}]
    if severity:
        wanted = severity_vocab.canonical(severity)
        rows = [row for row in rows if row["severity"] == wanted]
    if kev_only:
        rows = [row for row in rows if row["enrichment"]["kev"]["listed"]]
    if q:
        needle = q.strip().upper()
        rows = [row for row in rows if needle in row["cve_id"].upper()]
    total = len(rows)
    page = rows[offset:offset + limit]
    return {"data": page, "total": total, "limit": limit, "offset": offset,
            "coverage": {
                "advisory_catalog": "global catalog is not exposed here",
                "findings_with_cve": sum(row["findings"] for row in rows),
                "versions_known": False,
                "exploit_feed": "not connected",
            }}


@router.get("/vulnerabilities/meta/summary")
def summary(org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    """Counters for the dashboard card: distinct CVEs and the KEV subset."""
    rows = _group_rows(session, org, include_suppressed=False)
    return {"data": {"cves": len(rows),
                     "kev": sum(1 for row in rows if row["enrichment"]["kev"]["listed"]),
                     "findings": sum(row["findings"] for row in rows),
                     "unknown_enrichment": sum(
                         1 for row in rows
                         if not row["enrichment"]["kev"]["known"]
                         and not row["enrichment"]["epss"]["known"])}}


@router.get("/vulnerabilities/{cve_id}")
def get_vulnerability(cve_id: str,
                      include_suppressed: bool = Query(default=False),
                      org: models.Organization = Depends(auth.require_org),
                      session: Session = Depends(get_session)):
    """The concrete findings behind one CVE; 404 when it affects nothing here."""
    rows = _group_rows(session, org, include_suppressed)
    row = next((item for item in rows if item["cve_id"].upper() == cve_id.upper()), None)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "no finding in this organization references that advisory")
    query = (session.query(models.Finding)
             .filter(models.Finding.org_id == org.id,
                     models.Finding.vulnerability_id.is_not(None)))
    if not include_suppressed:
        query = query.filter(models.Finding.status != "suppressed")
    findings = []
    for finding in query.all():
        vulnerability = session.get(models.Vulnerability, finding.vulnerability_id)
        if vulnerability is None:
            continue
        if (vulnerability.cve_id or vulnerability.source_id).upper() != cve_id.upper():
            continue
        project = session.get(models.Project, finding.project_id)
        component = (session.get(models.Component, finding.component_id)
                     if finding.component_id else None)
        version = (session.get(models.ProjectVersion, finding.last_seen_version_id)
                   if finding.last_seen_version_id else None)
        findings.append({
            "id": finding.id, "status": finding.status,
            "severity": finding.severity, "priority": finding.priority,
            "assignee": finding.assignee,
            "project": project.slug if project else None,
            "version": version.version if version else None,
            "component": (component.purl or component.identity_key) if component else None,
            "title": finding.title,
            "first_seen_at": finding.first_seen_at.isoformat(),
            "last_seen_at": finding.last_seen_at.isoformat(),
        })
    findings.sort(key=lambda item: (severity_vocab.rank(item["severity"]),
                                    item["project"] or "", item["id"]))
    return {"data": {**row, "findings_detail": findings}}


class BulkPreviewIn(BaseModel):
    finding_ids: list[str] = Field(min_length=1, max_length=1000)
    status: str


@router.post("/vulnerabilities/{cve_id}/bulk-preview")
def bulk_preview(cve_id: str, payload: BulkPreviewIn = None,
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """Preview a grouped status change without writing anything.

    The preview and the future apply path share this selection logic, so the
    numbers a reader approves are the numbers that would change. Suppressed
    findings are skipped: their disposition belongs to the suppression rule.
    """
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    from backend.app.routers.findings import ALLOWED_STATUSES
    if payload.status not in ALLOWED_STATUSES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"status must be one of {sorted(ALLOWED_STATUSES)}")
    will_change, already, skipped = [], [], []
    for finding_id in payload.finding_ids:
        finding = session.get(models.Finding, finding_id)
        if finding is None or finding.org_id != org.id:
            skipped.append({"finding_id": finding_id, "reason": "not found in this organization"})
            continue
        vulnerability = (session.get(models.Vulnerability, finding.vulnerability_id)
                         if finding.vulnerability_id else None)
        if vulnerability is None or (vulnerability.cve_id or "").upper() != cve_id.upper():
            skipped.append({"finding_id": finding_id,
                            "reason": "finding does not belong to this CVE"})
            continue
        if finding.status == "suppressed":
            skipped.append({"finding_id": finding_id,
                            "reason": "suppressed findings change with their rule"})
            continue
        if finding.status == payload.status:
            already.append(finding_id)
            continue
        will_change.append({"id": finding.id, "from": finding.status,
                            "to": payload.status, "project": finding.project_id})
    return {"data": {"cve_id": cve_id, "target_status": payload.status,
                     "would_change": len(will_change), "unchanged": len(already),
                     "skipped": skipped, "findings": will_change,
                     "requires": "write role (viewer cannot change status)"}}


@router.post("/vulnerabilities/{cve_id}/bulk-status")
def bulk_status(cve_id: str, payload: BulkPreviewIn = None,
                actor: str = Query(default="api"),
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    """Apply the previewed change to exactly the findings it listed."""
    from backend.app.routers.findings import ALLOWED_STATUSES
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.status not in ALLOWED_STATUSES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"status must be one of {sorted(ALLOWED_STATUSES)}")
    changed, skipped = [], []
    for finding_id in payload.finding_ids:
        finding = session.get(models.Finding, finding_id)
        if finding is None or finding.org_id != org.id:
            skipped.append(finding_id)
            continue
        vulnerability = (session.get(models.Vulnerability, finding.vulnerability_id)
                         if finding.vulnerability_id else None)
        if vulnerability is None or (vulnerability.cve_id or "").upper() != cve_id.upper():
            skipped.append(finding_id)
            continue
        if finding.status == "suppressed":
            skipped.append(finding_id)
            continue
        if finding.status == payload.status:
            continue
        finding.status = payload.status
        finding.status_changed_at = models.utcnow()
        finding.updated_at = finding.status_changed_at
        _audit_log(session, org.id, actor, "finding.status_changed", "finding",
                   finding.id, f"{cve_id}: {finding.status}")
        changed.append(finding.id)
    session.commit()
    return {"data": {"cve_id": cve_id, "status": payload.status,
                     "changed": len(changed), "finding_ids": changed,
                     "skipped": skipped}}

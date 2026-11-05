"""Vulnerabilities: one row per PROBLEM, with every finding behind it.

The console needs two readings of the same data, and conflating them is what
makes security panels unusable:

* **Findings** — occurrences. The same SQL injection in two endpoints is two
  findings, because the fix is two changes in two files.
* **Vulnerabilities** — the problem itself. One row, with how many places it
  appears in, who is exposed, whether an exploit exists and what the fix is.
  This is the row you triage, ticket and close.

Grouping is by *signature*, not by row: a rule id for SAST and configuration
findings, a CVE id for dependency advisories. A secret groups by rule too — five
leaked keys in five files are one policy problem with five places to rotate.

Exposure is reported as inputs, never as a verdict without its evidence: CVSS
and severity come from the artifact, KEV/EPSS from the enrichment tables when a
feed has been imported, reachability from whether the affected project has
assets attached. When something is unknown the API says `known: false` with the
reason, because a blank reads like zero.
"""
import hashlib
import json

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models, projects as projects_ref, severity as severity_vocab
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1", tags=["vulnerabilities"])

OPEN_STATUSES = {"open", "acknowledged"}
CLOSED_STATUSES = {"resolved", "false_positive", "accepted_risk", "suppressed"}
PRIORITY_ORDER = ["P0", "P1", "P2", "P3", "P4", None]

VECTOR_LABELS = {
    "dependency-cve": "Dependency CVE",
    "credential": "Exposed credential",
    "sast": "Code weakness",
    "misconfig": "Insecure configuration",
}

# A secret is closed by rotating it, not by committing: this drives what the
# console tells the operator to do.
REMEDIATION = {
    "dependency-cve": "Upgrade the package",
    "credential": "Rotate the credential",
    "sast": "Change the code",
    "misconfig": "Change the configuration",
}


def _worst_severity(values) -> str:
    best = "UNKNOWN"
    for value in values:
        if value and severity_vocab.rank(value) < severity_vocab.rank(best):
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


def _detail_of(finding: models.Finding) -> dict:
    """The per-finding evidence blob written by the ingest, when it is JSON."""
    if not finding.detail or not finding.detail.strip().startswith("{"):
        return {}
    try:
        parsed = json.loads(finding.detail)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _enrichment(session: Session, cve_id: str | None) -> dict:
    if not cve_id:
        return {"kev": {"known": False, "listed": False, "reason": "no advisory id"},
                "epss": {"known": False, "score": None, "reason": "no advisory id"},
                "exploit": {"known": False, "available": None,
                            "reason": "not a CVE: no exploit feed applies"}}
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
        "exploit": {"known": kev is not None,
                    "available": True if kev is not None else None,
                    "reason": ("listed in CISA KEV" if kev is not None
                               else "no exploit feed connected")},
    }


def _signature_of(session: Session, finding: models.Finding) -> tuple[str, str | None, dict]:
    """(signature, cve_id, advisory) — what makes two findings the same problem."""
    if finding.vulnerability_id:
        advisory = session.get(models.Vulnerability, finding.vulnerability_id)
        if advisory is not None:
            cve_id = advisory.cve_id or advisory.source_id
            return cve_id, cve_id, {"title": advisory.title,
                                    "cvss_vector": advisory.cvss_vector,
                                    "url": advisory.url}
    return (finding.rule_id or finding.title or "unnamed"), None, {}


def _risk_of(severity: str, enrichment: dict, reachable: bool) -> dict:
    """One verdict with its reasons, never a number without an explanation.

    Deliberately simple and auditable: known-exploited beats everything, then
    severity, then whether anything outside can actually reach it.
    """
    reasons: list[str] = []
    if enrichment["kev"]["listed"]:
        reasons.append("known exploited (KEV)")
    if severity in {"CRITICAL", "HIGH"}:
        reasons.append(f"severity {severity}")
    if reachable:
        reasons.append("reachable from an inventoried asset")
    else:
        reasons.append("no asset is attached to the affected project")
    if enrichment["kev"]["listed"] or severity == "CRITICAL":
        label = "critical"
    elif severity == "HIGH" and reachable:
        label = "high"
    elif severity in {"HIGH", "MEDIUM"}:
        label = "medium"
    else:
        label = "low"
    return {"label": label, "reasons": reasons}


def _groups(session: Session, org: models.Organization,
            include_suppressed: bool) -> list[dict]:
    query = session.query(models.Finding).filter(models.Finding.org_id == org.id)
    if not include_suppressed:
        query = query.filter(models.Finding.status != "suppressed")
    findings = query.all()

    assets_by_project: dict[str, set[str]] = {}
    projects_cache: dict[str, models.Project] = {}
    components_cache: dict[str, models.Component] = {}
    buckets: dict[str, dict] = {}

    for finding in findings:
        signature, cve_id, advisory = _signature_of(session, finding)
        vector = finding.vector or ("dependency-cve" if cve_id else "sast")
        component = None
        if finding.component_id:
            component = components_cache.get(finding.component_id)
            if component is None:
                component = session.get(models.Component, finding.component_id)
                if component is not None:
                    components_cache[component.id] = component
        # A CVE against two different packages is two problems, not one.
        component_key = ""
        if cve_id and component is not None:
            component_key = component.name or component.purl or component.identity_key
        key = f"{vector}|{signature}|{component_key}"
        bucket = buckets.get(key)
        if bucket is None:
            bucket = buckets[key] = {
                "key": key, "vector": vector, "signature": signature,
                "cve_id": cve_id, "advisory": advisory, "findings": [],
                "components": {}, "projects": {}, "versions": {}, "titles": set(),
            }
        if finding.title:
            bucket["titles"].add(finding.title)
        bucket["findings"].append(finding)
        if component is not None:
            bucket["components"][component.id] = {
                "id": component.id, "name": component.name,
                "version": component.version, "purl": component.purl,
                "license": component.license,
                "manifest_path": component.manifest_path}
        if finding.project_id not in assets_by_project:
            assets_by_project[finding.project_id] = _asset_ids_for_project(
                session, org.id, finding.project_id)
        project = projects_cache.get(finding.project_id)
        if project is None:
            project = session.get(models.Project, finding.project_id)
            if project is not None:
                projects_cache[project.id] = project
        if project is not None:
            bucket["projects"][project.id] = {
                "id": project.id, "slug": project.slug, "name": project.name,
                "assets": len(assets_by_project[finding.project_id])}
            version = (session.get(models.ProjectVersion, finding.last_seen_version_id)
                       if finding.last_seen_version_id else None)
            if version is not None:
                bucket["versions"].setdefault(
                    (project.slug, version.component_id, version.version), []).append(finding)

    rows = []
    for bucket in buckets.values():
        findings = bucket["findings"]
        vector = bucket["vector"]
        asset_ids: set[str] = set()
        for finding in findings:
            asset_ids |= assets_by_project.get(finding.project_id, set())
        assets = [session.get(models.Asset, asset_id) for asset_id in sorted(asset_ids)]
        assets = [asset for asset in assets if asset is not None]

        details = [_detail_of(finding) for finding in findings]
        cvss_scores = [d.get("cvss_score") for d in details
                       if isinstance(d.get("cvss_score"), (int, float))]
        fixed = sorted({d["fixed_version"] for d in details
                        if isinstance(d.get("fixed_version"), str)})
        severity = _worst_severity([finding.severity for finding in findings])
        enrichment = _enrichment(session, bucket["cve_id"])
        reachable = bool(assets)
        first_seen = min((f.first_seen_at for f in findings if f.first_seen_at), default=None)
        last_seen = max((f.last_seen_at for f in findings if f.last_seen_at), default=None)
        versions = [
            {"project": project_slug, "component_id": component_id,
             "version": version_label, "findings": len(version_findings),
             "open_findings": sum(1 for f in version_findings if f.status in OPEN_STATUSES),
             "severity": _worst_severity([f.severity for f in version_findings])}
            for (project_slug, component_id, version_label),
            version_findings in bucket["versions"].items()
        ]
        versions.sort(key=lambda row: (row["project"], row["version"]))

        locations = []
        for finding in sorted(findings, key=lambda f: (severity_vocab.rank(f.severity),
                                                       f.path or "")):
            project = projects_cache.get(finding.project_id)
            component = (components_cache.get(finding.component_id)
                         if finding.component_id else None)
            locations.append({
                "finding_id": finding.id,
                "project": project.slug if project else None,
                "path": finding.path, "line": finding.line,
                "component": component.name if component else None,
                "component_version": component.version if component else None,
                "tool": finding.tool, "status": finding.status,
                "severity": finding.severity, "assignee": finding.assignee,
                "first_seen_at": (finding.first_seen_at.isoformat()
                                  if finding.first_seen_at else None),
                "last_seen_at": (finding.last_seen_at.isoformat()
                                 if finding.last_seen_at else None),
            })

        rows.append({
            "id": hashlib.sha1(bucket["key"].encode("utf-8")).hexdigest()[:16],
            "key": bucket["key"],
            "vector": vector,
            "vector_label": VECTOR_LABELS.get(vector, vector),
            "kind": findings[0].kind,
            "signature": bucket["signature"],
            "cve_id": bucket["cve_id"],
            "title": (bucket["advisory"].get("title")
                      or (sorted(bucket["titles"])[0] if bucket["titles"]
                          else bucket["signature"])),
            "severity": severity,
            "priority": _worst_priority([finding.priority for finding in findings]),
            "cvss": {"known": bool(cvss_scores),
                     "score": max(cvss_scores) if cvss_scores else None,
                     "vector": bucket["advisory"].get("cvss_vector")},
            "fix": {"available": bool(fixed), "versions": fixed,
                    "reason": None if fixed else "no fixed version stated by the scanner"},
            "remediation": REMEDIATION.get(vector),
            "enrichment": enrichment,
            "exposure": _risk_of(severity, enrichment, reachable),
            "reachable": reachable,
            "findings": len(findings),
            "open_findings": sum(1 for f in findings if f.status in OPEN_STATUSES),
            "statuses": sorted({f.status for f in findings}),
            "components": sorted(bucket["components"].values(),
                                 key=lambda row: (row["name"] or "", row["version"] or "")),
            "projects": sorted(bucket["projects"].values(), key=lambda row: row["slug"]),
            "versions": versions,
            "assets": {"count": len(assets),
                       "sample": [{"id": asset.id, "type": asset.type,
                                   "value": asset.value} for asset in assets[:8]],
                       "coverage": ("complete" if assets else
                                    "no asset is attached to the affected projects")},
            "locations": locations,
            "first_seen_at": first_seen.isoformat() if first_seen else None,
            "last_seen_at": last_seen.isoformat() if last_seen else None,
            "assignee": next((f.assignee for f in findings if f.assignee), None),
            "url": bucket["advisory"].get("url"),
        })

    rows.sort(key=lambda row: (severity_vocab.rank(row["severity"]),
                               -int(row["enrichment"]["kev"]["listed"]),
                               -row["findings"], row["signature"]))
    return rows


def _match(rows: list[dict], ref: str) -> dict | None:
    lowered = ref.lower()
    return next((item for item in rows
                 if item["id"] == ref
                 or (item["cve_id"] or "").lower() == lowered
                 or item["signature"].lower() == lowered), None)


@router.get("/vulnerabilities")
def list_vulnerabilities(project: str | None = Query(default=None),
                         vector: str | None = Query(default=None),
                         severity: str | None = Query(default=None),
                         status_filter: str | None = Query(default=None, alias="status"),
                         kev_only: bool = Query(default=False),
                         q: str | None = Query(default=None),
                         include_suppressed: bool = Query(default=False),
                         limit: int = Query(default=200, ge=1, le=1000),
                         offset: int = Query(default=0, ge=0),
                         org: models.Organization = Depends(auth.require_org),
                         session: Session = Depends(get_session)):
    """Every problem once, with the occurrences behind it."""
    rows = _groups(session, org, include_suppressed)
    if project:
        project_row = projects_ref.by_ref(session, org.id, project)
        if project_row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
        rows = [row for row in rows
                if project_row.id in {p["id"] for p in row["projects"]}]
    if vector:
        rows = [row for row in rows if row["vector"] == vector]
    if severity:
        wanted = severity_vocab.canonical(severity)
        rows = [row for row in rows if row["severity"] == wanted]
    if status_filter:
        rows = [row for row in rows if status_filter in row["statuses"]]
    if kev_only:
        rows = [row for row in rows if row["enrichment"]["kev"]["listed"]]
    if q:
        needle = q.strip().lower()
        rows = [row for row in rows
                if needle in (row["signature"] or "").lower()
                or needle in (row["title"] or "").lower()
                or needle in (row["vector_label"] or "").lower()]

    by_vector: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    by_risk: dict[str, int] = {}
    for row in rows:
        by_vector[row["vector"]] = by_vector.get(row["vector"], 0) + 1
        by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + 1
        by_risk[row["exposure"]["label"]] = by_risk.get(row["exposure"]["label"], 0) + 1
    total = len(rows)
    return {
        "data": rows[offset:offset + limit],
        "total": total,
        "limit": limit,
        "offset": offset,
        "counters": {
            "vulnerabilities": total,
            "findings": sum(row["findings"] for row in rows),
            "by_vector": by_vector,
            "by_severity": by_severity,
            "by_risk": by_risk,
            "fixable": sum(1 for row in rows if row["fix"]["available"]),
            "kev": sum(1 for row in rows if row["enrichment"]["kev"]["listed"]),
            "reachable": sum(1 for row in rows if row["reachable"]),
        },
        "coverage": {
            "vectors": list(VECTOR_LABELS.keys()),
            "exploit_feed": ("connected" if any(row["enrichment"]["kev"]["known"]
                                                for row in rows)
                             else "not connected (KEV/EPSS empty)"),
            "grouping": "one row per (vector, signature, component)",
        },
    }


@router.get("/vulnerabilities/meta/summary")
@router.get("/vulnerabilities/summary")
def summary(org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    """Counters for the dashboard and the projects list."""
    rows = _groups(session, org, include_suppressed=False)
    return {"data": {
        "vulnerabilities": len(rows),
        "findings": sum(row["findings"] for row in rows),
        "kev": sum(1 for row in rows if row["enrichment"]["kev"]["listed"]),
        "fixable": sum(1 for row in rows if row["fix"]["available"]),
        "by_vector": {vector: sum(1 for row in rows if row["vector"] == vector)
                      for vector in VECTOR_LABELS},
        "by_severity": {level: sum(1 for row in rows if row["severity"] == level)
                        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")},
        "by_risk": {label: sum(1 for row in rows if row["exposure"]["label"] == label)
                    for label in ("critical", "high", "medium", "low")},
    }}


@router.get("/vulnerabilities/{ref}")
def get_vulnerability(ref: str,
                      include_suppressed: bool = Query(default=False),
                      org: models.Organization = Depends(auth.require_org),
                      session: Session = Depends(get_session)):
    """One problem with every occurrence, or 404 when it affects nothing here."""
    row = _match(_groups(session, org, include_suppressed), ref)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "no finding in this organization matches that vulnerability")
    return {"data": row}


class StatusIn(BaseModel):
    status: str = Field(min_length=1, max_length=32)
    reason: str | None = Field(default=None, max_length=2000)


@router.patch("/vulnerabilities/{ref}/status")
def set_status(ref: str, payload: StatusIn,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """Move every finding of this problem at once.

    A vulnerability has one lifecycle even when it has twelve occurrences; making
    the operator click twelve times is how a queue stops being worked.
    """
    allowed = {"open", "acknowledged", "resolved", "false_positive", "accepted_risk"}
    if payload.status not in allowed:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"status must be one of {sorted(allowed)}")
    row = _match(_groups(session, org, include_suppressed=True), ref)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "vulnerability not found")
    now = models.utcnow()
    touched = 0
    for location in row["locations"]:
        finding = session.get(models.Finding, location["finding_id"])
        if finding is None or finding.status == "suppressed":
            continue
        finding.status = payload.status
        finding.status_reason = payload.reason
        finding.status_changed_at = now
        finding.updated_at = now
        touched += 1
    _audit_log(session, org.id, "operator", f"vulnerability.{payload.status}",
               "vulnerability", row["id"], payload.reason)
    session.commit()
    return {"data": {"id": row["id"], "status": payload.status, "findings": touched}}


class BulkPreviewIn(BaseModel):
    finding_ids: list[str] = Field(min_length=1, max_length=1000)
    status: str


@router.post("/vulnerabilities/{ref}/bulk-preview")
def bulk_preview(ref: str, payload: BulkPreviewIn = None,
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """Preview a grouped status change without writing anything.

    The preview and the apply path share the selection logic, so the numbers a
    reader approves are the numbers that would change. Suppressed findings are
    skipped: their disposition belongs to the suppression rule.
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
            skipped.append({"finding_id": finding_id,
                            "reason": "not found in this organization"})
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
    return {"data": {"ref": ref, "target_status": payload.status,
                     "would_change": len(will_change), "unchanged": len(already),
                     "skipped": skipped, "findings": will_change,
                     "requires": "write role (viewer cannot change status)"}}


@router.post("/vulnerabilities/{ref}/bulk-status")
def bulk_status(ref: str, payload: BulkPreviewIn = None,
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
        if finding.status in {"suppressed", payload.status}:
            skipped.append(finding_id)
            continue
        finding.status = payload.status
        finding.status_changed_at = models.utcnow()
        finding.updated_at = finding.status_changed_at
        _audit_log(session, org.id, actor, "finding.status_changed", "finding",
                   finding.id, f"{ref}: {payload.status}")
        changed.append(finding.id)
    session.commit()
    return {"data": {"ref": ref, "status": payload.status,
                     "changed": len(changed), "finding_ids": changed,
                     "skipped": skipped}}

"""SBOM ingestion endpoints."""
import json
import time
from urllib.parse import unquote

from fastapi import APIRouter, Depends, Body, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app.versions import pick_version
from backend.app import auth, ingest, models, scm_client
from backend.app.db import get_session
from backend.app.gates import NON_OPEN

router = APIRouter(prefix="/api/v1", tags=["sbom"])

MAX_BODY_BYTES = 50 * 1024 * 1024  # 50 MB, matching the reference platform's contract floor
ALLOWED_SOURCES = ("cli", "web", "ci", "api")
# A finding somebody disposed of — resolved, accepted, false positive, suppressed
# — is not silent: it is counted apart from the open list, because "nothing here"
# and "somebody looked and decided" are different answers.
SETTLED_STATUSES = NON_OPEN | {"suppressed"}


class ReceiptResponse(BaseModel):
    status: str
    import_id: str
    receipt: dict
    artifact: dict | None = None


@router.post("/sbom", response_model=ReceiptResponse)
def upload_sbom(
    body: bytes = Body(...),
    project: str | None = Query(default=None, description="project name override"),
    version: str | None = Query(default=None, description="project version override"),
    component: str | None = Query(
        default=None,
        description="component the version belongs to (name or slug); omit for a product-wide release"),
    source: str = Query(default="api"),
    filename: str | None = Query(default=None),
    artifact_digest: str | None = Query(default=None, max_length=128,
                                        description="digest of the exact build"),
    artifact_name: str | None = Query(default=None, max_length=255),
    artifact_provenance: str | None = Query(default=None, max_length=255),
    org: models.Organization = Depends(auth.require_org),
    session: Session = Depends(get_session),
):
    """Ingest a raw CycloneDX JSON SBOM body; idempotent per key triple.

    201 for a new receipt, 200 when the same content already landed for that
    project+version. `source` declares the delivery channel ('cli', 'web',
    'ci', 'api'); it carries no security meaning by itself.
    """
    if source not in ALLOWED_SOURCES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid source")
    if len(body) > MAX_BODY_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "SBOM body exceeds 50 MB")
    if not body.lstrip()[:1] == b"{":
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "body must be a JSON object")
    try:
        result = ingest.ingest_document(
            session, org.id, body, source=source, filename=filename,
            project_override=project, version_override=version,
            component_override=component)
    except (ingest.SbomDocumentError, ValueError, json.JSONDecodeError) as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from None
    receipt = session.get(models.SbomImport, result["import_id"])
    version = session.get(models.ProjectVersion, receipt.project_version_id)
    artifact = None
    if artifact_digest:
        artifact = (session.query(models.Artifact)
                    .filter_by(org_id=org.id, digest=artifact_digest.strip()).one_or_none())
        if artifact is None:
            artifact = models.Artifact(
                org_id=org.id, project_version_id=version.id,
                name=(artifact_name or filename or f"build-{artifact_digest[:12]}"),
                digest=artifact_digest.strip(), digest_algorithm="sha256",
                provenance=artifact_provenance, source=source)
            session.add(artifact)
            session.flush()
        if receipt.artifact_id is None:
            receipt.artifact_id = artifact.id
    if receipt.artifact_id:
        artifact = session.get(models.Artifact, receipt.artifact_id)
    session.commit()
    status_code = 201 if result["status"] == "created" else 200
    payload = ReceiptResponse.model_validate(result, from_attributes=True).model_dump()
    payload["artifact"] = ({"id": artifact.id, "name": artifact.name,
                            "digest": artifact.digest,
                            "provenance": artifact.provenance,
                            "project_version_id": artifact.project_version_id}
                           if artifact else None)
    return JSONResponse(status_code=status_code, content=payload)


@router.get("/imports/{import_id}")
def get_import(import_id: str, org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    receipt = session.get(models.SbomImport, import_id)
    if receipt is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "import not found")
    project_version = session.get(models.ProjectVersion, receipt.project_version_id)
    project = session.get(models.Project, project_version.project_id)
    if project.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "import not found")
    return {"data": ingest.receipt_of(receipt, project, project_version)}


@router.get("/sbom/compare")
def compare_versions(project: str = Query(...), from_version: str = Query(...),
                     to_version: str = Query(...),
                     org: models.Organization = Depends(auth.require_org),
                     session: Session = Depends(get_session)):
    """Component-level diff between two versions of the same project.

    Identity is the component name (plus purl when present); a version change
    is reported as `changed`, never silently folded into added/removed.
    """
    proj = (session.query(models.Project)
            .filter_by(org_id=org.id, slug=project).one_or_none())
    if proj is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")

    def load(version_label: str) -> dict:
        pv = (pick_version(session, proj.id, version_label))
        if pv is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                f"version not found: {version_label}")
        rows = (session.query(models.VersionComponent, models.Component)
                .join(models.Component,
                      models.VersionComponent.component_id == models.Component.id)
                .filter(models.VersionComponent.project_version_id == pv.id).all())
        return {(component.name or component.identity_key):
                {"id": component.id, "version": component.version,
                 "purl": component.purl}
                for _link, component in rows}

    before = load(from_version)
    after = load(to_version)
    added = [{"name": name, **after[name]}
             for name in sorted(set(after) - set(before))]
    removed = [{"name": name, **before[name]}
               for name in sorted(set(before) - set(after))]
    changed = []
    for name in sorted(set(before) & set(after)):
        if before[name]["version"] != after[name]["version"]:
            changed.append({"name": name,
                            "from": before[name]["version"],
                            "to": after[name]["version"]})
    return {"data": {"project": proj.slug, "from": from_version,
                     "to": to_version,
                     "counts": {"from": len(before), "to": len(after),
                                "added": len(added), "removed": len(removed),
                                "changed": len(changed)},
                     "added": added, "removed": removed, "changed": changed}}


def _version_of(session, org_id: str, project: str, version: str):
    project_row = (session.query(models.Project)
                   .filter_by(org_id=org_id, slug=project).one_or_none())
    if project_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    pv = (pick_version(session, project_row.id, version))
    if pv is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")
    return project_row, pv


def _component_set(session, org_id: str, project_version_id: str) -> dict:
    rows = (session.query(models.VersionComponent, models.Component)
            .join(models.Component, models.VersionComponent.component_id == models.Component.id)
            .filter(models.VersionComponent.project_version_id == project_version_id).all())
    # A version can legitimately hold several builds of the same name while a
    # stale link is being cleaned up; keep them all instead of hiding one.
    collected: dict[str, dict] = {}
    for _link, component in rows:
        key = component.name or component.identity_key
        entry = collected.setdefault(key, {"versions": [], "purl": component.purl})
        if component.version:
            entry["versions"].append(component.version)
    for entry in collected.values():
        entry["versions"] = sorted(set(entry["versions"]))
        entry["version"] = entry["versions"][-1] if entry["versions"] else None
    return collected


def _baseline_diff(before: dict, after: dict) -> dict:
    added = [{"name": name, **after[name]} for name in sorted(set(after) - set(before))]
    removed = [{"name": name, **before[name]} for name in sorted(set(before) - set(after))]
    changed = [{"name": name,
                "from": ", ".join(before[name]["versions"]) or None,
                "to": ", ".join(after[name]["versions"]) or None}
               for name in sorted(set(before) & set(after))
               if before[name]["versions"] != after[name]["versions"]]
    return {"counts": {"baseline": len(before), "current": len(after),
                       "added": len(added), "removed": len(removed),
                       "changed": len(changed)},
            "added": added, "removed": removed, "changed": changed}


class BaselineIn(BaseModel):
    project: str
    version: str
    note: str | None = None
    actor: str


@router.post("/sbom/baseline")
def set_baseline(payload: BaselineIn = None,
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """Freeze the current component set of a version as its security baseline."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    _project, pv = _version_of(session, org.id, payload.project, payload.version)
    current = _component_set(session, org.id, pv.id)
    if not current:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "no components for that version; ingest an SBOM first")
    row = (session.query(models.SbomBaseline)
           .filter_by(project_version_id=pv.id).one_or_none())
    now = models.utcnow()
    if row is None:
        row = models.SbomBaseline(org_id=org.id, project_version_id=pv.id,
                                  created_at=now)
        session.add(row)
    row.components = json.dumps(current, sort_keys=True)
    row.component_count = len(current)
    row.note = payload.note
    row.created_by = payload.actor
    row.created_at = now
    session.commit()
    return {"data": {"project": payload.project, "version": payload.version,
                     "component_count": row.component_count,
                     "created_at": row.created_at.isoformat(),
                     "replaced": True}}


@router.get("/sbom/baseline")
def get_baseline(project: str = Query(...), version: str = Query(...),
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    _project, pv = _version_of(session, org.id, project, version)
    row = (session.query(models.SbomBaseline)
           .filter_by(project_version_id=pv.id).one_or_none())
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no baseline for that version")
    return {"data": {"project": project, "version": version,
                     "component_count": row.component_count,
                     "note": row.note, "created_by": row.created_by,
                     "created_at": row.created_at.isoformat()}}


@router.delete("/sbom/baseline")
def delete_baseline(project: str = Query(...), version: str = Query(...),
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    _project, pv = _version_of(session, org.id, project, version)
    row = (session.query(models.SbomBaseline)
           .filter_by(project_version_id=pv.id).one_or_none())
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no baseline for that version")
    session.delete(row)
    session.commit()
    return {"data": {"deleted": True}}


@router.get("/sbom/baseline/diff")
def baseline_diff(project: str = Query(...), version: str = Query(...),
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    """Current component set against the stored baseline (never invented)."""
    _project, pv = _version_of(session, org.id, project, version)
    row = (session.query(models.SbomBaseline)
           .filter_by(project_version_id=pv.id).one_or_none())
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no baseline for that version")
    before = json.loads(row.components)
    after = _component_set(session, org.id, pv.id)
    return {"data": {"project": project, "version": version,
                     "baseline_at": row.created_at.isoformat(),
                     **_baseline_diff(before, after)}}


# ── the BOM as a screen, not a receipt ──────────────────────────────────────
# A BOM belongs to a project version, but it is not a project concern: the same
# reading (components, vulnerabilities, KEV, licenses) is asked from Supply
# chain without opening the project. So the index answers "which versions have
# a BOM" and the version endpoint answers "what is inside this one" — the two
# questions the Dependency-Track screen is built on.

CLOSED_FINDING_STATUSES = ("closed", "resolved", "false_positive")

# What a finding costs a component, before the exploitability multipliers. The
# numbers are policy, not physics: they exist so "which package should I look at
# first" has one answer instead of a reader comparing five severity badges. A
# vendor's risk score would be a black box; this one is written down.
RISK_WEIGHT = {"CRITICAL": 10.0, "HIGH": 6.0, "MEDIUM": 3.0, "LOW": 1.0,
               "UNKNOWN": 0.5}
RISK_KEV_MULTIPLIER = 2.0
SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def _purl_group(purl: str | None) -> str | None:
    """The package's namespace — npm scope, Maven groupId, Go module path.

    `pkg:npm/%40angular/core@17` is group `@angular`, name `core`: the group is
    what a reader groups by, and it is already in the purl rather than a column
    of its own.
    """
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("@", 1)[0]
    parts = [unquote(part) for part in body.split("/") if part]
    if len(parts) <= 2:
        return None
    return "/".join(parts[1:-1])


def _risk_score(findings, advisories: dict, kev_cves: set, epss: dict) -> float:
    """0–100. Known-exploited doubles the weight, EPSS scales it.

    A score nobody can recompute is a score nobody trusts: severity weight, times
    the KEV multiplier, times (1 + EPSS probability). Capped at 100.
    """
    total = 0.0
    for finding in findings:
        severity = (finding.severity or "UNKNOWN").upper()
        weight = RISK_WEIGHT.get(severity, RISK_WEIGHT["UNKNOWN"])
        advisory = advisories.get(finding.vulnerability_id) if finding.vulnerability_id else None
        cve = advisory.cve_id if advisory else None
        if cve and cve in kev_cves:
            weight *= RISK_KEV_MULTIPLIER
        probability = float(epss.get(cve, 0.0) or 0.0) if cve else 0.0
        total += weight * (1.0 + probability)
    return round(min(total, 100.0), 1)


def _severity_counts(findings) -> dict:
    counts = {sev: 0 for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
    for finding in findings:
        key = (finding.severity or "UNKNOWN").upper()
        counts[key if key in counts else "UNKNOWN"] += 1
    return counts


def _kev_cves(session) -> set:
    return {row.cve_id for row in session.query(models.KevEntry).all()}


def _epss_map(session, cves: set) -> dict:
    """EPSS probability per CVE, for the scores; a missing row means unknown, 0."""
    if not cves:
        return {}
    rows = (session.query(models.EpssScore.cve_id, models.EpssScore.epss)
            .filter(models.EpssScore.cve_id.in_(sorted(cves))).all())
    out = {}
    for cve_id, value in rows:
        try:
            out[cve_id] = float(value)
        except (TypeError, ValueError):
            continue
    return out


def _advisories_for(session, findings) -> dict:
    ids = {finding.vulnerability_id for finding in findings if finding.vulnerability_id}
    if not ids:
        return {}
    return {row.id: row for row in
            session.query(models.Vulnerability)
            .filter(models.Vulnerability.id.in_(sorted(ids))).all()}


def _project_component_names(session, project_id: str) -> set:
    """The project's own application components, lowercased.

    A package that IS one of the project's components is first-party; everything
    else in the BOM is third-party. That is what the "internal" column means.
    """
    rows = (session.query(models.ApplicationComponent.name,
                          models.ApplicationComponent.slug)
            .filter_by(project_id=project_id).all())
    names = set()
    for name, slug in rows:
        for value in (name, slug):
            if value:
                names.add(value.lower())
    return names


def _component_ref(session, project_id: str, ref: str | None) -> str | None:
    """Resolve a component by slug or name.

    A build is addressed as project/component/version: `aurea/web/main` and
    `aurea/backend/main` are different builds that share a label, and the URL has
    to say which one you mean.
    """
    if not ref:
        return None
    query = session.query(models.ApplicationComponent).filter(
        models.ApplicationComponent.project_id == project_id)
    row = query.filter(models.ApplicationComponent.slug == ref).one_or_none()
    if row is None:
        row = query.filter(func.lower(models.ApplicationComponent.name) == ref.lower()).one_or_none()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            f"component not found in this project: {ref}")
    return row.id


def _previous_version(session, project_id: str, version_row):
    """The previous build of *this component*, when there is one.

    A monorepo ships backend and web under the same label; comparing the web
    build against whatever the backend ingested last reads as a 370-package
    explosion that never happened.
    """
    query = (session.query(models.ProjectVersion)
             .filter(models.ProjectVersion.project_id == project_id,
                     models.ProjectVersion.created_at < version_row.created_at))
    if version_row.component_id:
        query = query.filter(models.ProjectVersion.component_id == version_row.component_id)
    else:
        query = query.filter(models.ProjectVersion.component_id.is_(None))
    return query.order_by(models.ProjectVersion.created_at.desc()).first()


def _component_finding_counts(session, org_id: str, version_id: str) -> dict:
    rows = (session.query(models.Finding.component_id,
                          func.count(models.Finding.id))
            .filter(models.Finding.org_id == org_id,
                    models.Finding.last_seen_version_id == version_id,
                    models.Finding.status.notin_(CLOSED_FINDING_STATUSES),
                    models.Finding.component_id.isnot(None))
            .group_by(models.Finding.component_id).all())
    return {component_id: count for component_id, count in rows}


def _project_trend(session, org_id: str, project_id: str,
                   component_id: str | None = None) -> list[dict]:
    """Every build of this component, oldest first: better or worse?

    Scoped to the component on purpose: a monorepo puts backend and web builds
    under the same project, and one line that jumps from 122 to 495 packages
    teaches nothing about either.

    One grouped query per axis instead of building a BOM per version: the header
    of a version screen is not the place to re-read 123 components thirteen
    times.
    """
    query = session.query(models.ProjectVersion).filter_by(project_id=project_id)
    if component_id:
        query = query.filter(models.ProjectVersion.component_id == component_id)
    else:
        query = query.filter(models.ProjectVersion.component_id.is_(None))
    versions = query.order_by(models.ProjectVersion.created_at).all()
    if not versions:
        return []
    ids = [row.id for row in versions]
    component_counts = dict(
        session.query(models.VersionComponent.project_version_id,
                      func.count(models.VersionComponent.component_id))
        .filter(models.VersionComponent.project_version_id.in_(ids))
        .group_by(models.VersionComponent.project_version_id).all())
    finding_rows = (session.query(models.Finding.last_seen_version_id,
                                  models.Finding.severity,
                                  func.count(models.Finding.id))
                    .filter(models.Finding.org_id == org_id,
                            models.Finding.last_seen_version_id.in_(ids),
                            models.Finding.kind == "vulnerability",
                            models.Finding.status.notin_(CLOSED_FINDING_STATUSES))
                    .group_by(models.Finding.last_seen_version_id,
                              models.Finding.severity).all())
    per_version: dict[str, dict] = {}
    for version_id, severity, count in finding_rows:
        bucket = per_version.setdefault(version_id, {"total": 0, "by_severity": {}})
        key = (severity or "UNKNOWN").upper()
        bucket["by_severity"][key] = bucket["by_severity"].get(key, 0) + count
        bucket["total"] += count
    trend = []
    for row in versions:
        bucket = per_version.get(row.id, {"total": 0, "by_severity": {}})
        counts = {severity: bucket["by_severity"].get(severity, 0)
                  for severity in SEVERITY_ORDER}
        trend.append({
            "version_id": row.id,
            "version": row.version,
            "component_id": row.component_id,
            "at": row.created_at.isoformat() if row.created_at else None,
            "components": component_counts.get(row.id, 0),
            "findings": bucket["total"],
            "by_severity": counts,
        })
    return trend


def _sorted(rows: list[dict], field: str, descending: bool,
            extractors: dict) -> list[dict]:
    """Sort on the platform, not in the browser.

    The table is paginated, and a page that sorts itself is a page that lies: the
    reader sees "the worst five" of the twenty-five they happen to be looking at.
    Rows whose field is missing stay at the end whichever direction was asked for
    — an unknown license is not "smaller than A".
    """
    extract = extractors.get(field) or extractors["_default"]
    missing = [row for row in rows if extract(row) is None]
    present = sorted((row for row in rows if extract(row) is not None),
                     key=extract, reverse=descending)
    return present + missing


def code_rows(findings: list) -> list[dict]:
    """Source results, flattened for the table. A secret is labelled as such:
    the class changes what you do about it, not just how it is coloured."""
    rows = []
    for finding in findings:
        secret = finding.kind == "secret"
        rows.append({
            "finding_id": finding.id,
            "severity": (finding.severity or "UNKNOWN").upper(),
            "class": "secret" if secret else "weakness",
            "vector": finding.vector or ("credential" if secret else "sast"),
            "rule": finding.rule_id,
            # Scanner messages arrive multi-line (Trivy embeds artifact, type,
            # link); one line keeps the table a table.
            "title": " ".join((finding.title or "").split())[:400],
            "path": finding.path,
            "line": finding.line,
            "cwe": finding.cwe,
            "tool": finding.tool or finding.source,
            "status": finding.status,
            "dismissed": (finding.status or "").lower() in SETTLED_STATUSES,
            "url": finding.url,
            "detail": finding.detail,
            # The line(s) the scanner flagged, captured at ingest from the SARIF
            # region: the console shows the code, not a description of it.
            "snippet": finding.reproduction,
            "attributed_on": (finding.first_seen_at.isoformat()
                              if finding.first_seen_at else None),
        })
    return rows


COMPONENT_SORTS = {
    "name": lambda row: (row["name"] or "").lower(),
    "version": lambda row: (row["version"] or "").lower(),
    "group": lambda row: (row["group"] or "").lower(),
    "internal": lambda row: row["internal"],
    "license": lambda row: (row["license"] or "").lower(),
    "risk": lambda row: row["risk"],
    "findings": lambda row: row["findings"],
    "_default": lambda row: row["risk"],
}

SEVERITY_RANK = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}

CODE_SORTS = {
    "severity": lambda row: SEVERITY_RANK.get(row["severity"], len(SEVERITY_ORDER)),
    "class": lambda row: row["class"],
    "rule": lambda row: (row["rule"] or "").lower(),
    "path": lambda row: (row["path"] or "").lower(),
    "line": lambda row: row["line"] if row["line"] is not None else 0,
    "tool": lambda row: (row["tool"] or "").lower(),
    "status": lambda row: row["status"],
    "_default": lambda row: SEVERITY_RANK.get(row["severity"], len(SEVERITY_ORDER)),
}

ADVISORY_SORTS = {
    "component": lambda row: (row["component"] or "").lower(),
    "version": lambda row: (row["component_version"] or "").lower(),
    "vulnerability": lambda row: (row["vulnerability"] or "").lower(),
    "severity": lambda row: SEVERITY_RANK.get(row["severity"], len(SEVERITY_ORDER)),
    "epss": lambda row: row["epss"],
    "kev": lambda row: row["kev"],
    "analyzer": lambda row: row["analyzer"],
    "status": lambda row: row["analysis"],
    "_default": lambda row: SEVERITY_RANK.get(row["severity"], len(SEVERITY_ORDER)),
}


def _code_elsewhere(session, org_id: str, project, version) -> list[dict]:
    """Sibling builds of the same component that carry source analysis.

    Attribution is per build: a SAST/secret run lands on the version its ticket
    named — usually a commit — while the moving `main` label keeps whatever the
    branch runs produced, so one of them can legitimately have none. Saying
    "this build has none" without naming the build that does sends the reader
    hunting through eleven versions; this is a pointer, never a merge of two
    builds' results.
    """
    if not version.component_id:
        return []
    siblings = (session.query(models.ProjectVersion)
                .filter_by(project_id=project.id, component_id=version.component_id)
                .filter(models.ProjectVersion.id != version.id)
                .order_by(models.ProjectVersion.created_at.desc()).all())
    if not siblings:
        return []
    rows = (session.query(models.Finding.last_seen_version_id, models.Finding.kind,
                          models.Finding.status)
            .filter(models.Finding.org_id == org_id,
                    models.Finding.kind.in_(("code-weakness", "secret")),
                    models.Finding.last_seen_version_id.in_([row.id for row in siblings]))
            .all())
    tally: dict[str, dict] = {}
    for version_id, kind, finding_status in rows:
        bucket = tally.setdefault(version_id, {"code": 0, "secrets": 0, "dismissed": 0})
        if (finding_status or "").lower() in SETTLED_STATUSES:
            bucket["dismissed"] += 1
        elif kind == "secret":
            bucket["secrets"] += 1
        else:
            bucket["code"] += 1
    out = []
    for sibling in siblings:
        bucket = tally.get(sibling.id)
        if not bucket:
            continue
        out.append({"version": sibling.version, "version_id": sibling.id, **bucket})
        if len(out) == 3:
            break
    return out


def _version_bom(session, org_id: str, project, version, kev_cves: set) -> dict:
    """One project version, read as a BOM: what it ships and what is wrong with it."""
    links = (session.query(models.VersionComponent)
             .filter_by(project_version_id=version.id).all())
    components = {}
    if links:
        components = {row.id: row for row in
                      session.query(models.Component)
                      .filter(models.Component.id.in_({link.component_id for link in links})).all()}
    # The audit list is about what the build ships: dependency CVEs. Code
    # weaknesses and leaked credentials belong to the source, not to the BOM,
    # and mixing them made "82 open findings" mean three different things.
    findings = (session.query(models.Finding)
                .filter_by(org_id=org_id, last_seen_version_id=version.id)
                .filter(models.Finding.status.notin_(CLOSED_FINDING_STATUSES))
                .filter(models.Finding.kind == "vulnerability").all())
    # Source findings load whole, then split: the tab lists every SAST/secret
    # result this build produced and says which ones a person already settled.
    # Dropping the settled ones made a dismissed secret scan look like a build
    # nobody scanned.
    code_all = (session.query(models.Finding)
                .filter_by(org_id=org_id, last_seen_version_id=version.id)
                .filter(models.Finding.kind.in_(("code-weakness", "secret")))
                .all())
    code_open = [row for row in code_all
                 if (row.status or "").lower() not in SETTLED_STATUSES]
    code_settled = [row for row in code_all if row not in code_open]
    imports = (session.query(models.SbomImport)
               .filter_by(project_version_id=version.id)
               .order_by(models.SbomImport.created_at.desc()).all())
    advisory_ids = {f.vulnerability_id for f in findings if f.vulnerability_id}
    advisories = {}
    if advisory_ids:
        advisories = {row.id: row for row in
                      session.query(models.Vulnerability)
                      .filter(models.Vulnerability.id.in_(advisory_ids)).all()}
    kev = sum(1 for finding in findings
              if (advisories.get(finding.vulnerability_id) or None) is not None
              and advisories[finding.vulnerability_id].cve_id in kev_cves)
    licenses = {}
    for component in components.values():
        license_name = (component.license or "unknown").strip() or "unknown"
        licenses[license_name] = licenses.get(license_name, 0) + 1
    return {
        "project": {"slug": project.slug, "name": project.name},
        "version": version.version,
        "version_id": version.id,
        "component_id": version.component_id,
        # Two builds can share a label in a monorepo; the component is what tells
        # "aurea · web · main" from "aurea · backend · main".
        "component": (session.get(models.ApplicationComponent, version.component_id).name
                      if version.component_id else None),
        "component_slug": (session.get(models.ApplicationComponent, version.component_id).slug
                           if version.component_id else None),
        "components": len(components),
        "direct": sum(1 for link in links if link.is_direct),
        "imports": [{"id": row.id, "source": row.source, "filename": row.filename,
                     "at": row.created_at.isoformat() if row.created_at else None,
                     "components_received": row.components_received}
                    for row in imports],
        "last_import_at": imports[0].created_at.isoformat() if imports else None,
        "findings": {"total": len(findings), "kev": kev,
                     "by_severity": _severity_counts(findings)},
        # Source-side results: the Code findings tab, and the counts its label
        # needs so the tab can say "20" before you open it.
        "code": {
            "total": len(code_open),
            "secrets": sum(1 for row in code_open if row.kind == "secret"),
            "dismissed": len(code_settled),
            "dismissed_secrets": sum(1 for row in code_settled if row.kind == "secret"),
            "by_severity": _severity_counts(code_open),
            "elsewhere": _code_elsewhere(session, org_id, project, version),
        },
        # Open rows first: the reader opens the tab for what still needs a
        # decision, and the settled ones hang below in the same list.
        "_code": code_open + code_settled,
        "licenses": licenses,
        "_components": components,
        "_findings": findings,
        "_advisories": advisories,
    }


@router.get("/sbom/index")
def bom_index(org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    """Every project version that has a BOM, newest import first."""
    rows = []
    seen_project = set()
    kev_cves = _kev_cves(session)
    for project in (session.query(models.Project).filter_by(org_id=org.id)
                    .order_by(models.Project.name).all()):
        for version in (session.query(models.ProjectVersion)
                        .filter_by(project_id=project.id)
                        .order_by(models.ProjectVersion.created_at.desc()).all()):
            data = _version_bom(session, org.id, project, version, kev_cves)
            if not data["imports"] and not data["components"]:
                continue
            data.pop("_components"); data.pop("_findings"); data.pop("_advisories")
            # Versions arrive newest first: the first one that survives the
            # empty filter is the latest BOM of that project.
            data["is_latest"] = project.slug not in seen_project
            seen_project.add(project.slug)
            rows.append(data)
    totals = {sev: sum(row["findings"]["by_severity"][sev] for row in rows)
              for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
    return {"data": rows,
            "totals": {"boms": len(rows),
                       "components": sum(row["components"] for row in rows),
                       "findings": sum(row["findings"]["total"] for row in rows),
                       "kev": sum(row["findings"]["kev"] for row in rows),
                       "by_severity": totals}}


@router.get("/sbom/version")
def bom_version(project: str = Query(...), version: str = Query(...),
                component: str | None = Query(default=None),
                component_id: str | None = Query(default=None),
                version_id: str | None = Query(default=None),
                component_sort: str = Query(default="risk"),
                component_dir: str = Query(default="desc"),
                advisory_sort: str = Query(default="severity"),
                advisory_dir: str = Query(default="asc"),
                code_sort: str = Query(default="severity"),
                code_dir: str = Query(default="asc"),
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    """One version's dependency-tracker payload: header, components, findings.

    A version label can exist more than once in a project — one row per component
    — so the row is chosen by the same rule every other endpoint uses
    (`pick_version`): the requested component, else the product-wide release,
    else the oldest row. `version_id` (which `/sbom/index` already returns) is the
    exact answer when the caller has it. Asking for `one_or_none()` here was a
    500 as soon as a monorepo shipped two components at the same label.
    """
    project_row = (session.query(models.Project)
                   .filter_by(org_id=org.id, slug=project).one_or_none())
    if project_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    if version_id:
        version_row = session.get(models.ProjectVersion, version_id)
        if version_row is not None and version_row.project_id != project_row.id:
            version_row = None
    else:
        if component and not component_id:
            component_id = _component_ref(session, project_row.id, component)
        version_row = pick_version(session, project_row.id, version, component_id)
    if version_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")

    data = _version_bom(session, org.id, project_row, version_row, _kev_cves(session))
    kev_cves = _kev_cves(session)
    components = data.pop("_components")
    findings = data.pop("_findings")
    code_findings = data.pop("_code", [])
    advisories = data.pop("_advisories")
    # One EPSS read for both views: the audit list shows it per advisory, the
    # component table multiplies it into the risk score.
    epss = _epss_map(session, {advisory.cve_id for advisory in advisories.values()
                               if advisory.cve_id})

    rows = []
    for finding in findings:
        component = components.get(finding.component_id) if finding.component_id else None
        advisory = advisories.get(finding.vulnerability_id)
        rows.append({
            "finding_id": finding.id,
            "component": component.name if component else None,
            "component_version": component.version if component else None,
            "purl": component.purl if component else None,
            "vulnerability": (advisory.cve_id if advisory and advisory.cve_id
                              else (advisory.source_id if advisory else finding.rule_id)),
            "title": advisory.title if advisory else finding.title,
            "severity": (finding.severity or "UNKNOWN").upper(),
            "kev": bool(advisory and advisory.cve_id in kev_cves),
            # FIRST's exploitation probability, when the feed has been mirrored.
            # Unknown is null, never 0: "nobody has scored this" and "nobody will
            # exploit this" are different facts.
            "epss": epss.get(advisory.cve_id) if advisory else None,
            "analyzer": finding.tool or finding.source,
            "kind": finding.kind,
            "attributed_on": finding.first_seen_at.isoformat() if finding.first_seen_at else None,
            "analysis": finding.status,
            "suppressed": finding.status in ("suppressed", "false_positive"),
            "url": advisory.url if advisory else finding.url,
        })
    # Worst first, and inside one severity the most likely to be exploited. This
    # is the base order every other sort is a stable reordering of, so "sort by
    # component" still shows each component's worst advisory first.
    rows.sort(key=lambda row: (SEVERITY_RANK.get(row["severity"], len(SEVERITY_ORDER)),
                               -(row["epss"] or 0)))
    rows = _sorted(rows, advisory_sort, advisory_dir == "desc", ADVISORY_SORTS)

    # The Components tab answers "what is inside this build and what does it
    # cost": identity (group, version, license), a risk score anybody can
    # recompute, and the severity bar. Per component, never a rollup.
    findings_by_component: dict[str, list] = {}
    for finding in findings:
        findings_by_component.setdefault(finding.component_id, []).append(finding)

    internal_names = _project_component_names(session, project_row.id)
    previous = _previous_version(session, project_row.id, version_row)
    previous_counts = (_component_finding_counts(session, org.id, previous.id)
                       if previous is not None else None)

    links = {link.component_id: link for link in
             session.query(models.VersionComponent)
             .filter_by(project_version_id=version_row.id).all()}
    rows_out = []
    for component in components.values():
        mine = findings_by_component.get(component.id, [])
        counts = _severity_counts(mine)
        worst = next((severity for severity in SEVERITY_ORDER if counts[severity]), None)
        rows_out.append({
            "component_id": component.id,
            # The purl owns the name: Trivy stores a scoped package as
            # `name: node` + `group: @types`, and a table of rows all called
            # "node" is not an inventory. Rows imported before this rule are
            # repaired on read instead of waiting for a re-scan.
            "name": ingest.purl_name(component.purl) or component.name,
            "version": component.version,
            "purl": component.purl,
            "group": _purl_group(component.purl),
            "internal": bool(component.name
                             and component.name.lower() in internal_names),
            "license": component.license,
            "direct": bool(links.get(component.id) and links[component.id].is_direct),
            # Where the package sits in the build's tree: the manifest it came
            # from and, when the BOM resolves packages against each other, its
            # parent. Null parent + direct means "pip could not tell us more".
            "manifest": links[component.id].manifest_path if component.id in links else None,
            "parent_purl": links[component.id].parent_purl if component.id in links else None,
            "findings": len(mine),
            "by_severity": counts,
            "worst": worst,
            "risk": _risk_score(mine, advisories, kev_cves, epss),
            # How this package moved since the previous build of the project:
            # the number the overview's "what changed" needs, computed once here
            # instead of by fetching a second version from the browser.
            "findings_previous": (previous_counts or {}).get(component.id, 0)
            if previous_counts is not None else None,
        })
    rows_out.sort(key=lambda row: (-row["risk"], -(row["findings"] or 0),
                                   (row["name"] or "").lower()))
    data["component_rows"] = _sorted(rows_out, component_sort,
                                     component_dir == "desc", COMPONENT_SORTS)
    data["previous_version"] = previous.version if previous is not None else None
    data["trend"] = _project_trend(session, org.id, project_row.id, version_row.component_id)

    data["vulnerabilities"] = rows
    data["code_findings"] = code_rows(code_findings)
    data["code_findings"] = _sorted(data["code_findings"], code_sort,
                                    code_dir == "desc", CODE_SORTS)
    return {"data": data}


def _ancestry(session, version_id: str, component) -> list[dict]:
    """The chain from one package up to whatever the application declares.

    "I have a CVE in brotli" is only actionable as "brotli came in through
    axios", so the drawer answers with the path, not just the immediate parent.
    A cycle (possible in a hand-written BOM) stops the walk instead of looping.
    """
    links = {link.component_id: link for link in
             session.query(models.VersionComponent)
             .filter_by(project_version_id=version_id).all()}
    if not links:
        return []
    by_purl = {}
    for row in (session.query(models.Component)
                .filter(models.Component.id.in_(set(links))).all()):
        if row.purl:
            by_purl[row.purl] = row
    path: list[dict] = []
    seen = {component.id}
    current = component
    while len(path) < 16:
        link = links.get(current.id)
        parent = by_purl.get(link.parent_purl) if link and link.parent_purl else None
        if parent is None or parent.id in seen:
            break
        path.append({"id": parent.id, "name": parent.name, "version": parent.version,
                     "purl": parent.purl})
        seen.add(parent.id)
        current = parent
    return path


# Small, short-lived cache: walking fifteen issues in one file should cost one
# fetch, not fifteen. The key includes the commit, so a new build never serves
# the previous one's source.
_SOURCE_CACHE: dict[tuple[str, str, str], tuple[float, str | None]] = {}
_SOURCE_TTL = 300.0


def _source_ref(session, version) -> tuple[str, str] | None:
    """(remote, commit) for the build: what was scanned, not what is on main."""
    job = (session.query(models.ScanJob)
           .filter_by(project_version_id=version.id)
           .order_by(models.ScanJob.created_at.desc()).first())
    if job is not None:
        try:
            subject = json.loads(job.subject or "{}")
        except ValueError:
            subject = {}
        if subject.get("repository") and subject.get("commit"):
            return subject["repository"], subject["commit"]
    run = (session.query(models.AnalysisRun)
           .filter_by(project_version_id=version.id)
           .order_by(models.AnalysisRun.created_at.desc()).first())
    if run is not None and run.repository_id and run.commit:
        repository = session.get(models.Repository, run.repository_id)
        if repository is not None:
            return repository.remote_url, run.commit
    return None


@router.get("/sbom/source")
def bom_source(version_id: str = Query(...), path: str = Query(...),
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """The whole file at the commit this build was scanned at.

    A highlighted snippet answers "what is wrong"; the file answers "where am I".
    The repository is public in this deployment, so no credential is involved —
    when it is not, the call reports that it could not read, never a blank file.
    """
    version_row = session.get(models.ProjectVersion, version_id)
    project = session.get(models.Project, version_row.project_id) if version_row else None
    if version_row is None or project is None or project.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")
    source = _source_ref(session, version_row)
    if source is None:
        return {"data": {"found": False,
                         "reason": "this build has no repository and commit recorded"}}
    repository, ref = source
    key = (repository, ref, path)
    now = time.monotonic()
    cached = _SOURCE_CACHE.get(key)
    if cached and now - cached[0] < _SOURCE_TTL:
        text = cached[1]
    else:
        text = scm_client.raw_file(repository, ref, path)
        if len(_SOURCE_CACHE) > 128:
            _SOURCE_CACHE.clear()
        _SOURCE_CACHE[key] = (now, text)
    if text is None:
        return {"data": {"found": False, "ref": ref, "path": path,
                         "reason": f"the repository did not return {path} at {ref[:8]}"}}
    lines = text.splitlines()
    return {"data": {"found": True, "ref": ref, "repository": repository, "path": path,
                     "lines": lines[:6000], "total": len(lines),
                     "truncated": len(lines) > 6000}}


@router.get("/sbom/component")
def bom_component(version_id: str = Query(...), component_id: str = Query(...),
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    """One package's advisories in this build and in the later ones.

    The drawer's question is "does upgrading fix it?", so the answer is grouped by
    version: what this build carries, then every later version of the same
    project where the same package is still affected. A package missing from a
    later version is simply not listed — absence is not a fix.
    """
    version_row = session.get(models.ProjectVersion, version_id)
    project = session.get(models.Project, version_row.project_id) if version_row else None
    if version_row is None or project is None or project.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")
    component = session.get(models.Component, component_id)
    if component is None or component.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "component not found")

    later = (session.query(models.ProjectVersion)
             .filter(models.ProjectVersion.project_id == project.id,
                     models.ProjectVersion.created_at >= version_row.created_at)
             .order_by(models.ProjectVersion.created_at).all())
    kev_cves = _kev_cves(session)

    versions = []
    for row in later:
        findings = (session.query(models.Finding)
                    .filter(models.Finding.org_id == org.id,
                            models.Finding.last_seen_version_id == row.id,
                            models.Finding.component_id == component_id,
                            models.Finding.status.notin_(CLOSED_FINDING_STATUSES))
                    .order_by(models.Finding.severity).all())
        if not findings and row.id != version_row.id:
            continue
        advisories = _advisories_for(session, findings)
        epss = _epss_map(session, {row_.cve_id for row_ in advisories.values()
                                   if row_.cve_id})
        versions.append({
            "version": row.version,
            "version_id": row.id,
            "at": row.created_at.isoformat() if row.created_at else None,
            "is_current": row.id == version_row.id,
            "risk": _risk_score(findings, advisories, kev_cves, epss),
            "findings": [{
                "id": finding.id,
                "advisory": (advisories[finding.vulnerability_id].cve_id
                             or advisories[finding.vulnerability_id].source_id)
                if finding.vulnerability_id in advisories else finding.rule_id,
                "title": (advisories[finding.vulnerability_id].title
                          if finding.vulnerability_id in advisories else finding.title),
                "severity": (finding.severity or "UNKNOWN").upper(),
                "kev": bool(finding.vulnerability_id in advisories
                            and advisories[finding.vulnerability_id].cve_id in kev_cves),
                "epss": epss.get(getattr(advisories.get(finding.vulnerability_id),
                                         "cve_id", None)),
                "url": (advisories[finding.vulnerability_id].url
                        if finding.vulnerability_id in advisories else finding.url),
                "status": finding.status,
            } for finding in findings],
        })

    # Who this package pulls in, and who pulled it in. The chain answers "why is
    # it here"; the children answer "what else comes with it" — the two questions
    # you actually have when a transitive package has a CVE.
    link = (session.query(models.VersionComponent)
            .filter_by(project_version_id=version_row.id, component_id=component.id)
            .one_or_none())
    version_links = (session.query(models.VersionComponent)
                     .filter_by(project_version_id=version_row.id).all())
    version_ids = {row.component_id for row in version_links}
    siblings = {row.id: row for row in
                session.query(models.Component)
                .filter(models.Component.id.in_(version_ids)).all()} if version_ids else {}
    findings_by_component: dict[str, list] = {}
    for finding in (session.query(models.Finding)
                    .filter_by(org_id=org.id, last_seen_version_id=version_row.id)
                    .filter(models.Finding.status.notin_(CLOSED_FINDING_STATUSES))
                    .filter(models.Finding.kind == "vulnerability").all()):
        findings_by_component.setdefault(finding.component_id, []).append(finding)

    def brief(child, parent_link):
        mine = findings_by_component.get(child.id, [])
        counts = _severity_counts(mine)
        return {
            "id": child.id, "name": child.name, "version": child.version,
            "purl": child.purl,
            "findings": len(mine),
            "worst": next((severity for severity in SEVERITY_ORDER if counts[severity]), None),
            "direct": bool(parent_link and parent_link.is_direct),
            "via": parent_link.manifest_path if parent_link else None,
        }

    requires = []
    if component.purl:
        for candidate_id, candidate_link in ((row.component_id, row) for row in version_links):
            if candidate_link.parent_purl != component.purl:
                continue
            child = siblings.get(candidate_id)
            if child is not None:
                requires.append(brief(child, candidate_link))
    required_by = []
    if link is not None and link.parent_purl:
        for candidate in siblings.values():
            if candidate.purl == link.parent_purl:
                required_by.append(brief(candidate, version_links[0] if version_links else None))
                break
    requires.sort(key=lambda row: (-row["findings"], (row["name"] or "").lower()))

    return {"data": {
        "component": {
            "id": component.id, "name": component.name, "version": component.version,
            "purl": component.purl, "license": component.license,
            "group": _purl_group(component.purl),
            "direct": bool(link and link.is_direct),
            "manifest": link.manifest_path if link else None,
            "risk": _risk_score(findings_by_component.get(component.id, []), _advisories_for(
                session, findings_by_component.get(component.id, [])),
                _kev_cves(session), _epss_map(session, {
                    advisory.cve_id for advisory in _advisories_for(
                        session, findings_by_component.get(component.id, [])).values()
                    if advisory.cve_id})),
        },
        "requires": requires,
        "required_by": required_by,
        # Immediate parent first: how this package got into the build.
        "path": _ancestry(session, version_row.id, component),
        "project": {"slug": project.slug, "name": project.name},
        "version": version_row.version,
        "versions": versions,
    }}

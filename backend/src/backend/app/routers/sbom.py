"""SBOM ingestion endpoints."""
import json

from fastapi import APIRouter, Depends, Body, HTTPException, Query, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from backend.app.versions import pick_version
from backend.app import auth, ingest, models
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1", tags=["sbom"])

MAX_BODY_BYTES = 50 * 1024 * 1024  # 50 MB, matching the reference platform's contract floor
ALLOWED_SOURCES = ("cli", "web", "ci", "api")


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


def _severity_counts(findings) -> dict:
    counts = {sev: 0 for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")}
    for finding in findings:
        key = (finding.severity or "UNKNOWN").upper()
        counts[key if key in counts else "UNKNOWN"] += 1
    return counts


def _kev_cves(session) -> set:
    return {row.cve_id for row in session.query(models.KevEntry).all()}


def _version_bom(session, org_id: str, project, version, kev_cves: set) -> dict:
    """One project version, read as a BOM: what it ships and what is wrong with it."""
    links = (session.query(models.VersionComponent)
             .filter_by(project_version_id=version.id).all())
    components = {}
    if links:
        components = {row.id: row for row in
                      session.query(models.Component)
                      .filter(models.Component.id.in_({link.component_id for link in links})).all()}
    findings = (session.query(models.Finding)
                .filter_by(org_id=org_id, last_seen_version_id=version.id)
                .filter(models.Finding.status.notin_(CLOSED_FINDING_STATUSES)).all())
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
        "components": len(components),
        "direct": sum(1 for link in links if link.is_direct),
        "imports": [{"id": row.id, "source": row.source, "filename": row.filename,
                     "at": row.created_at.isoformat() if row.created_at else None,
                     "components_received": row.components_received}
                    for row in imports],
        "last_import_at": imports[0].created_at.isoformat() if imports else None,
        "findings": {"total": len(findings), "kev": kev,
                     "by_severity": _severity_counts(findings)},
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
                component_id: str | None = Query(default=None),
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    """One version's dependency-tracker payload: header, components, findings."""
    project_row = (session.query(models.Project)
                   .filter_by(org_id=org.id, slug=project).one_or_none())
    if project_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    query = (session.query(models.ProjectVersion)
             .filter_by(project_id=project_row.id, version=version))
    if component_id:
        query = query.filter_by(component_id=component_id)
    version_row = query.one_or_none()
    if version_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")

    data = _version_bom(session, org.id, project_row, version_row, _kev_cves(session))
    kev_cves = _kev_cves(session)
    components = data.pop("_components")
    findings = data.pop("_findings")
    advisories = data.pop("_advisories")

    rows = []
    for finding in sorted(findings, key=lambda f: (f.severity or "UNKNOWN", f.first_seen_at)):
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
            "analyzer": finding.tool or finding.source,
            "kind": finding.kind,
            "attributed_on": finding.first_seen_at.isoformat() if finding.first_seen_at else None,
            "analysis": finding.status,
            "suppressed": finding.status in ("suppressed", "false_positive"),
            "url": advisory.url if advisory else finding.url,
        })

    # The Components tab reads the same version: each library with its own
    # finding count, so "what is wrong here" starts from the inventory, not
    # from a severity rollup nobody can act on.
    per_component = {}
    worst = {}
    for finding in findings:
        key = finding.component_id
        per_component[key] = per_component.get(key, 0) + 1
        severity = (finding.severity or "UNKNOWN").upper()
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
        if severity not in order:
            severity = "UNKNOWN"
        if key not in worst or order.index(severity) < order.index(worst[key]):
            worst[key] = severity
    links = {link.component_id: link for link in
             session.query(models.VersionComponent)
             .filter_by(project_version_id=version_row.id).all()}
    data["component_rows"] = sorted(
        ({"name": component.name, "version": component.version,
          "purl": component.purl, "license": component.license,
          "direct": bool(links.get(component.id) and links[component.id].is_direct),
          "findings": per_component.get(component.id, 0),
          "worst": worst.get(component.id)}
         for component in components.values()),
        key=lambda row: (-(row["findings"] or 0), (row["name"] or "").lower()))

    data["vulnerabilities"] = rows
    return {"data": data}

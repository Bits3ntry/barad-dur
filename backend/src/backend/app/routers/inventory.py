"""Inventory and project listing endpoints."""
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models, severity as severity_mod
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1", tags=["inventory"])

SEVERITIES = severity_mod.SEVERITIES
CLOSED_STATUSES = {"resolved", "suppressed", "false_positive"}


def _serialize_version_profile(session: Session, org_id: str,
                               project: models.Project,
                               version: models.ProjectVersion) -> dict:
    """Everything the console needs for one project version, in one round trip.

    This is the Dependency-Track view: how many components, which of them carry
    vulnerabilities, the license mix, and the severity vector — scoped to the
    version instead of the whole organization.
    """
    links = (session.query(models.VersionComponent)
             .filter_by(project_version_id=version.id).all())
    components = {}
    if links:
        rows = (session.query(models.Component)
                .filter(models.Component.id.in_({l.component_id for l in links}))
                .all())
        components = {row.id: row for row in rows}

    findings = (session.query(models.Finding)
                .filter_by(org_id=org_id, last_seen_version_id=version.id)
                .filter(models.Finding.status.notin_(CLOSED_STATUSES))
                .all())

    kev_cves = {row.cve_id for row in session.query(models.KevEntry).all()}
    advisories = {}
    vuln_ids = {f.vulnerability_id for f in findings if f.vulnerability_id}
    if vuln_ids:
        for row in (session.query(models.Vulnerability)
                    .filter(models.Vulnerability.id.in_(vuln_ids)).all()):
            advisories[row.id] = row

    by_severity = Counter()
    by_kind = Counter()
    per_component = Counter()
    kev = 0
    for finding in findings:
        by_severity[severity_mod.canonical(finding.severity)] += 1
        by_kind[finding.kind] += 1
        if finding.component_id:
            per_component[finding.component_id] += 1
        advisory = advisories.get(finding.vulnerability_id)
        if advisory and advisory.cve_id in kev_cves:
            kev += 1

    license_counts = Counter(
        (component.license or "unknown").strip() or "unknown"
        for component in components.values())

    top_components = []
    for component_id, count in per_component.most_common(10):
        component = components.get(component_id)
        if component is None:
            continue
        worst = "UNKNOWN"
        for finding in findings:
            if finding.component_id != component_id:
                continue
            severity = severity_mod.canonical(finding.severity)
            if SEVERITIES.index(severity) < SEVERITIES.index(worst):
                worst = severity
        top_components.append({"name": component.name, "version": component.version,
                               "purl": component.purl, "license": component.license,
                               "findings": count, "worst_severity": worst})

    last_import = (session.query(models.SbomImport)
                   .filter_by(project_version_id=version.id)
                   .order_by(models.SbomImport.created_at.desc()).first())

    direct = sum(1 for link in links if link.is_direct)
    return {
        "project": project.slug,
        "project_name": project.name,
        "group": project.group_name or "ungrouped",
        "version": version.version,
        "version_id": version.id,
        "components": {"total": len(links), "direct": direct,
                       "transitive": len(links) - direct},
        "licenses": {"distinct": len(license_counts),
                     "top": [{"license": name, "count": count}
                             for name, count in license_counts.most_common(8)]},
        "findings": {"total": len(findings),
                     "by_severity": {sev: by_severity.get(sev, 0) for sev in SEVERITIES},
                     "by_kind": dict(by_kind),
                     "kev": kev,
                     "vulnerable_components": len(per_component)},
        "top_components": top_components,
        "last_import": ({"id": last_import.id,
                         "imported_at": last_import.created_at.isoformat(),
                         "source": last_import.source}
                        if last_import else None),
    }


@router.get("/inventory/portfolio")
def portfolio(org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    """Every project version with its component/finding rollup.

    Grouping has three levels — group -> project -> version — and accounting is
    always "the selected version, otherwise the latest". Each row says whether
    it is the latest for its project, and `groups` is the rollup a reader wants
    at the top: per product, counting one version per project (not the sum of
    every historical version, which double-counts components).
    """
    rows = []
    for project in (session.query(models.Project).filter_by(org_id=org.id)
                    .order_by(models.Project.name).all()):
        versions = (session.query(models.ProjectVersion)
                    .filter_by(project_id=project.id)
                    .order_by(models.ProjectVersion.created_at.desc()).all())
        for index, version in enumerate(versions):
            row = _serialize_version_profile(session, org.id, project, version)
            row["is_latest"] = index == 0
            rows.append(row)

    def _blank():
        return {"versions": 0, "projects": 0, "components": 0, "findings": 0, "kev": 0,
                "by_severity": {sev: 0 for sev in SEVERITIES}}

    def _add(target, row):
        target["versions"] += 1
        target["components"] += row["components"]["total"]
        target["findings"] += row["findings"]["total"]
        target["kev"] += row["findings"]["kev"]
        for sev in SEVERITIES:
            target["by_severity"][sev] += row["findings"]["by_severity"][sev]

    totals = _blank()
    latest_totals = _blank()
    groups = {}
    for row in rows:
        _add(totals, row)
        bucket = groups.setdefault(row["group"], {**_blank(), "group": row["group"],
                                                  "projects": []})
        if row["project"] not in bucket["projects"]:
            bucket["projects"].append(row["project"])
            bucket["projects_count"] = len(bucket["projects"])
        if row["is_latest"]:
            _add(latest_totals, row)
            _add(bucket, row)
            bucket.setdefault("latest_versions", []).append(
                {"project": row["project"], "version": row["version"]})

    totals["projects"] = len({row["project"] for row in rows})
    latest_totals["projects"] = totals["projects"]
    for bucket in groups.values():
        bucket["versions"] = len(bucket.get("latest_versions") or [])
        bucket["projects_count"] = len(bucket["projects"])
    return {"data": rows, "totals": totals, "latest_totals": latest_totals,
            "groups": sorted(groups.values(), key=lambda item: item["group"].lower())}


@router.get("/inventory/profile")
def version_profile(project: str = Query(...), version: str = Query(...),
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    """One project version's rollup, with the components that carry findings."""
    project_row = (session.query(models.Project)
                   .filter_by(org_id=org.id, slug=project).one_or_none())
    if project_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    version_row = (session.query(models.ProjectVersion)
                   .filter_by(project_id=project_row.id, version=version).one_or_none())
    if version_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")
    return {"data": _serialize_version_profile(session, org.id, project_row, version_row)}


@router.get("/projects")
def list_projects(org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    rows = (session.query(models.Project)
            .filter_by(org_id=org.id).order_by(models.Project.name).all())
    data = []
    for project in rows:
        versions = (session.query(models.ProjectVersion)
                    .filter_by(project_id=project.id)
                    .order_by(models.ProjectVersion.created_at).all())
        data.append({"id": project.id, "name": project.name, "slug": project.slug,
                     "group": project.group_name,
                     "versions": [v.version for v in versions]})
    return {"data": data}


class ProjectGroupIn(BaseModel):
    group: str | None = Field(
        default=None,
        description="Product or account that owns this repository; null ungroups it")


@router.patch("/projects/{slug}")
def set_project_group(slug: str, payload: ProjectGroupIn,
                      org: models.Organization = Depends(auth.require_org),
                      session: Session = Depends(get_session)):
    """Assign the project to a group (or clear it).

    Free text rather than a table: the hierarchy reads Aurea > backend, but a
    new organization decides its own labels, and moving a repository between
    products must not need a migration.
    """
    project = (session.query(models.Project)
               .filter_by(org_id=org.id, slug=slug).one_or_none())
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    project.group_name = (payload.group or "").strip() or None
    session.commit()
    return {"data": {"slug": project.slug, "group": project.group_name}}


@router.get("/components")
def list_components(
    project: str | None = Query(default=None),
    version: str | None = Query(default=None),
    org: models.Organization = Depends(auth.require_org),
    session: Session = Depends(get_session),
):
    query = (session.query(models.VersionComponent, models.Component)
             .join(models.Component, models.VersionComponent.component_id == models.Component.id)
             .filter(models.Component.org_id == org.id))
    project_version = None
    if project or version:
        if not (project and version):
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                "project and version filters go together")
        project_version = _resolve_version(session, org.id, project, version)
        if project_version is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")
        query = query.filter(models.VersionComponent.project_version_id == project_version.id)
    rows = query.order_by(models.Component.identity_key).all()
    data = [{
        "id": component.id,
        "purl": component.purl,
        "identity_key": component.identity_key,
        "name": component.name,
        "version": component.version,
        "license": component.license,
        "manifest_path": component.manifest_path,
        "is_direct": link.is_direct,
        "parent_purl": link.parent_purl,
        "updated_at": component.updated_at.isoformat() if component.updated_at else None,
    } for link, component in rows]
    return {"data": data, "total": len(data)}


def _resolve_version(session: Session, org_id: str, project: str, version: str):
    project_row = (session.query(models.Project)
                   .filter_by(org_id=org_id, slug=project)
                   .one_or_none())
    if project_row is None:
        return None
    return (session.query(models.ProjectVersion)
            .filter_by(project_id=project_row.id, version=version).one_or_none())


@router.get("/components/impact")
def component_impact(component_id: str | None = Query(default=None),
                     purl: str | None = Query(default=None),
                     name: str | None = Query(default=None),
                     version: str | None = Query(default=None),
                     org: models.Organization = Depends(auth.require_org),
                     session: Session = Depends(get_session)):
    """Cross-project impact: where a component is used and what it exposes.

    Identity is resolved by id, purl, or name(+version); ambiguity is an error
    rather than a silent guess.
    """
    query = session.query(models.Component).filter_by(org_id=org.id)
    if component_id:
        query = query.filter_by(id=component_id)
    elif purl:
        query = query.filter_by(purl=purl)
    elif name:
        query = query.filter_by(name=name)
        if version:
            query = query.filter_by(version=version)
    else:
        raise HTTPException(status.HTTP_400_BAD_REQUEST,
                            "provide component_id, purl or name")
    matches = query.all()
    if not matches:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "component not found")
    if len(matches) > 1:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"ambiguous component ({len(matches)} versions match); pass "
            "component_id, purl or name+version")

    component = matches[0]
    usages = []
    for link in (session.query(models.VersionComponent)
                 .filter_by(component_id=component.id).all()):
        pv = session.get(models.ProjectVersion, link.project_version_id)
        if pv is None:
            continue
        project = session.get(models.Project, pv.project_id)
        if project is None or project.org_id != org.id:
            continue
        findings = (session.query(models.Finding)
                    .filter_by(org_id=org.id, component_id=component.id,
                               last_seen_version_id=pv.id).all())
        severities = {}
        for row in findings:
            severities[row.severity] = severities.get(row.severity, 0) + 1
        usages.append({"project": project.slug, "version": pv.version,
                       "is_direct": bool(link.is_direct),
                       "findings": len(findings),
                       "open_findings": sum(1 for f in findings
                                            if f.status not in {"resolved",
                                                                "false_positive",
                                                                "suppressed"}),
                       "by_severity": severities})
    usages.sort(key=lambda row: (row["open_findings"], row["findings"]),
                reverse=True)
    return {"data": {"component": {"id": component.id, "name": component.name,
                                   "version": component.version,
                                   "purl": component.purl,
                                   "license": component.license},
                     "projects_using": len(usages),
                     "total_findings": sum(row["findings"] for row in usages),
                     "open_findings": sum(row["open_findings"] for row in usages),
                     "usages": usages}}

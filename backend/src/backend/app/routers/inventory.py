"""Inventory and project listing endpoints."""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app import auth, models
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1", tags=["inventory"])


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
                     "versions": [v.version for v in versions]})
    return {"data": data}


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

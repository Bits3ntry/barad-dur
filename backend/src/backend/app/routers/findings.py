"""Vulnerability analysis and findings endpoints (F1)."""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app import auth, models, vulns
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1", tags=["findings"])


@router.post("/analyze")
def analyze_version(
    project: str = Query(...),
    version: str = Query(...),
    org: models.Organization = Depends(auth.require_org),
    session: Session = Depends(get_session),
):
    """Match the version inventory against OSV and upsert deduped findings.

    Synchronous on purpose at POC scale (one querybatch call); a queue-based
    ingest path follows the F2/F3 shape instead of blocking here forever.
    """
    project_row = (session.query(models.Project)
                   .filter_by(org_id=org.id, slug=project).one_or_none())
    if project_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    project_version = _version(session, project_row, version)
    if project_version is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")
    counters = vulns.analyze(session, org.id, project_row, project_version)
    session.commit()
    return {"status": "analyzed" if "error" not in counters else "error",
            "project": project_row.name, "version": project_version.version,
            "counts": counters}


@router.get("/findings")
def list_findings(
    project: str | None = Query(default=None),
    version: str | None = Query(default=None),
    kind: str | None = Query(default=None),
    org: models.Organization = Depends(auth.require_org),
    session: Session = Depends(get_session),
):
    query = (session.query(models.Finding)
             .join(models.Project, models.Finding.project_id == models.Project.id)
             .filter(models.Finding.org_id == org.id))
    if project or version:
        if not (project and version):
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                "project and version filters go together")
        project_version = _resolve(session, org.id, project, version)
        if project_version is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")
        # A finding carries the latest scan context through version links:
        # filter on components currently listed for that version.
        query = (query.join(models.VersionComponent,
                            models.VersionComponent.component_id == models.Finding.component_id)
                 .filter(models.VersionComponent.project_version_id == project_version.id))
    if kind:
        query = query.filter(models.Finding.kind == kind)
    rows = query.order_by(models.Finding.last_seen_at.desc()).all()

    data = []
    for finding in rows:
        component = session.get(models.Component, finding.component_id) \
            if finding.component_id else None
        vulnerability = session.get(models.Vulnerability, finding.vulnerability_id) \
            if finding.vulnerability_id else None
        data.append({
            "id": finding.id,
            "kind": finding.kind,
            "status": finding.status,
            "severity": finding.severity,
            "title": finding.title,
            "fingerprint": finding.fingerprint,
            "source": finding.source,
            "source_id": vulnerability.source_id if vulnerability else None,
            "cve_id": vulnerability.cve_id if vulnerability else None,
            "source_url": vulnerability.url if vulnerability else None,
            "component_purl": (component.purl or component.identity_key) if component else None,
            "first_seen_at": finding.first_seen_at.isoformat(),
            "last_seen_at": finding.last_seen_at.isoformat(),
        })
    return {"data": data, "total": len(data)}


def _resolve(session, org_id: str, project: str, version: str):
    project_row = (session.query(models.Project)
                   .filter_by(org_id=org_id, slug=project).one_or_none())
    if project_row is None:
        return None
    return (session.query(models.ProjectVersion)
            .filter_by(project_id=project_row.id, version=version).one_or_none())


def _version(session, project_row, version: str):
    return (session.query(models.ProjectVersion)
            .filter_by(project_id=project_row.id, version=version).one_or_none())

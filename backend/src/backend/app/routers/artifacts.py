"""Artifacts: the exact build an SBOM describes and a deployment runs.

The chain is version → artifact → SBOM receipt → deployment. A version can have
several artifacts, and "in production" is read from deployments, never from a
flag on the version. An artifact with no SBOM says so; it is not silently
"clean".
"""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.versions import pick_version
from backend.app import auth, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/artifacts", tags=["artifacts"])


def _artifact_data(session: Session, artifact: models.Artifact) -> dict:
    version = (session.get(models.ProjectVersion, artifact.project_version_id)
               if artifact.project_version_id else None)
    project = session.get(models.Project, version.project_id) if version else None
    imports = (session.query(models.SbomImport)
               .filter_by(artifact_id=artifact.id).all())
    deployments = (session.query(models.Deployment)
                   .filter_by(org_id=artifact.org_id, artifact_id=artifact.id).all())
    components = 0
    if version is not None:
        components = (session.query(models.VersionComponent)
                      .filter_by(project_version_id=version.id).count())
    return {
        "id": artifact.id, "name": artifact.name, "digest": artifact.digest,
        "digest_algorithm": artifact.digest_algorithm,
        "provenance": artifact.provenance, "source": artifact.source,
        "build_ref": artifact.build_ref,
        "project": project.slug if project else None,
        "version": version.version if version else None,
        "sbom": [{"import_id": row.id, "filename": row.filename,
                  "source": row.source, "components": row.components_received,
                  "imported_at": row.created_at.isoformat()} for row in imports],
        "sbom_present": bool(imports),
        "components_in_version": components,
        "deployments": [{"id": row.id, "name": row.name,
                         "environment": row.environment, "status": row.status}
                        for row in deployments],
        "in_production": any(row.status == "active" and row.environment == "production"
                             for row in deployments),
        "coverage": {
            "sbom": ("version-level SBOM linked"
                     if imports else "no SBOM is linked to this artifact"),
            "components": ("from the version's SBOM" if imports else "unknown"),
            "usage_per_artifact": ("not implemented: component usage is recorded per "
                                   "version, not per artifact"),
        },
    }


@router.get("")
def list_artifacts(project: str | None = Query(default=None),
                   version: str | None = Query(default=None),
                   org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    query = session.query(models.Artifact).filter_by(org_id=org.id)
    rows = query.order_by(models.Artifact.created_at.desc()).all()
    data = []
    for row in rows:
        item = _artifact_data(session, row)
        if project and item["project"] != project:
            continue
        if version and item["version"] != version:
            continue
        data.append(item)
    return {"data": data, "total": len(data)}


class ArtifactIn(BaseModel):
    project: str = Field(min_length=1, max_length=128)
    version: str | None = Field(default=None, max_length=255)
    name: str = Field(min_length=1, max_length=255)
    digest: str | None = Field(default=None, max_length=128)
    provenance: str | None = Field(default=None, max_length=255)
    build_ref: str | None = Field(default=None, max_length=255)
    actor: str = Field(default="system", max_length=255)


@router.post("", status_code=status.HTTP_201_CREATED)
def create_artifact(payload: ArtifactIn = None,
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    project = (session.query(models.Project)
               .filter_by(org_id=org.id, slug=payload.project).one_or_none())
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    version_row = None
    if payload.version:
        version_row = (pick_version(session, project.id, payload.version))
        if version_row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")
    if payload.digest:
        existing = (session.query(models.Artifact)
                    .filter_by(org_id=org.id, digest=payload.digest).one_or_none())
        if existing is not None:
            return {"data": _artifact_data(session, existing), "already_known": True}
    artifact = models.Artifact(
        org_id=org.id, project_version_id=version_row.id if version_row else None,
        name=payload.name, digest=payload.digest,
        digest_algorithm="sha256" if payload.digest else None,
        provenance=payload.provenance, build_ref=payload.build_ref, source="manual")
    session.add(artifact)
    session.flush()
    _audit_log(session, org.id, payload.actor, "artifact.created", "artifact",
               artifact.id, f"{payload.name} ({payload.digest or 'no digest'})")
    session.commit()
    return {"data": _artifact_data(session, artifact), "already_known": False}


@router.get("/{artifact_id}")
def get_artifact(artifact_id: str,
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    artifact = session.get(models.Artifact, artifact_id)
    if artifact is None or artifact.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "artifact not found")
    data = _artifact_data(session, artifact)
    data["authorization"] = ("a deployment pointing here says what runs where; it does "
                             "not authorize testing it")
    return {"data": data}

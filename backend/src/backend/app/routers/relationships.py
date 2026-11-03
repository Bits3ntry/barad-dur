"""BL-010 endpoints: repositories, services, deployments and typed links.

Every link mutation is temporal (removed_at, never a delete) and audited.
Unknown entity ids/types are rejected; duplicates are idempotent ``already_
linked`` responses, so shared assets/projects never create copies.
"""
import datetime as _dt

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1", tags=["relationships"])


def _now() -> _dt.datetime:
    return models.utcnow()


# ─────────────────────────── repositories ───────────────────────────


class RepositoryIn(BaseModel):
    provider: str = Field(default="git", max_length=32)
    name: str = Field(min_length=1, max_length=255)
    remote_url: str = Field(min_length=6, max_length=2048)
    actor: str | None = None


@router.get("/repositories")
def list_repositories(org: models.Organization = Depends(auth.require_org),
                      session: Session = Depends(get_session)):
    rows = (session.query(models.Repository)
            .filter_by(org_id=org.id).all())
    return {"data": [{"id": r.id, "provider": r.provider, "name": r.name,
                      "remote_url": r.remote_url} for r in rows],
            "total": len(rows)}


@router.post("/repositories")
def create_repository(payload: RepositoryIn = None,
                      org: models.Organization = Depends(auth.require_org),
                      session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    existing = (session.query(models.Repository)
                .filter_by(org_id=org.id, remote_url=payload.remote_url).one_or_none())
    if existing is not None:
        return {"data": {"id": existing.id}, "already_known": True}
    repo = models.Repository(org_id=org.id, provider=payload.provider,
                             name=payload.name, remote_url=payload.remote_url)
    session.add(repo)
    session.flush()
    _audit_log(session, org.id, payload.actor or "system", "repository.added",
               "repository", repo.id, payload.remote_url)
    session.commit()
    return {"data": {"id": repo.id}}


class LinkIn(BaseModel):
    relation: str = Field(default="builds", max_length=32)
    actor: str | None = None


def _link_data(link) -> dict:
    """Shape per link model: polymorphic links carry entity_type/entity_id;
    typed association tables carry their own FK names."""
    added_at = getattr(link, "added_at", None)
    if isinstance(link, models.ProjectRepository):
        return {"id": link.id, "project_id": link.project_id,
                "repository_id": link.repository_id, "relation": link.relation,
                "added_at": added_at.isoformat(), "added_by": link.added_by}
    if isinstance(link, models.ServiceProject):
        return {"id": link.id, "service_id": link.service_id,
                "project_id": link.project_id, "relation": link.relation,
                "added_at": added_at.isoformat(), "added_by": link.added_by}
    return {"id": link.id, "entity_type": link.entity_type, "entity_id": link.entity_id,
            "relation": link.relation, "added_at": added_at.isoformat(),
            "added_by": link.added_by}


# ─────────────────────────── services ───────────────────────────


class ServiceIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    runtime: str | None = Field(default=None, max_length=64)
    owner: str | None = None
    actor: str | None = None


@router.get("/services")
def list_services(org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    rows = session.query(models.Service).filter_by(org_id=org.id).all()
    return {"data": [{"id": s.id, "name": s.name, "runtime": s.runtime,
                      "owner": s.owner} for s in rows], "total": len(rows)}


@router.post("/services")
def create_service(payload: ServiceIn = None,
                   org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    existing = (session.query(models.Service)
                .filter_by(org_id=org.id, name=payload.name).one_or_none())
    if existing is not None:
        return {"data": {"id": existing.id}, "already_known": True}
    svc = models.Service(org_id=org.id, name=payload.name,
                         runtime=payload.runtime, owner=payload.owner)
    session.add(svc)
    session.flush()
    _audit_log(session, org.id, payload.actor or "system", "service.added",
               "service", svc.id, payload.name)
    session.commit()
    return {"data": {"id": svc.id}}


# ─────────────────────────── deployments ───────────────────────────


class DeploymentIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    environment: str = Field(default="production", max_length=64)
    service_id: str | None = None
<<<<<<< Updated upstream
    artifact_id: str | None = None
    application_component_id: str | None = None
    status: str = "active"
    deployed_at: str | None = None
=======
>>>>>>> Stashed changes
    actor: str | None = None


@router.get("/deployments")
def list_deployments(org: models.Organization = Depends(auth.require_org),
                     session: Session = Depends(get_session)):
    rows = session.query(models.Deployment).filter_by(org_id=org.id).all()
<<<<<<< Updated upstream
    data = []
    for d in rows:
        artifact = session.get(models.Artifact, d.artifact_id) if d.artifact_id else None
        version = (session.get(models.ProjectVersion, artifact.project_version_id)
                   if artifact and artifact.project_version_id else None)
        data.append({"id": d.id, "name": d.name, "environment": d.environment,
                     "service_id": d.service_id, "status": d.status,
                     "artifact": ({"id": artifact.id, "name": artifact.name,
                                   "digest": artifact.digest} if artifact else None),
                     "version": version.version if version else None})
    return {"data": data, "total": len(data)}
=======
    return {"data": [{"id": d.id, "name": d.name, "environment": d.environment,
                      "service_id": d.service_id} for d in rows], "total": len(rows)}
>>>>>>> Stashed changes


@router.post("/deployments")
def create_deployment(payload: DeploymentIn = None,
                      org: models.Organization = Depends(auth.require_org),
                      session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.service_id is not None:
        service = session.get(models.Service, payload.service_id)
        if service is None or service.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "service not found")
<<<<<<< Updated upstream
    if payload.artifact_id is not None:
        artifact = session.get(models.Artifact, payload.artifact_id)
        if artifact is None or artifact.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "artifact not found")
    if payload.application_component_id is not None:
        component = session.get(models.ApplicationComponent,
                                payload.application_component_id)
        if component is None or component.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                "application component not found")
    if payload.status not in models.DEPLOYMENT_STATUSES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"status must be one of {sorted(models.DEPLOYMENT_STATUSES)}")
    deployed_at = None
    if payload.deployed_at:
        try:
            from datetime import datetime as _dt
            deployed_at = _dt.fromisoformat(payload.deployed_at.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                "deployed_at must be ISO-8601") from None
    dep = models.Deployment(org_id=org.id, service_id=payload.service_id,
                            name=payload.name, environment=payload.environment,
                            artifact_id=payload.artifact_id,
                            application_component_id=payload.application_component_id,
                            status=payload.status, deployed_at=deployed_at,
=======
    dep = models.Deployment(org_id=org.id, service_id=payload.service_id,
                            name=payload.name, environment=payload.environment,
>>>>>>> Stashed changes
                            created_at=_now(), updated_at=_now())
    session.add(dep)
    session.flush()
    _audit_log(session, org.id, payload.actor or "system", "deployment.added",
<<<<<<< Updated upstream
               "deployment", dep.id,
               f"{payload.name} ({payload.environment})"
               + (f" artifact {payload.artifact_id}" if payload.artifact_id else ""))
    session.commit()
    return {"data": {"id": dep.id, "environment": dep.environment,
                     "status": dep.status, "artifact_id": dep.artifact_id}}
=======
               "deployment", dep.id, f"{payload.name} ({payload.environment})")
    session.commit()
    return {"data": {"id": dep.id}}
>>>>>>> Stashed changes


# ─────────────────────── generic typed links ───────────────────────


def _resolve_entity(session, org, entity_type: str, entity_id: str):
    if entity_type == "project":
        entity = session.get(models.Project, entity_id)
    elif entity_type == "service":
        entity = session.get(models.Service, entity_id)
    elif entity_type == "deployment":
        entity = session.get(models.Deployment, entity_id)
    else:
        return None
    if entity is None or getattr(entity, "org_id", None) != org.id:
        return None
    return entity


def _existing_active_link(model, session, org_id: str, **keys):
    query = session.query(model).filter_by(org_id=org_id, removed_at=None, **keys)
    return query.one_or_none()


class ProjectLinkIn(LinkIn):
    repository_id: str | None = None
    remote_url: str | None = None
    provider: str = "git"
    name: str | None = None


@router.post("/projects/{project_id}/repositories")
def link_repository(project_id: str, payload: ProjectLinkIn = None,
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    if payload is None or not (payload.repository_id or payload.remote_url):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "repository_id or remote_url required")
    project = session.get(models.Project, project_id)
    if project is None or project.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    if payload.repository_id:
        repo = session.get(models.Repository, payload.repository_id)
    else:
        repo = (session.query(models.Repository)
                .filter_by(org_id=org.id, remote_url=payload.remote_url).one_or_none())
        if repo is None:
            repo = models.Repository(
                org_id=org.id, provider=payload.provider,
                name=payload.name or payload.remote_url.rsplit("/", 1)[-1],
                remote_url=payload.remote_url)
            session.add(repo)
            session.flush()
    if repo is None or repo.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "repository not found")
    existing = _existing_active_link(
        models.ProjectRepository, session, org.id,
        project_id=project.id, repository_id=repo.id, relation=payload.relation)
    if existing is not None:
        return {"data": _link_data(existing), "already_linked": True}
    link = models.ProjectRepository(
        org_id=org.id, project_id=project.id, repository_id=repo.id,
        relation=payload.relation, added_by=payload.actor)
    session.add(link)
    session.flush()
    _audit_log(session, org.id, payload.actor or "system", "project_repo.linked",
               "repository", repo.id, f"{project.slug}:{payload.relation}")
    session.commit()
    return {"data": _link_data(link)}


class AssetLinkIn(LinkIn):
    entity_type: str
    entity_id: str


@router.post("/assets/{asset_id}/links")
def link_asset(asset_id: str, payload: AssetLinkIn = None,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.entity_type not in ("project", "service", "deployment"):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "entity_type must be project | service | deployment")
    asset = session.get(models.Asset, asset_id)
    if asset is None or asset.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    if payload.entity_id == asset_id and payload.entity_type == "asset":
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "cannot self-link")
    entity = _resolve_entity(session, org, payload.entity_type, payload.entity_id)
    if entity is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "linked entity not found")
    existing = _existing_active_link(
        models.AssetLink, session, org.id, asset_id=asset.id,
        entity_type=payload.entity_type, entity_id=payload.entity_id,
        relation=payload.relation)
    if existing is not None:
        return {"data": _link_data(existing), "already_linked": True}
    link = models.AssetLink(
        org_id=org.id, asset_id=asset.id, entity_type=payload.entity_type,
        entity_id=payload.entity_id, relation=payload.relation,
        added_by=payload.actor)
    session.add(link)
    session.flush()
    _audit_log(session, org.id, payload.actor or "system", "asset.linked",
               "asset", asset.id,
               f"{payload.entity_type}:{payload.entity_id}:{payload.relation}")
    session.commit()
    return {"data": _link_data(link)}


@router.get("/assets/{asset_id}/links")
def list_asset_links(asset_id: str,
                     org: models.Organization = Depends(auth.require_org),
                     session: Session = Depends(get_session)):
    asset = session.get(models.Asset, asset_id)
    if asset is None or asset.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    rows = (session.query(models.AssetLink)
            .filter_by(org_id=org.id, asset_id=asset.id, removed_at=None).all())
    return {"data": [_link_data(r) for r in rows], "total": len(rows)}


class UnlinkIn(BaseModel):
    link_id: str
    actor: str | None = None


@router.delete("/assets/{asset_id}/links/{link_id}")
def unlink_asset(asset_id: str, link_id: str, actor: str = "",
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    asset = session.get(models.Asset, asset_id)
    link = session.get(models.AssetLink, link_id)
    if asset is None or link is None or link.asset_id != asset.id \
            or link.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "link not found")
    if link.removed_at is not None:
        return {"data": _link_data(link), "already_removed": True}
    link.removed_at = _now()
    _audit_log(session, org.id, actor or "system", "asset.unlinked",
               "asset", asset.id,
               f"{link.entity_type}:{link.entity_id}:{link.relation}")
    session.commit()
    return {"data": _link_data(link)}


class FindingContextIn(BaseModel):
    entity_type: str
    entity_id: str
    relation: str = Field(default="observed_in", max_length=32)
    actor: str | None = None


@router.post("/findings/{finding_id}/contexts")
def link_finding_context(finding_id: str, payload: FindingContextIn = None,
                         org: models.Organization = Depends(auth.require_org),
                         session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.entity_type not in ("repository", "service", "deployment", "asset"):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "entity_type must be repository | service | deployment | asset")
    finding = session.get(models.Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    if payload.entity_type == "repository":
        entity = session.get(models.Repository, payload.entity_id)
    else:
        entity = _resolve_entity(session, org, payload.entity_type, payload.entity_id)
    if entity is None or getattr(entity, "org_id", None) != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "context entity not found")
    existing = _existing_active_link(
        models.FindingContext, session, org.id, finding_id=finding.id,
        entity_type=payload.entity_type, entity_id=payload.entity_id,
        relation=payload.relation)
    if existing is not None:
        return {"data": _link_data(existing), "already_linked": True}
    link = models.FindingContext(
        org_id=org.id, finding_id=finding.id, entity_type=payload.entity_type,
        entity_id=payload.entity_id, relation=payload.relation,
        added_by=payload.actor)
    session.add(link)
    session.flush()
    _audit_log(session, org.id, payload.actor or "system", "finding.context_linked",
               "finding", finding.id,
               f"{payload.entity_type}:{payload.entity_id}")
    session.commit()
    return {"data": _link_data(link)}


@router.get("/findings/{finding_id}/contexts")
def list_finding_contexts(finding_id: str,
                          org: models.Organization = Depends(auth.require_org),
                          session: Session = Depends(get_session)):
    finding = session.get(models.Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    rows = (session.query(models.FindingContext)
            .filter_by(org_id=org.id, finding_id=finding.id, removed_at=None).all())
    return {"data": [_link_data(r) for r in rows], "total": len(rows)}


@router.delete("/findings/{finding_id}/contexts/{context_id}")
def unlink_finding_context(finding_id: str, context_id: str, actor: str = "",
                           org: models.Organization = Depends(auth.require_org),
                           session: Session = Depends(get_session)):
    link = session.get(models.FindingContext, context_id)
    if link is None or link.finding_id != finding_id or link.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "context not found")
    if link.removed_at is not None:
        return {"data": _link_data(link), "already_removed": True}
    link.removed_at = _now()
    _audit_log(session, org.id, actor or "system", "finding.context_unlinked",
               "finding", finding_id, f"{link.entity_type}:{link.entity_id}")
    session.commit()
    return {"data": _link_data(link)}


@router.get("/findings/{finding_id}/occurrences")
def list_occurrences(finding_id: str,
                     org: models.Organization = Depends(auth.require_org),
                     session: Session = Depends(get_session)):
    """Sighting history for one finding (BL-040): the finding row dedupes the
    weakness; each distinct sighting (context/tool/source/version) is kept."""
    finding = session.get(models.Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    rows = (session.query(models.Occurrence)
            .filter_by(org_id=org.id, finding_id=finding.id)
            .order_by(models.Occurrence.seen_at.desc()).all())
    return {"data": [{
        "id": r.id, "seen_at": r.seen_at.isoformat(),
        "project_version_id": r.project_version_id, "ci_run_id": r.ci_run_id,
        "tool": r.tool, "source": r.source, "evidence": r.evidence,
    } for r in rows], "total": len(rows)}

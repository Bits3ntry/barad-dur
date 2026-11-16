"""Business context: the crown jewels are components — AUREA > Backend.

A project is a container (it holds the backend, the web, the fx service). What the
business runs, and what a compromise actually takes down, is one of those services.
So the judgement lives on `application_components`, and everything else hangs off it:
the deployments across environments, the assets those deployments reach, the
observations behind them.

Only components somebody registered are listed. An asset nobody filed appears in
Discovery → Assets; a finding is attributed to its project today, which the screen
says out loud instead of pretending a component owns it.
"""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app import auth, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/business-context", tags=["business-context"])

LEVELS = ("crown", "high", "normal", "low")
OPEN_STATUSES = ("open", "acknowledged")
OBSERVED_KINDS = ("port", "web_path", "technology", "certificate")


def _level(value: str | None) -> str:
    return value if value in LEVELS else "unclassified"


def _asset_index(session: Session, org_id: str) -> dict[str, set[str]]:
    """component id → the assets it carries, directly or through a deployment."""
    index: dict[str, set[str]] = {}
    links = (session.query(models.AssetLink)
             .filter(models.AssetLink.org_id == org_id,
                     models.AssetLink.removed_at.is_(None)).all())
    by_entity: dict[tuple, set[str]] = {}
    for link in links:
        by_entity.setdefault((link.entity_type, link.entity_id), set()).add(link.asset_id)
    deployments = (session.query(models.Deployment)
                   .filter(models.Deployment.org_id == org_id).all())
    for deployment in deployments:
        if not deployment.application_component_id:
            continue
        index.setdefault(deployment.application_component_id, set()).update(
            by_entity.get(("deployment", deployment.id), set()))
    for (entity_type, entity_id), assets in by_entity.items():
        if entity_type == "application_component":
            index.setdefault(entity_id, set()).update(assets)
    return index


def _observed_assets(session: Session, org_id: str, asset_ids: set[str]) -> set[str]:
    if not asset_ids:
        return set()
    rows = (session.query(models.Observation.asset_id)
            .filter(models.Observation.org_id == org_id,
                    models.Observation.asset_id.in_(asset_ids),
                    models.Observation.kind.in_(OBSERVED_KINDS))
            .distinct().all())
    return {row[0] for row in rows}


def _row(component: models.ApplicationComponent, project: models.Project | None,
         deployments: list[models.Deployment], assets: set[str],
         observed: set[str], project_findings: int) -> dict:
    environments = sorted({item.environment for item in deployments if item.environment})
    return {
        "id": component.id,
        "name": component.name,
        "slug": component.slug,
        "kind": component.kind,
        "project_id": component.project_id,
        "project_slug": project.slug if project else None,
        "project_name": project.name if project else None,
        "criticality": _level(component.criticality),
        "business_service": component.business_service,
        "reason": component.criticality_reason,
        "set_by": component.criticality_set_by,
        "set_at": component.criticality_updated_at.isoformat()
        if component.criticality_updated_at else None,
        "deployments": len(deployments),
        "environments": environments,
        "assets": len(assets),
        "observed_assets": len(observed),
        # Attribution, said honestly: findings are filed against the project today.
        "project_findings_open": project_findings,
    }


@router.get("")
def business_context(
        criticality: str | None = Query(default=None,
                                         description="crown | high | normal | low | unclassified"),
        project: str | None = Query(default=None, description="project slug"),
        q: str | None = Query(default=None, description="component name or slug"),
        all_components: bool = Query(default=False, alias="all",
                                     description="include components nobody designated"),
        limit: int = Query(default=200, ge=1, le=500),
        offset: int = Query(default=0, ge=0),
        org: models.Organization = Depends(auth.require_org),
        session: Session = Depends(get_session)):
    """Registered components with their business level, and the facts behind it."""
    query = (session.query(models.ApplicationComponent)
             .filter(models.ApplicationComponent.org_id == org.id))
    # The screen shows what somebody designated. The whole registry is one click
    # away through the candidate search, never a wall of undecided rows.
    if not all_components:
        query = query.filter(models.ApplicationComponent.criticality.isnot(None))
    if criticality == "unclassified":
        query = query.filter(models.ApplicationComponent.criticality.is_(None))
    elif criticality:
        if criticality not in LEVELS:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"criticality must be one of {list(LEVELS) + ['unclassified']}")
        query = query.filter(models.ApplicationComponent.criticality == criticality)
    if project:
        project_row = (session.query(models.Project)
                       .filter_by(org_id=org.id, slug=project).one_or_none())
        if project_row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
        query = query.filter(models.ApplicationComponent.project_id == project_row.id)
    if q:
        needle = f"%{q.strip()}%"
        query = query.filter(models.ApplicationComponent.name.ilike(needle)
                             | models.ApplicationComponent.slug.ilike(needle))
    total = query.count()
    rows = (query.order_by(models.ApplicationComponent.criticality.is_(None),
                           models.ApplicationComponent.name)
            .offset(offset).limit(limit).all())

    projects = {row.id: row for row in
                session.query(models.Project).filter_by(org_id=org.id).all()}
    deployments: dict[str, list[models.Deployment]] = {}
    for deployment in (session.query(models.Deployment)
                       .filter(models.Deployment.org_id == org.id).all()):
        if deployment.application_component_id:
            deployments.setdefault(deployment.application_component_id, []).append(deployment)
    assets_by_component = _asset_index(session, org.id)
    project_findings = dict(session.query(models.Finding.project_id,
                                          func.count(models.Finding.id))
                            .filter(models.Finding.org_id == org.id,
                                    models.Finding.status.in_(OPEN_STATUSES),
                                    models.Finding.project_id.isnot(None))
                            .group_by(models.Finding.project_id).all())

    data = []
    for component in rows:
        assets = assets_by_component.get(component.id, set())
        data.append(_row(component, projects.get(component.project_id),
                         deployments.get(component.id, []), assets,
                         _observed_assets(session, org.id, assets),
                         project_findings.get(component.project_id, 0)))

    summary = {level: 0 for level in LEVELS}
    summary["unclassified"] = 0
    for (value,) in (session.query(models.ApplicationComponent.criticality)
                     .filter(models.ApplicationComponent.org_id == org.id).all()):
        summary[_level(value)] += 1
    # `components` is what somebody designated; the unclassified count is not a
    # designation, and summing every level made "5 of 5 designated" with one jewel.
    summary["components"] = sum(summary[level] for level in LEVELS)
    summary["registered"] = (session.query(models.ApplicationComponent)
                             .filter(models.ApplicationComponent.org_id == org.id)
                             .count())
    summary["jewel_assets"] = sum(
        len(assets_by_component.get(row[0], set())) for row in
        (session.query(models.ApplicationComponent.id)
         .filter(models.ApplicationComponent.org_id == org.id,
                 models.ApplicationComponent.criticality == "crown").all()))

    # The group header the screen prints: a project is context, not the judgement.
    grouped = [{"slug": row.slug, "name": row.name,
                "findings_open": project_findings.get(row.id, 0)}
               for row in projects.values() if row.id in {c.project_id for c in rows}]

    return {"data": data, "total": total, "limit": limit, "offset": offset,
            "summary": summary, "projects": grouped,
            "note": ("Only registered components are listed. Findings are attributed "
                     "to the project today, not to the component: the screen says "
                     "so instead of splitting a number nobody measured.")}


@router.get("/candidates")
def candidates(q: str | None = Query(default=None, description="name, slug or project"),
               limit: int = Query(default=20, ge=1, le=100),
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """Components that exist and carry no level yet: the designation picker.

    Searching here is how a jewel gets chosen — you look for the service you run,
    not for one of 274 domains. Rows already designated are not candidates.
    """
    query = (session.query(models.ApplicationComponent, models.Project)
             .join(models.Project,
                   models.Project.id == models.ApplicationComponent.project_id)
             .filter(models.ApplicationComponent.org_id == org.id,
                     models.ApplicationComponent.criticality.is_(None)))
    if q and q.strip():
        needle = f"%{q.strip()}%"
        query = query.filter(models.ApplicationComponent.name.ilike(needle)
                             | models.ApplicationComponent.slug.ilike(needle)
                             | models.Project.name.ilike(needle)
                             | models.Project.slug.ilike(needle))
    rows = (query.order_by(models.Project.name, models.ApplicationComponent.name)
            .limit(limit).all())
    deployments = dict(session.query(models.Deployment.application_component_id,
                                     func.count(models.Deployment.id))
                       .filter(models.Deployment.org_id == org.id,
                               models.Deployment.application_component_id.isnot(None))
                       .group_by(models.Deployment.application_component_id).all())
    return {"data": [{"id": component.id, "name": component.name,
                      "slug": component.slug, "kind": component.kind,
                      "project_slug": project.slug, "project_name": project.name,
                      "deployments": deployments.get(component.id, 0)}
                     for component, project in rows],
            "total": len(rows)}


class CriticalityIn(BaseModel):
    criticality: str | None = Field(default=None, max_length=16)
    business_service: str | None = Field(default=None, max_length=255)
    reason: str | None = Field(default=None, max_length=2000)
    actor: str = Field(default="console", max_length=255)


@router.patch("/components/{component_id}")
def set_criticality(component_id: str, payload: CriticalityIn = None,
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    """Designate (or withdraw) one component's business level.

    `criticality: null` is a legitimate value: it returns the component to
    `unclassified`, which is what a withdrawn judgement looks like.
    """
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    component = session.get(models.ApplicationComponent, component_id)
    if component is None or component.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "component not found")
    level = payload.criticality
    if level in ("", "unclassified"):
        level = None
    if level is not None and level not in LEVELS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"criticality must be one of {list(LEVELS) + ['unclassified']}")
    previous = component.criticality or "unclassified"
    component.criticality = level
    if payload.business_service is not None:
        component.business_service = payload.business_service.strip() or None
    if payload.reason is not None:
        component.criticality_reason = payload.reason.strip() or None
    component.criticality_set_by = payload.actor
    component.criticality_updated_at = models.utcnow()
    project = session.get(models.Project, component.project_id)
    _audit_log(session, org.id, payload.actor, "component.criticality_set",
               "application_component", component.id,
               f"{project.slug if project else '?'}/{component.slug}: "
               f"{previous} -> {_level(level)}")
    session.commit()

    deployments = (session.query(models.Deployment)
                   .filter_by(org_id=org.id,
                              application_component_id=component.id).all())
    assets = _asset_index(session, org.id).get(component.id, set())
    findings = dict(session.query(models.Finding.project_id, func.count(models.Finding.id))
                    .filter(models.Finding.org_id == org.id,
                            models.Finding.status.in_(OPEN_STATUSES),
                            models.Finding.project_id.isnot(None))
                    .group_by(models.Finding.project_id).all())
    return {"data": _row(component, project, deployments, assets,
                         _observed_assets(session, org.id, assets),
                         findings.get(component.project_id, 0)),
            "changed": previous != _level(level)}

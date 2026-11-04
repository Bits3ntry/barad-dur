"""Declarative inventory: projects, components, code, environments and probes.

This is the "what do we have?" half of the CTEM cycle, and it never needs a scan.
A team records AUREA → components (backend, web, iOS) → repositories →
environments (DEV/PRE/PRO) with the version running there, plus the domains and
apps it already knows about. Discovery adds candidates; cataloguing them is an
explicit act that grants nothing.

Rules that hold across this module:

* **Declaring is not scanning.** A deployment row says "PRO runs Backend 1.7.4";
  it never implies an artifact was analysed, and it grants no authorization.
* **A version can be written by hand.** `version_label` exists so inventory works
  before the first import. A probe or an import may confirm it later and
  `source` records which one it was.
* **A health probe is a GET.** It reads JSON from the deployment's own endpoint,
  never posts, and its token is sealed and never returned.
* **Assets are shared, never copied.** Cataloguing links an asset to a project;
  the same asset can serve two projects without duplicating the row.
"""
import json
import re
import urllib.error
import urllib.request
from datetime import datetime, timedelta

from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app import auth, auth_local, models, scm_client
from backend.app import secrets as secret_store
from backend.app.db import get_session
from backend.app.projects import by_ref
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1", tags=["inventory-projects"])

EXPOSURES = {"public", "internal", "unknown"}
SOURCES = {"manual", "pipeline", "health", "discovery"}
PROBE_TIMEOUT = 8.0
VERSION_KEYS = ("version", "app_version", "application_version", "release",
                "release_version", "build_version")


def _iso(value: datetime | None) -> str | None:
    return value.isoformat() if value else None


def _slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")
    return slug[:120] or "project"


def _project_row(session: Session, org: models.Organization, ref: str) -> models.Project:
    row = by_ref(session, org.id, ref)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    return row


# ── serialisation ────────────────────────────────────────────────────────────

def _repository_data(row: models.Repository, components: list[str] | None = None) -> dict:
    return {"id": row.id, "name": row.name, "remote_url": row.remote_url,
            "provider": row.provider, "last_commit_sha": row.last_commit_sha,
            "components": components or []}


def _next_due(row: models.HealthProbe) -> datetime | None:
    """When the tick will pick this probe again; None means "manual only".

    `interval_minutes = 0` is a deliberate "check when I press the button", so a
    probe without an interval must never look overdue in the console.
    """
    if not row.enabled or not row.interval_minutes:
        return None
    if row.last_run_at is None:
        return models.utcnow()
    return auth_local.ensure_aware(row.last_run_at) + timedelta(
        minutes=row.interval_minutes)


def _probe_data(row: models.HealthProbe | None) -> dict | None:
    if row is None:
        return None
    return {"id": row.id, "url": row.url, "version_path": row.version_path,
            "status_path": row.status_path, "enabled": bool(row.enabled),
            "interval_minutes": row.interval_minutes,
            "token_set": bool(row.token_cipher),
            "last_run_at": _iso(row.last_run_at), "last_ok_at": _iso(row.last_ok_at),
            "next_due_at": _iso(_next_due(row)),
            "last_error": row.last_error}


def _deployment_data(row: models.Deployment, component_name: str | None = None,
                     probe: models.HealthProbe | None = None) -> dict:
    return {"id": row.id, "name": row.name, "environment": row.environment,
            "component_id": row.application_component_id,
            "component": component_name,
            "version_id": row.version_id,
            "version_label": row.version_label, "source": row.source,
            "exposure": row.exposure, "requires_auth": bool(row.requires_auth),
            "status": row.status,
            "deployed_at": _iso(row.deployed_at),
            "last_checked_at": _iso(row.last_checked_at),
            "last_check_status": row.last_check_status,
            "last_check_error": row.last_check_error,
            "probe": _probe_data(probe)}


def _asset_data(row: models.Asset, component: str | None = None,
                deployment: dict | None = None) -> dict:
    return {"id": row.id, "type": row.type, "value": row.value,
            "source": row.source, "owner": row.owner,
            "classification_status": row.classification_status,
            "component": component,
            "deployment": deployment,
            "deployment_id": (deployment or {}).get("id"),
            "discovered_at": _iso(row.discovered_at),
            "last_seen_at": _iso(row.last_seen_at),
            "notes": row.notes,
            "detail": row.detail}


ASSET_TYPES = {"domain", "subdomain", "ip", "url", "api", "mobile_app"}


def _project_assets(session: Session, org_id: str,
                    project: models.Project) -> list[dict]:
    """Assets filed under the project, plus the component each one belongs to.

    A component is optional on purpose: a WordPress site is a domain with no code
    component in the inventory, and it still has to be owned by the project.
    """
    rows = (session.query(models.Asset)
            .filter_by(org_id=org_id, project_id=project.id)
            .order_by(models.Asset.type, models.Asset.value).all())
    if not rows:
        return []
    component_names = {row.id: row.name for row in
                       (session.query(models.ApplicationComponent)
                        .filter_by(project_id=project.id).all())}
    asset_ids = [row.id for row in rows]
    links = (session.query(models.AssetLink)
             .filter(models.AssetLink.org_id == org_id,
                     models.AssetLink.asset_id.in_(asset_ids),
                     models.AssetLink.removed_at.is_(None)).all())
    by_asset_component: dict[str, str] = {}
    by_asset_deployment: dict[str, str] = {}
    link_by_asset: dict[str, str] = {}
    for link in links:
        if link.entity_type == "application_component":
            name = component_names.get(link.entity_id)
            if name:
                by_asset_component[link.asset_id] = name
        elif link.entity_type == "deployment":
            by_asset_deployment[link.asset_id] = link.entity_id
            link_by_asset[link.asset_id] = link.id

    # An asset served by an environment is what tells DEV from PRO in URLs.
    deployment_rows: dict[str, models.Deployment] = {}
    if by_asset_deployment:
        deployment_rows = {row.id: row for row in
                           (session.query(models.Deployment)
                            .filter(models.Deployment.org_id == org_id,
                                    models.Deployment.id.in_(
                                        set(by_asset_deployment.values()))).all())}
    return [_asset_data(
        row,
        by_asset_component.get(row.id),
        _deployment_ref(deployment_rows.get(by_asset_deployment.get(row.id)),
                        component_names,
                        link_by_asset.get(row.id)),
    ) for row in rows]


def _deployment_ref(row: models.Deployment | None,
                    component_names: dict[str, str],
                    link_id: str | None = None) -> dict | None:
    """Small, self-contained reference so the UI can label a row without joins."""
    if row is None:
        return None
    return {"id": row.id, "environment": row.environment,
            "component": component_names.get(row.application_component_id or ""),
            "version_label": row.version_label, "link_id": link_id}


def _version_row(session: Session, project: models.Project, label: str | None,
                 component_id: str | None) -> models.ProjectVersion | None:
    value = (label or "").strip()
    if not value:
        return None
    return (session.query(models.ProjectVersion)
            .filter_by(project_id=project.id, version=value,
                       component_id=component_id).one_or_none())


def _ensure_version(session: Session, project: models.Project, label: str | None,
                    component_id: str | None = None) -> models.ProjectVersion | None:
    """A label the team declares is a version of that component.

    SBOM imports attach to a `project_versions` row, so declaring `1.7.4` in PRO
    must not create a label nobody can upload an SBOM against.
    """
    value = (label or "").strip()
    if not value:
        return None
    row = _version_row(session, project, value, component_id)
    if row is None:
        row = models.ProjectVersion(project_id=project.id, component_id=component_id,
                                    version=value)
        session.add(row)
        session.flush()
    return row


def _version_summary(session: Session, project: models.Project,
                     label: str | None, component_id: str | None = None) -> dict | None:
    """Read-only: reading the inventory never invents a version row."""
    value = (label or "").strip()
    if not value:
        return None
    row = _version_row(session, project, value, component_id)
    if row is None:
        return {"project_version_id": None, "version": value,
                "component_id": component_id, "sbom_imports": 0, "baseline": False}
    imports = (session.query(models.SbomImport)
               .filter_by(project_version_id=row.id).count())
    baseline = (session.query(models.SbomBaseline)
                .filter_by(project_version_id=row.id).one_or_none())
    return {"project_version_id": row.id, "version": row.version,
            "component_id": row.component_id,
            "sbom_imports": imports, "baseline": baseline is not None}


def _project_counts(session: Session, project: models.Project) -> dict:
    components = (session.query(models.ApplicationComponent)
                  .filter_by(project_id=project.id).count())
    deployments = (session.query(models.Deployment)
                   .join(models.ApplicationComponent,
                         models.Deployment.application_component_id
                         == models.ApplicationComponent.id)
                   .filter(models.ApplicationComponent.project_id == project.id,
                           models.Deployment.retired_at.is_(None)).count())
    assets = session.query(models.Asset).filter_by(project_id=project.id).count()
    repos = (session.query(models.Repository)
             .join(models.ProjectRepository,
                   models.ProjectRepository.repository_id == models.Repository.id)
             .filter(models.ProjectRepository.project_id == project.id,
                     models.ProjectRepository.removed_at.is_(None)).count())
    environments = [row[0] for row in
                    session.query(models.Deployment.environment)
                    .join(models.ApplicationComponent,
                          models.Deployment.application_component_id
                          == models.ApplicationComponent.id)
                    .filter(models.ApplicationComponent.project_id == project.id)
                    .distinct().all()]
    return {"components": components, "deployments": deployments, "assets": assets,
            "repositories": repos, "environments": sorted(environments)}


@router.get("/projects")
def list_projects(org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    rows = (session.query(models.Project)
            .filter_by(org_id=org.id).order_by(models.Project.name).all())
    data = []
    for project in rows:
        # Newest first: every screen defaults to the first entry, and defaulting
        # to the oldest version is how an analysed project opened on an empty one.
        versions = (session.query(models.ProjectVersion)
                    .filter_by(project_id=project.id)
                    .order_by(models.ProjectVersion.created_at.desc()).all())
        data.append({"id": project.id, "name": project.name, "slug": project.slug,
                     "group": project.group_name,
                     "description": project.description,
                     "owner": project.owner,
                     "versions": [v.version for v in versions],
                     "counts": _project_counts(session, project)})
    return {"data": data, "total": len(data)}


class ProjectIn(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    slug: str | None = Field(default=None, max_length=120)
    group: str | None = Field(default=None, max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    owner: str | None = Field(default=None, max_length=255)
    actor: str = Field(default="console", max_length=320)


@router.post("/projects")
def create_project(payload: ProjectIn = None,
                   org: models.Organization = Depends(auth.require_writer),
                   session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    slug = (payload.slug or _slugify(payload.name)).strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", slug or ""):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "slug may only contain lowercase letters, digits and dashes")
    if (session.query(models.Project)
            .filter_by(org_id=org.id, slug=slug).first()):
        raise HTTPException(status.HTTP_409_CONFLICT, "project slug already exists")
    row = models.Project(org_id=org.id, name=payload.name.strip(), slug=slug,
                         group_name=(payload.group or "").strip() or None,
                         description=(payload.description or "").strip() or None,
                         owner=(payload.owner or "").strip() or None)
    session.add(row)
    session.flush()
    _audit_log(session, org.id, payload.actor, "inventory.project_created",
               "project", row.id, f"{row.name} ({row.slug})")
    session.commit()
    return {"data": {"id": row.id, "name": row.name, "slug": row.slug,
                     "group": row.group_name, "description": row.description,
                     "owner": row.owner, "versions": [],
                     "counts": {"components": 0, "deployments": 0, "assets": 0,
                                "repositories": 0, "environments": []}}}


@router.get("/projects/{ref}/inventory")
def project_inventory(ref: str,
                      org: models.Organization = Depends(auth.require_org),
                      session: Session = Depends(get_session)):
    project = _project_row(session, org, ref)
    components = (session.query(models.ApplicationComponent)
                  .filter_by(project_id=project.id)
                  .order_by(models.ApplicationComponent.name).all())
    component_by_id = {row.id: row for row in components}

    links = (session.query(models.ComponentRepository)
             .filter_by(org_id=org.id)
             .filter(models.ComponentRepository.removed_at.is_(None)).all())
    repositories = {row.id: row for row in
                    (session.query(models.Repository).filter_by(org_id=org.id).all())}
    repos_by_component: dict[str, list[dict]] = {}
    for link in links:
        repo = repositories.get(link.repository_id)
        if repo is None or link.component_id not in component_by_id:
            continue
        repos_by_component.setdefault(link.component_id, []).append(
            _repository_data(repo))

    deployments = (session.query(models.Deployment)
                   .filter(models.Deployment.org_id == org.id,
                           models.Deployment.application_component_id.in_(
                               list(component_by_id) or [""]))
                   .order_by(models.Deployment.environment,
                             models.Deployment.name).all())
    probes = {row.deployment_id: row for row in
              (session.query(models.HealthProbe).filter_by(org_id=org.id).all())}

    def component_name(component_id: str | None) -> str | None:
        row = component_by_id.get(component_id) if component_id else None
        return row.name if row is not None else None

    deployment_rows = [_deployment_data(row,
                                        component_name(row.application_component_id),
                                        probes.get(row.id))
                       for row in deployments]

    deployments_by_component: dict[str, list[dict]] = {}
    environments: dict[str, list[dict]] = {}
    for row in deployment_rows:
        deployments_by_component.setdefault(row["component_id"], []).append(row)
        environments.setdefault(row["environment"], []).append(row)

    component_rows = []
    for component in components:
        component_deployments = deployments_by_component.get(component.id, [])
        versions = sorted({d["version_label"] for d in component_deployments
                           if d["version_label"]})
        component_rows.append({
            "id": component.id, "name": component.name, "slug": component.slug,
            "kind": component.kind, "description": component.description,
            "repositories": repos_by_component.get(component.id, []),
            "deployments": component_deployments, "versions": versions})

    assets = _project_assets(session, org.id, project)
    domains_by_deployment: dict[str, list[str]] = {}
    for asset in assets:
        if asset.get("deployment_id"):
            domains_by_deployment.setdefault(asset["deployment_id"], []).append(
                asset["value"])
    version_cache: dict[tuple, dict | None] = {}
    for row in deployment_rows:
        row["domains"] = domains_by_deployment.get(row["id"], [])
        key = (row.get("version_label") or "", row.get("component_id"))
        if key not in version_cache:
            version_cache[key] = _version_summary(session, project, key[0], key[1])
        row["sbom"] = version_cache[key]

    project_repos = (session.query(models.Repository)
                     .join(models.ProjectRepository,
                           models.ProjectRepository.repository_id
                           == models.Repository.id)
                     .filter(models.ProjectRepository.project_id == project.id,
                             models.ProjectRepository.removed_at.is_(None)).all())
    linked_repo_ids = {row["id"] for rows in repos_by_component.values()
                       for row in rows}
    # Newest first: the reader wants the last builds, not the whole history.
    version_rows = (session.query(models.ProjectVersion)
                    .filter_by(project_id=project.id)
                    .order_by(models.ProjectVersion.created_at.desc(),
                              models.ProjectVersion.version.desc()).all())
    project_versions = [row.version for row in version_rows]
    imports_by_version = dict(
        (version_id, count) for version_id, count
        in (session.query(models.SbomImport.project_version_id,
                          func.count(models.SbomImport.id))
            .filter(models.SbomImport.project_version_id.in_(
                [row.id for row in version_rows] or [""]))
            .group_by(models.SbomImport.project_version_id).all()))
    baselines = {row.project_version_id for row in
                 (session.query(models.SbomBaseline)
                  .filter(models.SbomBaseline.project_version_id.in_(
                      [row.id for row in version_rows] or [""])).all())}
    return {"data": {
        "project": {"id": project.id, "name": project.name, "slug": project.slug,
                    "versions": project_versions,
                    "group": project.group_name,
                    "description": project.description,
                    "owner": project.owner,
                    "counts": _project_counts(session, project)},
        "components": component_rows,
        "repositories": [_repository_data(row) for row in project_repos],
        "unlinked_repositories": [_repository_data(row) for row in project_repos
                                  if row.id not in linked_repo_ids],
        "versions": [{
            "id": row.id, "version": row.version,
            "component_id": row.component_id,
            "component": component_name(row.component_id),
            "sbom_imports": imports_by_version.get(row.id, 0),
            "baseline": row.id in baselines,
            "deployments": [
                {"component": dep["component"], "environment": dep["environment"],
                 "deployment_id": dep["id"]}
                for dep in deployment_rows if dep["version_id"] == row.id],
        } for row in version_rows],
        "deployments": deployment_rows,
        "environments": [{"name": name, "deployments": rows}
                         for name, rows in sorted(environments.items())],
        "assets": assets,
    }}


class ComponentIn(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    kind: str = Field(default="backend", max_length=24)
    description: str | None = Field(default=None, max_length=2000)
    actor: str = Field(default="console", max_length=320)


COMPONENT_KINDS = {"backend", "frontend", "web", "ios", "android", "worker",
                   "service", "library", "infrastructure", "other"}


@router.get("/projects/{ref}/verification")
def project_verification(ref: str,
                         principal: str = Query(default="console", max_length=255),
                         org: models.Organization = Depends(auth.require_org),
                         session: Session = Depends(get_session)):
    """May we collect this host, and what did we last see?

    Permission and scope are different ledgers and this route answers only one of
    them:

    * **allowed** — the grant decision for the exact capability and tool the
      collector uses. A grant is permission to run a test; it does not require
      the host to be inside the declared scope, which is the universe automated
      cycles sweep;
    * **excluded** — an explicit exclusion, which wins over every grant and is
      the only scope-side rule that changes this answer;
    * **observed** — the newest snapshot with its timestamp. No snapshot means
      "never observed" — never "clean", and never "unreachable".

    A read model on purpose: the console renders it instead of joining tables.
    """
    from backend.app import authorization

    project = _project_row(session, org, ref)
    assets = _project_assets(session, org.id, project)
    asset_ids = [row["id"] for row in assets]

    def iso(value):
        """SQLite hands back naive datetimes; an ISO string without an offset is
        read as local time by the browser and lands an hour off."""
        if value is None:
            return None
        if value.tzinfo is None:
            from datetime import timezone
            value = value.replace(tzinfo=timezone.utc)
        return value.isoformat()

    def permission(capability: str, tool: str, target_type: str, value: str,
                   environment: str | None) -> dict:
        decision = authorization.authorize(
            session, org.id, principal, capability,
            [{"type": target_type, "value": value}], tool=tool,
            environment=environment)
        grant = None
        exclusion = None
        matched = decision.get("matched") or []
        if matched and matched[0] == "grant":
            row = session.get(models.ScanGrant, matched[1])
            if row is not None:
                grant = {"id": row.id,
                         "capabilities": [c for c in row.capabilities.split(",") if c],
                         "tools": [t for t in (row.tools or "").split(",") if t],
                         "environment": row.environment,
                         "valid_until": iso(row.valid_until)}
        elif matched and matched[0] == "exclusion":
            row = session.get(models.ScopeExclusion, matched[1])
            if row is not None:
                exclusion = {"id": row.id, "type": row.target_type,
                             "value": row.value, "reason": row.reason}
        return {"allowed": decision["decision"] != "deny",
                "reason": decision["reason"],
                "grant": grant,
                "exclusion": exclusion,
                "excluded": decision["reason"].startswith("explicit exclusion")}

    latest: dict[str, models.AssetSnapshot] = {}
    if asset_ids:
        for snap in (session.query(models.AssetSnapshot)
                     .filter(models.AssetSnapshot.org_id == org.id,
                             models.AssetSnapshot.asset_id.in_(asset_ids))
                     .order_by(models.AssetSnapshot.observed_at.desc()).all()):
            latest.setdefault(snap.asset_id, snap)

    now = models.utcnow()
    rows = []
    for asset in assets:
        target_type = ("domain" if asset["type"] in {"domain", "subdomain"}
                       else asset["type"])
        snap = latest.get(asset["id"])
        observation = None
        if snap is not None:
            try:
                payload = json.loads(snap.data or "{}")
            except ValueError:
                payload = {}
            dns = payload.get("dns") or {}
            tls = payload.get("tls") or None
            observed_at = snap.observed_at
            if observed_at is not None and observed_at.tzinfo is None:
                from datetime import timezone
                observed_at = observed_at.replace(tzinfo=timezone.utc)
            observation = {
                "observed_at": iso(observed_at),
                "source": snap.source,
                "age_days": (max(0, (now - observed_at).days)
                             if observed_at is not None else None),
                "ipv4": len(dns.get("ipv4") or []),
                "ipv6": len(dns.get("ipv6") or []),
                "tls": None if not tls else {
                    "version": tls.get("tls_version"),
                    "not_after": tls.get("not_after"),
                    "error": tls.get("error"),
                },
            }
        environment = (asset.get("deployment") or {}).get("environment")
        rows.append({
            "id": asset["id"], "value": asset["value"], "type": asset["type"],
            "notes": asset.get("notes"),
            "component": asset.get("component"),
            "environment": environment,
            "deployment_id": asset.get("deployment_id"),
            "permissions": {
                "passive_discovery": permission(
                    "passive_discovery", "dns-collector", target_type,
                    asset["value"], environment),
                "active_verification": permission(
                    "active_verification", "tls-probe", target_type,
                    asset["value"], environment),
            },
            "observation": observation,
        })

    component_ids = [row.id for row in
                     (session.query(models.ApplicationComponent)
                      .filter_by(project_id=project.id).all())]
    probes = {row.deployment_id: row for row in
              (session.query(models.HealthProbe).filter_by(org_id=org.id).all())}
    deployment_rows = []
    if component_ids:
        for row in (session.query(models.Deployment)
                    .filter(models.Deployment.org_id == org.id,
                            models.Deployment.application_component_id.in_(
                                component_ids))
                    .order_by(models.Deployment.environment,
                              models.Deployment.name).all()):
            probe = probes.get(row.id)
            deployment_rows.append({
                "id": row.id, "environment": row.environment, "name": row.name,
                "version_label": row.version_label, "exposure": row.exposure,
                "last_checked_at": iso(row.last_checked_at),
                "last_check_status": row.last_check_status,
                "last_check_error": row.last_check_error,
                "probe": None if probe is None else {
                    "configured": bool(probe.enabled),
                    "url": probe.url,
                    "last_ok_at": iso(probe.last_ok_at),
                    "last_error": probe.last_error,
                },
            })

    summary = {
        "assets": len(rows),
        "authorized": sum(1 for row in rows
                          if row["permissions"]["passive_discovery"]["allowed"]),
        "observed": sum(1 for row in rows if row["observation"]),
        "never_observed": sum(1 for row in rows if not row["observation"]),
        "stale": sum(1 for row in rows if row["observation"]
                     and (row["observation"]["age_days"] or 0) > 30),
        "excluded": sum(1 for row in rows
                        if row["permissions"]["passive_discovery"]["excluded"]),
        "deployments": len(deployment_rows),
        "probed": sum(1 for row in deployment_rows
                      if row["probe"] and row["probe"]["configured"]),
    }
    return {"data": {"project": {"id": project.id, "slug": project.slug,
                                 "name": project.name},
                     "principal": principal, "summary": summary,
                     "assets": rows, "deployments": deployment_rows}}


@router.post("/projects/{ref}/components")
def create_component(ref: str, payload: ComponentIn = None,
                     org: models.Organization = Depends(auth.require_writer),
                     session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    project = _project_row(session, org, ref)
    kind = (payload.kind or "backend").strip().lower()
    if kind not in COMPONENT_KINDS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"kind must be one of {sorted(COMPONENT_KINDS)}")
    slug = _slugify(payload.name)
    if (session.query(models.ApplicationComponent)
            .filter_by(project_id=project.id, slug=slug).first()):
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "a component with that name already exists in this project")
    row = models.ApplicationComponent(org_id=org.id, project_id=project.id,
                                      kind=kind, name=payload.name.strip(),
                                      slug=slug,
                                      description=payload.description,
                                      created_at=models.utcnow(),
                                      updated_at=models.utcnow())
    session.add(row)
    session.flush()
    _audit_log(session, org.id, payload.actor, "inventory.component_created",
               "application_component", row.id, f"{project.slug}/{row.slug} ({kind})")
    session.commit()
    return {"data": {"id": row.id, "name": row.name, "slug": row.slug,
                     "kind": row.kind, "description": row.description,
                     "repositories": [], "deployments": [], "versions": []}}


class ProjectVersionIn(BaseModel):
    version: str = Field(min_length=1, max_length=255)
    component_id: str | None = Field(default=None, max_length=64)
    actor: str = Field(default="console", max_length=320)


@router.post("/projects/{ref}/versions")
def create_project_version(ref: str, payload: ProjectVersionIn,
                           org: models.Organization = Depends(auth.require_writer),
                           session: Session = Depends(get_session)):
    """Name a version of the product without deploying it anywhere.

    Versions and deployments are different questions: "which builds exist" and
    "which build runs in PRO". An SBOM attaches to the version, so this exists
    even before any environment uses it.
    """
    project = _project_row(session, org, ref)
    label = payload.version.strip()
    if not label:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "version required")
    component = None
    if payload.component_id:
        component = (session.query(models.ApplicationComponent)
                     .filter_by(id=payload.component_id, project_id=project.id,
                                org_id=org.id).one_or_none())
        if component is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                "component not found in this project")
    existing = _version_row(session, project, label,
                            component.id if component else None)
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"{component.name if component else 'the project'} already "
                            f"has version {label}")
    row = models.ProjectVersion(project_id=project.id, version=label,
                                component_id=component.id if component else None)
    session.add(row)
    session.flush()
    _audit_log(session, org.id, payload.actor, "inventory.version_created",
               "project_version", row.id,
               f"{project.slug} {component.slug if component else '*'} {label}")
    session.commit()
    return {"data": {"id": row.id, "version": row.version,
                     "component_id": row.component_id,
                     "component": component.name if component else None,
                     "sbom_imports": 0, "baseline": False, "deployments": []}}


class ProjectAssetIn(BaseModel):
    type: str = Field(default="domain", max_length=32)
    value: str = Field(min_length=1, max_length=1024,
                       description="Domain, URL, IP, CIDR or mobile app id")
    component_id: str | None = Field(default=None, max_length=64)
    deployment_id: str | None = Field(
        default=None, max_length=64,
        description="Environment that serves this asset (DEV, PRE, PRO…)")
    notes: str | None = Field(default=None, max_length=4000)
    actor: str = Field(default="console", max_length=320)


@router.post("/projects/{ref}/assets")
def add_project_asset(ref: str, payload: ProjectAssetIn,
                      org: models.Organization = Depends(auth.require_writer),
                      session: Session = Depends(get_session)):
    """File an asset under the project, with an optional component.

    Manual declaration is the point of the inventory: you record what you know
    before any scan exists. Scanning is a separate, authorized action.
    """
    project = _project_row(session, org, ref)
    kind = (payload.type or "").strip().lower()
    if kind not in ASSET_TYPES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"type must be one of {sorted(ASSET_TYPES)}")
    value = payload.value.strip()
    if not value:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "value required")
    if kind in {"domain", "subdomain", "api"}:
        value = value.lower()
        if "://" in value:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                "give the hostname, not a URL, for a domain")

    component = None
    if payload.component_id:
        component = (session.query(models.ApplicationComponent)
                     .filter_by(id=payload.component_id, org_id=org.id,
                                project_id=project.id).first())
        if component is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                "component not found in this project")

    deployment = None
    if payload.deployment_id:
        deployment = (session.query(models.Deployment)
                      .filter_by(id=payload.deployment_id, org_id=org.id).first())
        if deployment is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "deployment not found")
        if deployment.application_component_id:
            owner = (session.query(models.ApplicationComponent)
                     .filter_by(id=deployment.application_component_id,
                                project_id=project.id).first())
            if owner is None:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    "that deployment belongs to another project")
            # The environment already says which part runs there: no need to
            # ask twice, and a conflicting answer would just be a lie.
            if component is not None and component.id != owner.id:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    "the deployment belongs to another component")
            component = component or owner

    asset = (session.query(models.Asset)
             .filter_by(org_id=org.id, type=kind, value=value).first())
    if asset is not None and asset.project_id and asset.project_id != project.id:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "that asset already belongs to another project")
    if asset is None:
        asset = models.Asset(org_id=org.id, type=kind, value=value,
                             source="manual", detail=payload.notes)
        session.add(asset)
        session.flush()
    asset.project_id = project.id
    asset.classification_status = "owned"
    if payload.notes:
        asset.detail = payload.notes

    if component is not None:
        link = (session.query(models.AssetLink)
                .filter_by(org_id=org.id, asset_id=asset.id,
                           entity_type="application_component",
                           entity_id=component.id).first())
        if link is None:
            session.add(models.AssetLink(org_id=org.id, asset_id=asset.id,
                                         entity_type="application_component",
                                         entity_id=component.id))

    if deployment is not None:
        link = (session.query(models.AssetLink)
                .filter_by(org_id=org.id, asset_id=asset.id,
                           entity_type="deployment",
                           entity_id=deployment.id).first())
        if link is None:
            session.add(models.AssetLink(org_id=org.id, asset_id=asset.id,
                                         entity_type="deployment",
                                         relation="exposes",
                                         entity_id=deployment.id))
    _audit_log(session, org.id, payload.actor, "inventory.asset_added", "asset",
               asset.id, f"{kind} {value} -> {project.slug}"
               + (f" ({deployment.environment})" if deployment else ""))
    session.commit()
    return {"data": _asset_data(
        asset, component.name if component else None,
        {"id": deployment.id, "environment": deployment.environment,
         "component": component.name if component else None,
         "version_label": deployment.version_label} if deployment else None)}


class DeploymentIn(BaseModel):
    component_id: str
    environment: str = Field(min_length=2, max_length=64)
    version_id: str | None = Field(default=None, max_length=64)
    version_label: str | None = Field(default=None, max_length=255)
    exposure: str = Field(default="unknown", max_length=16)
    requires_auth: bool = False
    name: str | None = Field(default=None, max_length=255)
    actor: str = Field(default="console", max_length=320)


@router.post("/projects/{ref}/deployments")
def create_deployment(ref: str, payload: DeploymentIn = None,
                      org: models.Organization = Depends(auth.require_writer),
                      session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    project = _project_row(session, org, ref)
    component = session.get(models.ApplicationComponent, payload.component_id)
    if component is None or component.project_id != project.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "component not found")
    exposure = (payload.exposure or "unknown").strip().lower()
    if exposure not in EXPOSURES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"exposure must be one of {sorted(EXPOSURES)}")
    environment = payload.environment.strip()
    existing = (session.query(models.Deployment)
                .filter_by(org_id=org.id,
                           application_component_id=component.id,
                           environment=environment,
                           retired_at=None).one_or_none())
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"{component.name} is already deployed in {environment}; "
                            "update that deployment instead")
    version = None
    if payload.version_id:
        version = session.get(models.ProjectVersion, payload.version_id)
        if version is None or version.project_id != project.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "version not found")
        if version.component_id and version.component_id != component.id:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                "that version belongs to another component")
        version.component_id = component.id
    else:
        version = _ensure_version(session, project, payload.version_label, component.id)
    row = models.Deployment(
        org_id=org.id, name=(payload.name or f"{component.name} · {environment}")[:255],
        environment=environment, application_component_id=component.id,
        version_id=version.id if version else None,
        version_label=version.version if version else None,
        exposure=exposure, requires_auth=payload.requires_auth, source="manual",
        status="active", deployed_at=models.utcnow(), updated_at=models.utcnow())
    session.add(row)
    session.flush()
    _audit_log(session, org.id, payload.actor, "inventory.deployment_created",
               "deployment", row.id,
               f"{project.slug}/{component.slug}@{environment} "
               f"{row.version_label or 'version unknown'}")
    session.commit()
    data = _deployment_data(row, component.name)
    data["sbom"] = _version_summary(session, project, row.version_label, component.id)
    return {"data": data}


class DeploymentPatch(BaseModel):
    environment: str | None = Field(default=None, min_length=2, max_length=64)
    version_id: str | None = Field(default=None, max_length=64)
    version_label: str | None = Field(default=None, max_length=255)
    exposure: str | None = Field(default=None, max_length=16)
    requires_auth: bool | None = None
    status: str | None = Field(default=None, max_length=24)
    actor: str = Field(default="console", max_length=320)


@router.patch("/deployments/{deployment_id}")
def patch_deployment(deployment_id: str, payload: DeploymentPatch = None,
                     org: models.Organization = Depends(auth.require_writer),
                     session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    row = session.get(models.Deployment, deployment_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "deployment not found")
    changed = []
    if payload.environment is not None:
        wanted = payload.environment.strip()
        clash = (session.query(models.Deployment)
                 .filter(models.Deployment.org_id == org.id,
                         models.Deployment.application_component_id
                         == row.application_component_id,
                         models.Deployment.environment == wanted,
                         models.Deployment.id != row.id,
                         models.Deployment.status != "retired").first())
        if clash is not None:
            raise HTTPException(status.HTTP_409_CONFLICT,
                                f"that component already has a {wanted} environment")
        row.environment = wanted
        changed.append(f"environment {wanted}")
    if payload.version_id is not None or payload.version_label is not None:
        component = session.get(models.ApplicationComponent,
                                row.application_component_id)
        project_for_row = (session.get(models.Project, component.project_id)
                           if component else None)
        if project_for_row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "component not found")
        if payload.version_id:
            version = session.get(models.ProjectVersion, payload.version_id)
            if version is None or version.project_id != project_for_row.id:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "version not found")
        else:
            version = _ensure_version(session, project_for_row,
                                      payload.version_label, component.id)
        row.version_id = version.id if version else None
        row.version_label = version.version if version else None
        row.source = "manual"
        changed.append(f"version {row.version_label or '-'}")
    if payload.exposure is not None:
        exposure = payload.exposure.strip().lower()
        if exposure not in EXPOSURES:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"exposure must be one of {sorted(EXPOSURES)}")
        row.exposure = exposure
        changed.append(f"exposure {exposure}")
    if payload.requires_auth is not None:
        row.requires_auth = payload.requires_auth
        changed.append(f"requires_auth {payload.requires_auth}")
    if payload.status is not None:
        row.status = payload.status.strip()
        if row.status == "retired":
            row.retired_at = models.utcnow()
        changed.append(f"status {row.status}")
    row.updated_at = models.utcnow()
    if changed:
        _audit_log(session, org.id, payload.actor, "inventory.deployment_updated",
                   "deployment", row.id, ", ".join(changed)[:300])
        session.commit()
    component = session.get(models.ApplicationComponent, row.application_component_id)
    data = _deployment_data(row, component.name if component else None)
    if component is not None:
        project_for_row = session.get(models.Project, component.project_id)
        if project_for_row is not None:
            data["sbom"] = _version_summary(session, project_for_row,
                                            row.version_label, component.id)
    return {"data": data}


# ── version probe (read-only GET) ────────────────────────────────────────────

class ProbeIn(BaseModel):
    url: str = Field(min_length=8, max_length=1024)
    token: str | None = Field(default=None, max_length=4096)
    clear_token: bool = False
    version_path: str = Field(default="auto", max_length=128)
    status_path: str = Field(default="status", max_length=128)
    enabled: bool = True
    interval_minutes: int = Field(default=0, ge=0, le=1440)
    actor: str = Field(default="console", max_length=320)


def _probe_headers(token: str | None) -> dict:
    headers = {"Accept": "application/json", "User-Agent": "barad-dur/version-probe"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _dig(payload, path: str):
    current = payload
    for part in (path or "").split("."):
        if not part:
            continue
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _auto_version(payload) -> str | None:
    if not isinstance(payload, dict):
        return None
    for key in VERSION_KEYS:
        value = payload.get(key)
        if isinstance(value, (str, int, float)) and str(value).strip():
            return str(value).strip()
    for container in ("build", "git", "app", "meta", "data"):
        nested = payload.get(container)
        if isinstance(nested, dict):
            for key in VERSION_KEYS + ("short_sha", "sha", "commit"):
                value = nested.get(key)
                if isinstance(value, (str, int, float)) and str(value).strip():
                    return str(value).strip()
    return None


def _run_probe(probe: models.HealthProbe, token: str | None) -> dict:
    request = urllib.request.Request(probe.url, headers=_probe_headers(token))
    try:
        with urllib.request.urlopen(request, timeout=PROBE_TIMEOUT) as response:
            raw = response.read(64_000).decode(errors="replace")
            http_status = response.status
    except urllib.error.HTTPError as exc:
        return {"ok": False, "http_status": exc.code, "version": None,
                "status": None, "payload": None,
                "error": f"http_{exc.code}: {exc.read()[:200].decode(errors='replace')}"}
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return {"ok": False, "http_status": None, "version": None, "status": None,
                "payload": None, "error": f"unreachable: {type(exc).__name__}: {exc}"[:300]}
    try:
        payload = json.loads(raw or "{}")
    except json.JSONDecodeError:
        return {"ok": False, "http_status": http_status, "version": None,
                "status": None, "payload": raw[:2000],
                "error": "response is not JSON"}
    version = (_dig(payload, probe.version_path)
               if probe.version_path not in ("", "auto") else _auto_version(payload))
    status_value = _dig(payload, probe.status_path)
    if isinstance(status_value, dict):
        status_value = status_value.get("status") or status_value.get("state")
    if version is None:
        return {"ok": False, "http_status": http_status, "version": None,
                "status": status_value, "payload": payload,
                "error": f"no version at '{probe.version_path}'"}
    return {"ok": True, "http_status": http_status, "version": str(version).strip(),
            "status": status_value, "payload": payload, "error": None}


@router.put("/deployments/{deployment_id}/health-probe")
def put_probe(deployment_id: str, payload: ProbeIn = None,
              org: models.Organization = Depends(auth.require_admin),
              session: Session = Depends(get_session)):
    """Configure the optional version check. It holds a token, so admin only."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    deployment = session.get(models.Deployment, deployment_id)
    if deployment is None or deployment.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "deployment not found")
    url = payload.url.strip()
    if not url.startswith(("http://", "https://")):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "url must start with http:// or https://")
    row = (session.query(models.HealthProbe)
           .filter_by(deployment_id=deployment_id).one_or_none())
    if row is None:
        row = models.HealthProbe(org_id=org.id, deployment_id=deployment_id,
                                 created_at=models.utcnow(),
                                 created_by=payload.actor)
        session.add(row)
    row.url = url
    if payload.token:
        row.token_cipher = secret_store.seal(session, payload.token.strip())
    elif payload.clear_token:
        row.token_cipher = None
    row.version_path = payload.version_path.strip() or "auto"
    row.status_path = payload.status_path.strip() or "status"
    row.enabled = payload.enabled
    row.interval_minutes = payload.interval_minutes
    row.updated_at = models.utcnow()
    _audit_log(session, org.id, payload.actor, "inventory.probe_configured",
               "deployment", deployment_id,
               f"{url} (version path {row.version_path})")
    session.commit()
    return {"data": _probe_data(row)}


@router.post("/deployments/{deployment_id}/health/check")
def check_health(deployment_id: str, actor: str = "console",
                 org: models.Organization = Depends(auth.require_writer),
                 session: Session = Depends(get_session)):
    """Run the probe now. A GET against the deployment's own endpoint."""
    deployment = session.get(models.Deployment, deployment_id)
    if deployment is None or deployment.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "deployment not found")
    probe = (session.query(models.HealthProbe)
             .filter_by(deployment_id=deployment_id).one_or_none())
    if probe is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "no version probe configured for this deployment")
    token = None
    if probe.token_cipher:
        try:
            token = secret_store.open_sealed(session, probe.token_cipher)
        except ValueError as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
    outcome = _run_probe(probe, token)
    _apply_probe_outcome(session, probe, deployment, outcome, actor, models.utcnow())
    session.commit()
    return {"data": {"version": outcome["version"], "status": outcome["status"],
                     "http_status": outcome["http_status"],
                     "error": outcome["error"],
                     "deployment": _deployment_data(deployment)},
            "probe": _probe_data(probe)}


def _apply_probe_outcome(session: Session, probe: models.HealthProbe,
                         deployment: models.Deployment | None, outcome: dict,
                         actor: str, now: datetime) -> None:
    """Record one attempt on the probe and on the deployment it watches.

    Shared by `check now` and the tick so a scheduled check cannot drift from a
    manual one: same fields, same audit action, same "failed, version untouched"
    rule — a failed probe never rewrites the version it was meant to confirm.
    """
    probe.last_run_at = now
    probe.last_error = outcome["error"]
    probe.last_payload = (json.dumps(outcome["payload"])[:4000]
                          if outcome["payload"] is not None else None)
    if outcome["ok"]:
        probe.last_ok_at = now
    if deployment is not None:
        deployment.last_checked_at = now
        deployment.updated_at = now
        if outcome["ok"]:
            deployment.version_label = outcome["version"]
            deployment.source = "health"
            deployment.last_check_status = "ok"
            deployment.last_check_error = None
            # A probe that reads a version nobody declared IS the declaration:
            # the tree has to show where that build runs, or the row reports a
            # version that exists nowhere in the component.
            _link_probe_version(session, deployment, outcome["version"], actor)
        else:
            deployment.last_check_status = "failed"
            deployment.last_check_error = (outcome["error"] or "")[:500]
    detail = (f"{outcome['version']} (HTTP {outcome['http_status']})"
              if outcome["ok"] else f"failed: {outcome['error']}")
    _audit_log(session, probe.org_id, actor, "inventory.version_checked",
               "deployment", probe.deployment_id, detail[:300])


def _link_probe_version(session: Session, deployment: models.Deployment,
                        label: str | None, actor: str) -> bool:
    """Point the deployment at a real version row, creating it if needed.

    A /health probe answers "what is running here?", which is exactly what a
    version row means. Recording the answer only as text left the component tree
    listing 1.1–1.8 while PRO reported 21.7.8: a version the inventory did not
    have. Returns True when the row was created (so the caller can say so).
    """
    value = (label or "").strip()
    component = (session.get(models.ApplicationComponent,
                             deployment.application_component_id)
                 if deployment.application_component_id else None)
    if not value or component is None:
        return False
    project = session.get(models.Project, component.project_id)
    if project is None:
        return False
    known = _version_row(session, project, value, component.id) is not None
    version_row = _ensure_version(session, project, value, component.id)
    if version_row is None:
        return False
    deployment.version_id = version_row.id
    if not known:
        _audit_log(session, project.org_id, actor, "inventory.version_discovered",
                   "project_version", version_row.id,
                   f"{project.slug} {component.slug} {value} "
                   f"(read from {deployment.environment} health probe)")
    return not known


class ProbeTickIn(BaseModel):
    limit: int = Field(default=10, ge=1, le=200)
    actor: str = Field(default="scheduler", max_length=320)


@router.post("/probes/tick")
def tick_probes(payload: ProbeTickIn = None,
                session: Session = Depends(get_session),
                x_api_key: str = Header(default="", alias="X-API-Key"),
                authorization_header: str = Header(default="", alias="Authorization")):
    """Run every enabled probe whose interval has elapsed. Safe from cron.

    No grant is involved: a probe is a GET against the deployment's own endpoint,
    declared by the organization that owns it — the same read `check now` does.
    The row is claimed with a compare-and-swap on `last_run_at` *before* the
    request leaves, so two ticks (or two API replicas behind one cron) can never
    run the same probe twice; the loser reports `skipped`, not a duplicate check.

    A probe with `interval_minutes = 0` is manual-only and is never picked up.
    """
    payload = payload or ProbeTickIn()
    principal = auth.resolve_principal(session, x_api_key, authorization_header)
    now = models.utcnow()
    query = (session.query(models.HealthProbe)
             .filter(models.HealthProbe.enabled.is_(True),
                     models.HealthProbe.interval_minutes > 0))
    # A cron token is platform-wide; a user token only ticks its own org.
    if principal["kind"] == "user":
        query = query.filter(models.HealthProbe.org_id == principal["org_id"])

    due = []
    for probe in query.all():
        # Never-run probes are due at once; `_next_due` answers "now" for them,
        # but comparing that to a `now` captured earlier is a race with itself.
        if probe.last_run_at is None:
            due.append((probe.id, probe.deployment_id, None))
            continue
        next_due = _next_due(probe)
        if next_due is not None and next_due <= now:
            due.append((probe.id, probe.deployment_id, probe.last_run_at))
    due = due[:payload.limit]

    results = []
    for probe_id, deployment_id, expected in due:
        claim = (session.query(models.HealthProbe)
                 .filter(models.HealthProbe.id == probe_id)
                 .filter(models.HealthProbe.last_run_at.is_(None) if expected is None
                         else models.HealthProbe.last_run_at == expected)
                 .update({"last_run_at": now, "updated_at": now},
                         synchronize_session=False))
        session.commit()
        if claim != 1:
            results.append({"probe": probe_id, "deployment": deployment_id,
                            "result": "skipped", "reason": "claimed by another tick"})
            continue

        probe = session.get(models.HealthProbe, probe_id)
        deployment = session.get(models.Deployment, deployment_id)
        token = None
        if probe.token_cipher:
            try:
                token = secret_store.open_sealed(session, probe.token_cipher)
            except ValueError as exc:
                probe.last_error = str(exc)[:500]
                session.commit()
                results.append({"probe": probe_id, "deployment": deployment_id,
                                "result": "error", "reason": str(exc)[:200]})
                continue
        outcome = _run_probe(probe, token)
        _apply_probe_outcome(session, probe, deployment, outcome,
                             payload.actor, models.utcnow())
        session.commit()
        results.append({
            "probe": probe_id, "deployment": deployment_id,
            "result": "ok" if outcome["ok"] else "failed",
            "version": outcome["version"], "error": outcome["error"],
            "next_due_at": _iso(_next_due(probe))})

    return {"data": results, "ran": len(results),
            "due": len(due), "evaluated": len(due)}


# ── cataloguing discovered assets ────────────────────────────────────────────

@router.get("/inventory/unassigned")
def unassigned_assets(limit: int = Query(default=200, le=500),
                      org: models.Organization = Depends(auth.require_org),
                      session: Session = Depends(get_session)):
    """Discovered assets nobody has catalogued yet, plus the projects to file them."""
    rows = (session.query(models.Asset)
            .filter(models.Asset.org_id == org.id,
                    models.Asset.archived_at.is_(None),
                    (models.Asset.project_id.is_(None))
                    | (models.Asset.classification_status != "owned"))
            .order_by(models.Asset.discovered_at.desc()).limit(limit).all())
    projects = [{"id": row.id, "name": row.name, "slug": row.slug}
                for row in (session.query(models.Project)
                            .filter_by(org_id=org.id)
                            .order_by(models.Project.name).all())]
    return {"data": [_asset_data(row) for row in rows], "total": len(rows),
            "projects": projects}


class CatalogIn(BaseModel):
    project: str
    component_id: str | None = None
    deployment_id: str | None = None
    relation: str = Field(default="serves", max_length=32)
    actor: str = Field(default="console", max_length=320)


@router.post("/assets/{asset_id}/catalog")
def catalog_asset(asset_id: str, payload: CatalogIn = None,
                  org: models.Organization = Depends(auth.require_writer),
                  session: Session = Depends(get_session)):
    """File an asset under a project. Ownership, not authorization: no grant."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    asset = session.get(models.Asset, asset_id)
    if asset is None or asset.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    project = _project_row(session, org, payload.project)
    asset.project_id = project.id
    asset.classification_status = "owned"
    entity_type, entity_id = "project", project.id
    if payload.deployment_id:
        deployment = session.get(models.Deployment, payload.deployment_id)
        if deployment is None or deployment.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "deployment not found")
        entity_type, entity_id = "deployment", deployment.id
    elif payload.component_id:
        component = session.get(models.ApplicationComponent, payload.component_id)
        if component is None or component.project_id != project.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "component not found")
        entity_type, entity_id = "application_component", component.id
    link = (session.query(models.AssetLink)
            .filter_by(asset_id=asset.id, entity_type=entity_type,
                       entity_id=entity_id).one_or_none())
    if link is None:
        session.add(models.AssetLink(org_id=org.id, asset_id=asset.id,
                                     entity_type=entity_type, entity_id=entity_id,
                                     relation=payload.relation,
                                     added_by=payload.actor,
                                     added_at=models.utcnow()))
    _audit_log(session, org.id, payload.actor, "inventory.asset_catalogued",
               "asset", asset.id,
               f"{asset.type}:{asset.value} -> {project.slug}/{entity_type}")
    session.commit()
    return {"data": _asset_data(asset)}

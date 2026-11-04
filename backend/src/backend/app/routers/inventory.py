"""Inventory and project listing endpoints."""
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models, severity as severity_mod
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

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


def _project_by_ref(session: Session, org_id: str, ref: str) -> models.Project | None:
    """Resolve the display name as well as the canonical slug for read views."""
    return (session.query(models.Project).filter_by(org_id=org_id, slug=ref).one_or_none()
            or session.query(models.Project).filter_by(org_id=org_id, name=ref).one_or_none())


def _graph_node(node_type: str, row_id: str, label: str, **fields) -> dict:
    return {"id": f"{node_type}:{row_id}", "type": node_type, "label": label, **fields}


@router.get("/projects/{project_ref}/runtime-graph")
def project_runtime_graph(project_ref: str,
                          org: models.Organization = Depends(auth.require_org),
                          session: Session = Depends(get_session)):
    """A tenant-safe evidence graph for one application's running surface.

    This deliberately joins only stored relationships. It does not infer an
    artifact from a version, a deployment from a host name, or a vulnerability
    from an endpoint response; those would make the visual plausible but false.
    """
    project = _project_by_ref(session, org.id, project_ref)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")

    nodes, edges = [], []
    project_node = _graph_node("project", project.id, project.name, slug=project.slug)
    nodes.append(project_node)

    def edge(source: str, target: str, relation: str, **fields):
        edges.append({"from": source, "to": target, "relation": relation, **fields})

    components = (session.query(models.ApplicationComponent)
                  .filter_by(org_id=org.id, project_id=project.id)
                  .order_by(models.ApplicationComponent.name).all())
    component_ids = {row.id for row in components}
    for row in components:
        node = _graph_node("application_component", row.id, row.name,
                           kind=row.kind, slug=row.slug)
        nodes.append(node)
        edge(project_node["id"], node["id"], "contains")

    repositories = []
    for link in (session.query(models.ProjectRepository)
                 .filter_by(org_id=org.id, project_id=project.id, removed_at=None).all()):
        row = session.get(models.Repository, link.repository_id)
        if row is None or row.org_id != org.id:
            continue
        repositories.append(row)
        node = _graph_node("repository", row.id, row.name, provider=row.provider,
                           remote_url=row.remote_url)
        nodes.append(node)
        edge(project_node["id"], node["id"], "uses", evidence="declared")
    repository_ids = {row.id for row in repositories}

    versions = (session.query(models.ProjectVersion).filter_by(project_id=project.id)
                .order_by(models.ProjectVersion.created_at.desc()).all())
    version_ids = {row.id for row in versions}
    for row in versions:
        node = _graph_node("version", row.id, row.version,
                           created_at=row.created_at.isoformat() if row.created_at else None)
        nodes.append(node)
        edge(project_node["id"], node["id"], "has_version")

    artifacts = (session.query(models.Artifact).filter_by(org_id=org.id).all())
    artifacts = [row for row in artifacts
                 if row.project_version_id in version_ids
                 or row.application_component_id in component_ids]
    artifact_ids = {row.id for row in artifacts}
    for row in artifacts:
        node = _graph_node("artifact", row.id, row.name, digest=row.digest,
                           provenance=row.provenance, source=row.source)
        nodes.append(node)
        if row.application_component_id in component_ids:
            edge(f"application_component:{row.application_component_id}", node["id"],
                 "builds", evidence="declared")
        if row.project_version_id in version_ids:
            edge(node["id"], f"version:{row.project_version_id}", "is_build_of",
                 evidence="declared")

    project_assets = (session.query(models.Asset)
                      .filter_by(org_id=org.id, project_id=project.id).all())
    asset_ids = {row.id for row in project_assets}
    asset_links = (session.query(models.AssetLink)
                   .filter_by(org_id=org.id, entity_type="deployment", removed_at=None).all())
    linked_deployment_ids = {row.entity_id for row in asset_links if row.asset_id in asset_ids}
    deployments = (session.query(models.Deployment).filter_by(org_id=org.id).all())
    deployments = [row for row in deployments
                   if row.artifact_id in artifact_ids
                   or row.application_component_id in component_ids
                   or row.id in linked_deployment_ids]
    deployment_ids = {row.id for row in deployments}
    for row in deployments:
        node = _graph_node("deployment", row.id, row.name, environment=row.environment,
                           status=row.status,
                           deployed_at=row.deployed_at.isoformat() if row.deployed_at else None)
        nodes.append(node)
        if row.artifact_id in artifact_ids:
            edge(f"artifact:{row.artifact_id}", node["id"], "runs_as", evidence="declared")
        elif row.application_component_id in component_ids:
            edge(f"application_component:{row.application_component_id}", node["id"],
                 "runs_as", evidence="declared")

    # Include assets reached from a deployment even if an older row had not yet
    # been filed under the project. The association itself is the evidence.
    for link in asset_links:
        if link.entity_id in deployment_ids:
            row = session.get(models.Asset, link.asset_id)
            if row is not None and row.org_id == org.id:
                asset_ids.add(row.id)
                if row not in project_assets:
                    project_assets.append(row)
    for row in project_assets:
        node = _graph_node("asset", row.id, row.value, asset_type=row.type,
                           classification=row.classification_status)
        nodes.append(node)
        for link in asset_links:
            if link.asset_id == row.id and link.entity_id in deployment_ids:
                edge(f"deployment:{link.entity_id}", node["id"], "is_exposed_by",
                     evidence="declared")

    endpoints = (session.query(models.WebEndpoint)
                 .filter(models.WebEndpoint.org_id == org.id,
                         models.WebEndpoint.asset_id.in_(asset_ids)).all() if asset_ids else [])
    for row in endpoints:
        node = _graph_node("endpoint", row.id, f"{row.method} {row.path}", origin=row.origin,
                           state=row.state, status_code=row.status_code,
                           last_observed_at=row.last_observed_at.isoformat()
                           if row.last_observed_at else None)
        nodes.append(node)
        edge(f"asset:{row.asset_id}", node["id"], "has_registered", evidence="observed")

    analysis_runs = (session.query(models.AnalysisRun).filter_by(org_id=org.id,
                     project_id=project.id).order_by(models.AnalysisRun.created_at.desc()).limit(20).all())
    for row in analysis_runs:
        node = _graph_node("analysis_run", row.id, row.tool,
                           revision=row.revision, branch=row.branch, coverage=row.coverage,
                           findings_seen=row.findings_seen)
        nodes.append(node)
        source = (f"repository:{row.repository_id}" if row.repository_id in repository_ids
                  else project_node["id"])
        edge(source, node["id"], "analysed_by", evidence="observed")
        if row.project_version_id in version_ids:
            edge(node["id"], f"version:{row.project_version_id}", "evaluates")

    findings = (session.query(models.Finding).filter_by(org_id=org.id, project_id=project.id)
                .filter(models.Finding.status.notin_(CLOSED_STATUSES)).all())
    contexts = (session.query(models.FindingContext).filter_by(org_id=org.id)
                .filter(models.FindingContext.finding_id.in_({row.id for row in findings})).all()
                if findings else [])
    known_contexts = {f"asset:{row.id}" for row in project_assets}
    known_contexts |= {f"deployment:{row.id}" for row in deployments}
    known_contexts |= {f"repository:{row.id}" for row in repositories}
    known_contexts |= {f"endpoint:{row.id}" for row in endpoints}
    for row in findings:
        node = _graph_node("finding", row.id, row.title or row.kind, kind=row.kind,
                           severity=severity_mod.canonical(row.severity), status=row.status)
        nodes.append(node)
        matches = [ctx for ctx in contexts
                   if ctx.finding_id == row.id and f"{ctx.entity_type}:{ctx.entity_id}" in known_contexts]
        if matches:
            for ctx in matches:
                edge(f"{ctx.entity_type}:{ctx.entity_id}", node["id"], "observed_in",
                     evidence="observed")
        else:
            edge(project_node["id"], node["id"], "has_finding", evidence="project")

    # Risk is not a new relationship: it is an attribute of the node it was
    # observed on. A version carries the findings last seen in it, and the
    # project carries all of them — that is what lets the graph colour a node
    # without inventing an edge.
    by_version: dict[str, list] = {}
    for row in findings:
        if row.last_seen_version_id:
            by_version.setdefault(row.last_seen_version_id, []).append(row)

    def risk_of(rows: list) -> dict:
        worst = "UNKNOWN"
        by_vector: dict[str, int] = {}
        for row in rows:
            label = severity_mod.canonical(row.severity)
            if severity_mod.rank(label) < severity_mod.rank(worst):
                worst = label
            by_vector[row.vector or "sast"] = by_vector.get(row.vector or "sast", 0) + 1
        return {"findings": len(rows), "worst": worst, "by_vector": by_vector}

    project_risk = risk_of(findings)
    for node in nodes:
        if node["type"] == "project":
            node["risk"] = project_risk
        elif node["type"] == "version":
            node["risk"] = risk_of(by_version.get(node["id"].split(":", 1)[1], []))

    active_deployments = sum(1 for row in deployments if row.status == "active")
    coverage = []
    if not components:
        coverage.append("no application components are recorded")
    if not deployments:
        coverage.append("no deployments are linked to this project")
    if deployments and not asset_ids:
        coverage.append("deployments have no linked assets")
    if not endpoints:
        coverage.append("no registered endpoints are linked to project assets")
    return {"data": {
        "project": {"id": project.id, "slug": project.slug, "name": project.name},
        "summary": {"components": len(components), "repositories": len(repositories),
                    "versions": len(versions), "artifacts": len(artifacts),
                    "deployments": len(deployments), "active_deployments": active_deployments,
                    "assets": len(asset_ids), "registered_endpoints": len(endpoints),
                    "open_findings": len(findings),
                    "risk": project_risk, "coverage": coverage},
        "nodes": nodes, "edges": edges,
    }}

def _version_by_label(session: Session, project_id: str, version: str,
                      component_id: str | None):
    """Versions are scoped to a component, so a label alone can be ambiguous."""
    query = (session.query(models.ProjectVersion)
             .filter_by(project_id=project_id, version=version))
    if component_id:
        return query.filter_by(component_id=component_id).one_or_none()
    rows = query.all()
    if len(rows) == 1:
        return rows[0]
    if not rows:
        return None
    raise HTTPException(status.HTTP_409_CONFLICT,
                        "several components have this version; pass component_id")


@router.get("/inventory/profile")
def version_profile(project: str = Query(...), version: str = Query(...),
                    component_id: str | None = Query(default=None),
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    """One project version's rollup, with the components that carry findings."""
    project_row = (session.query(models.Project)
                   .filter_by(org_id=org.id, slug=project).one_or_none())
    if project_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    version_row = _version_by_label(session, project_row.id, version, component_id)
    if version_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")
    return {"data": _serialize_version_profile(session, org.id, project_row, version_row)}


class VersionRenameIn(BaseModel):
    version: str = Field(min_length=1, max_length=255,
                         description="New label for this project version")


@router.patch("/projects/{slug}/versions/{version}")
def rename_version(slug: str, version: str, payload: VersionRenameIn,
                   component_id: str | None = Query(default=None),
                   org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    """Relabel a version, e.g. a commit sha that the SBOM itself never declared.

    Renaming is safe: the label is the only thing that changes, every component,
    finding and occurrence keeps pointing at the same row.
    """
    project = (session.query(models.Project)
               .filter_by(org_id=org.id, slug=slug).one_or_none())
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    row = _version_by_label(session, project.id, version, component_id)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")
    new_label = payload.version.strip()
    if new_label == version:
        return {"data": {"version": row.version}}
    clash = (session.query(models.ProjectVersion)
             .filter_by(project_id=project.id, component_id=row.component_id,
                        version=new_label).one_or_none())
    if clash is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "that component already has a version with this name")
    row.version = new_label
    # Deployments mirror the label so the table never shows a stale name.
    (session.query(models.Deployment)
     .filter_by(version_id=row.id)
     .update({models.Deployment.version_label: new_label},
             synchronize_session=False))
    session.commit()
    return {"data": {"version": row.version, "previous": version,
                     "component_id": row.component_id}}


class ProjectGroupIn(BaseModel):
    group: str | None = Field(
        default=None,
        description="Product or account that owns this repository; null ungroups it")
    name: str | None = Field(
        default=None, max_length=255,
        description="Display name; the slug stays fixed")
    description: str | None = Field(default=None, max_length=2000)
    owner: str | None = Field(default=None, max_length=255)
    actor: str = Field(default="console", max_length=320)


@router.patch("/projects/{slug}")
def set_project_group(slug: str, payload: ProjectGroupIn,
                      org: models.Organization = Depends(auth.require_admin),
                      session: Session = Depends(get_session)):
    """Group and display name of a project.

    Free text rather than a table: the hierarchy reads Aurea > backend, but a
    new organization decides its own labels, and moving a repository between
    products must not need a migration.
    """
    from backend.app.projects import by_ref

    project = by_ref(session, org.id, slug)
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    changed = []
    provided = payload.model_fields_set
    # `null` is meaningful here: it clears the group. Only an absent field means
    # "leave it alone", so the body's own keys decide.
    if "group" in provided:
        project.group_name = (payload.group or "").strip() or None
        changed.append(f"group {project.group_name or '-'}")
    if "name" in provided and payload.name and payload.name.strip() != project.name:
        changed.append(f"name {project.name} -> {payload.name.strip()}")
        project.name = payload.name.strip()
    if "description" in provided:
        project.description = (payload.description or "").strip() or None
        changed.append("description")
    if "owner" in provided:
        project.owner = (payload.owner or "").strip() or None
        changed.append(f"owner {project.owner or '-'}")
    if changed:
        _audit_log(session, org.id, payload.actor, "project.updated", "project",
                   project.id, ", ".join(changed)[:300])
    session.commit()
    return {"data": {"id": project.id, "slug": project.slug, "name": project.name,
                     "group": project.group_name,
                     "description": project.description, "owner": project.owner}}


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

"""Deployment chain: the facts, and nothing but the facts (D74, D78, D79).

One question, one answer: *what do we have, where is it, which version actually
runs, and how much do we know?*

    repository → build (commit, SBOM) → deployment (DEV/PRE/PRO/PROE)
    → asset (domain, ip, url) → observation (dns, tls, technology, port, web_path)

Every edge carries `{value, source, observed_at | last_checked_at, confidence}`,
and **no edge carries an opinion**: no severity, no score, no `affected`, no KEV.
That is not modesty, it is the split this platform is built on — the interpretation
of these facts against a vulnerability lives in `exposure/verdict`, which consumes
this endpoint. A score here would leak into every consumer (project page, asset
page, chat, MCP) and become arithmetic nobody can review.

`completeness.unknown_edges` is the other half of the contract: the endpoint has to
say which relation it could not establish, because an absent edge is not a negative
edge. With no observations it answers "we know nothing about exposure", never
"nothing is exposed".
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app import auth, models
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1", tags=["deployment-chain"])

# Caps: an answer a model can read, not a dump of the estate.
LIMIT_COMPONENTS = 50
LIMIT_BUILDS = 50
LIMIT_DEPLOYMENTS = 50
LIMIT_ASSETS = 50
LIMIT_OBSERVATIONS = 120
LIMIT_FINDINGS = 100


def _iso(value: datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.isoformat()


def _age_days(value: datetime | None, now: datetime) -> int | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    delta = now - value
    return max(0, int(delta.total_seconds() // 86400))


def _component_rows(session: Session, org_id: str, purl: str | None,
                    component: str | None, project: str | None):
    if component and component.lower().startswith("pkg:"):
        # A caller that hands the purl in `component` is asking the same question.
        # Answering 404 there told a model "the estate has no such component" when the
        # row existed — and a 4xx is read as a gap in the data, never as a bad argument.
        purl, component = component, None
    query = session.query(models.Component).filter_by(org_id=org_id)
    if purl:
        # A versionless purl still has to find the component: `pkg:npm/lodash`
        # must match `pkg:npm/lodash@4.17.21` without inventing a version.
        if "@" in purl:
            query = query.filter(models.Component.purl == purl)
        else:
            query = query.filter(
                (models.Component.purl == purl)
                | (models.Component.purl.like(purl + "@%"))
                | (models.Component.identity_key.like(purl + "@%")))
    if component:
        query = query.filter(models.Component.name.ilike(component))
    rows = query.order_by(models.Component.name).limit(LIMIT_COMPONENTS + 1).all()
    if project and not purl and not component:
        # Narrow by project through the builds that contain the component.
        versions = (session.query(models.ProjectVersion)
                    .filter_by(project_id=_project_id(session, org_id, project))
                    .all())
        allowed = {row.component_id for row in versions if row.component_id}
        linked = {row.component_id for row in session.query(models.VersionComponent)
                  .filter(models.VersionComponent.project_version_id.in_(
                      [row.id for row in versions] or [""]))
                  .all()}
        keep = allowed | linked
        rows = [row for row in rows if row.id in keep]
    return rows


def _project_id(session: Session, org_id: str, ref: str) -> str:
    """The project behind a ref: id, slug or name — the same three `projects.by_ref`
    accepts, so the chain and the findings list never disagree about what a project is."""
    from backend.app import projects as projects_ref
    row = projects_ref.by_ref(session, org_id, ref)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    return row.id


def _project_label(session: Session, project_id: str) -> tuple[str, str]:
    row = session.get(models.Project, project_id)
    return (row.slug, row.name) if row else (project_id, project_id)


def _deployment_matches(session: Session, org_id: str, component_ids: list[str],
                        version_ids: list[str], labels_by_component: dict,
                        limit_note: dict) -> list[dict]:
    """Deployments that run one of these versions, and how we know it.

    `matched_by` is part of the answer: `version_id` is a confirmed build,
    `artifact` is a build digest, `label` is a team's declaration that no build
    has confirmed yet. Collapsing the three would make a declared version look
    as solid as a shipped artifact.
    """
    out: list[dict] = []
    if not component_ids and not version_ids:
        return out

    rows = []
    if version_ids:
        rows.extend(session.query(models.Deployment)
                    .filter_by(org_id=org_id)
                    .filter(models.Deployment.version_id.in_(version_ids))
                    .all())
        artifact_ids = [row.id for row in session.query(models.Artifact)
                        .filter(models.Artifact.org_id == org_id)
                        .filter(models.Artifact.project_version_id.in_(version_ids))
                        .all()]
        if artifact_ids:
            rows.extend(session.query(models.Deployment)
                        .filter_by(org_id=org_id)
                        .filter(models.Deployment.artifact_id.in_(artifact_ids))
                        .all())
    label_rows = []
    # A deployment's `version_label` names a *project version*, not a package
    # version: comparing it to `component.version` matched nothing and made every
    # declared deployment invisible.
    for component_id, labels in labels_by_component.items():
        for label in labels:
            if not label:
                continue
            label_rows.extend(session.query(models.Deployment)
                              .filter_by(org_id=org_id,
                                         application_component_id=component_id,
                                         version_label=label)
                              .all())

    seen: dict[str, dict] = {}
    for row in rows:
        matched_by = "version_id" if row.version_id in version_ids else "artifact"
        seen[row.id] = {"row": row, "matched_by": matched_by}
    for row in label_rows:
        seen.setdefault(row.id, {"row": row, "matched_by": "label"})

    for entry in list(seen.values())[:LIMIT_DEPLOYMENTS]:
        row = entry["row"]
        project_id = _project_of_version(session, row.version_id) if row.version_id else None
        slug, name = _project_label(session, project_id) if project_id else (None, None)
        service = session.get(models.Service, row.service_id) if row.service_id else None
        out.append({
            "id": row.id,
            "name": row.name,
            "environment": row.environment,
            "project": slug or None,
            "project_name": name or None,
            "version_label": row.version_label,
            "version_id": row.version_id,
            "exposure": row.exposure,
            "requires_auth": row.requires_auth,
            "status": row.status,
            "source": row.source,
            "service": service.name if service else None,
            "deployed_at": _iso(row.deployed_at),
            "last_checked_at": _iso(row.last_checked_at),
            "last_check_status": row.last_check_status,
            "matched_by": entry["matched_by"],
            "confidence": "confirmed" if entry["matched_by"] != "label" else "declared",
        })
    if len(seen) > LIMIT_DEPLOYMENTS:
        limit_note["deployments"] = True
    return out


def _project_of_version(session: Session, version_id: str | None) -> str | None:
    if not version_id:
        return None
    row = session.get(models.ProjectVersion, version_id)
    return row.project_id if row else None


def _asset_edges(session: Session, org_id: str, deployment_ids: list[str],
                 service_ids: list[str], project_ids: list[str]) -> list[dict]:
    links = (session.query(models.AssetLink)
             .filter_by(org_id=org_id)
             .filter(models.AssetLink.removed_at.is_(None))
             .all())
    wanted = {"deployment": set(deployment_ids),
              "service": set(service_ids),
              "project": set(project_ids)}
    asset_ids: dict[str, list[dict]] = {}
    for link in links:
        if link.entity_id in wanted.get(link.entity_type, set()):
            asset_ids.setdefault(link.asset_id, []).append(
                {"entity_type": link.entity_type,
                 "entity_id": link.entity_id,
                 "relation": link.relation,
                 "added_at": _iso(link.added_at)})
    # Ownership declared straight on the asset (inventory, not scan authorization).
    if project_ids:
        for asset in (session.query(models.Asset)
                      .filter_by(org_id=org_id)
                      .filter(models.Asset.project_id.in_(project_ids))
                      .all()):
            asset_ids.setdefault(asset.id, []).append(
                {"entity_type": "project", "entity_id": asset.project_id,
                 "relation": "owned_by", "added_at": None})

    out = []
    rows = (session.query(models.Asset)
            .filter(models.Asset.id.in_(list(asset_ids) or [""]))
            .order_by(models.Asset.type, models.Asset.value)
            .limit(LIMIT_ASSETS + 1).all())
    for asset in rows[:LIMIT_ASSETS]:
        out.append({
            "id": asset.id,
            "type": asset.type,
            "value": asset.value,
            "classification_status": asset.classification_status,
            "owner": asset.owner,
            "source": asset.source,
            "last_seen_at": _iso(asset.last_seen_at),
            "relations": asset_ids.get(asset.id, []),
        })
    return out


def _observation_edges(session: Session, org_id: str, asset_ids: list[str],
                       limit_note: dict) -> list[dict]:
    if not asset_ids:
        return []
    rows = (session.query(models.Observation)
            .filter_by(org_id=org_id)
            .filter(models.Observation.asset_id.in_(asset_ids))
            .order_by(models.Observation.observed_at.desc())
            .limit(LIMIT_OBSERVATIONS + 1).all())
    if len(rows) > LIMIT_OBSERVATIONS:
        limit_note["observations"] = True
    return [{"asset_id": row.asset_id, "kind": row.kind,
             "subject": row.subject, "port": row.port,
             "protocol": row.protocol, "source": row.source,
             "coverage": row.coverage, "observed_at": _iso(row.observed_at)}
            for row in rows[:LIMIT_OBSERVATIONS]]


def _finding_edges(session: Session, org_id: str, component_ids: list[str],
                   limit_note: dict) -> list[dict]:
    """Known issues **of these components** — not of their whole build.

    A build's findings belong to `sbom/version`; pulling them here made one package
    carry a hundred unrelated rows into a model's context.
    """
    if not component_ids:
        return []
    rows = (session.query(models.Finding)
            .filter_by(org_id=org_id)
            .filter(models.Finding.component_id.in_(component_ids))
            .order_by(models.Finding.last_seen_at.desc())
            .limit(LIMIT_FINDINGS + 1).all())
    if len(rows) > LIMIT_FINDINGS:
        limit_note["findings"] = True
    return [{"id": row.id, "kind": row.kind, "status": row.status,
             "component_id": row.component_id,
             "vulnerability_id": row.vulnerability_id,
             "first_seen_at": _iso(row.first_seen_at),
             "last_seen_at": _iso(row.last_seen_at)}
            for row in rows[:LIMIT_FINDINGS]]


@router.get("/deployment/chain")
def deployment_chain(
    purl: str | None = Query(default=None, max_length=1024),
    component: str | None = Query(default=None, max_length=512),
    project: str | None = Query(default=None, max_length=255),
    asset: str | None = Query(default=None, max_length=1024),
    org: models.Organization = Depends(auth.require_org),
    session: Session = Depends(get_session),
):
    """Facts for one component, project or asset. No vulnerability, no verdict."""
    if not any((purl, component, project, asset)):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "one of purl, component, project or asset is required")
    now = models.utcnow()
    limit_note: dict[str, bool] = {}
    unknown: list[str] = []

    if asset:
        asset_row = (session.query(models.Asset)
                     .filter_by(org_id=org.id)
                     .filter((models.Asset.id == asset)
                             | (models.Asset.value == asset))
                     .one_or_none())
        if asset_row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
        assets = [{**_asset_payload(asset_row), "relations": []}]
        observations = _observation_edges(session, org.id, [asset_row.id], limit_note)
        if not observations:
            unknown.append(f"no observation recorded for asset {asset_row.value}")
        return {
            "query": {"asset": asset, "purl": None, "component": None,
                      "project": None},
            "as_of": _weakest([asset_row.last_seen_at]),
            "edges": {"components": [], "builds": [], "deployments": [],
                      "assets": assets, "observations": observations,
                      "findings": []},
            "completeness": {"has_sbom": False, "has_deployment": False,
                             "has_asset": True, "has_observation": bool(observations),
                             "unknown_edges": unknown,
                             "truncated": limit_note},
        }

    components = _component_rows(session, org.id, purl, component, project)
    if not components:
        # An empty chain is an answer, not a missing page. A project with no builds (a
        # lab target served straight from the host) used to 404, and the answer that read
        # it said "the chain lookup came back 404" — reporting our status code as a gap in
        # the estate. 404 stays for a ref that does not resolve at all (a bad purl or a
        # project nobody holds); "nothing to link" is 200 with the reason in `unknown`.
        if project and _project_id(session, org.id, project):
            unknown.append(f"project {project} has no component or build linked to it")
        elif purl or component:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                "no component in this organization matches the query")
        else:
            unknown.append("no component matched the query")
        return {
            "query": {"purl": purl, "component": component, "project": project,
                      "asset": None},
            "as_of": None,
            "edges": {"components": [], "builds": [], "deployments": [],
                      "assets": [], "observations": [], "findings": []},
            "completeness": {"has_sbom": False, "has_deployment": False,
                             "has_asset": False, "has_observation": False,
                             "unknown_edges": unknown,
                             "truncated": limit_note},
        }
    component_ids = [row.id for row in components]

    links = []
    if component_ids:
        links = (session.query(models.VersionComponent)
                 .filter(models.VersionComponent.component_id.in_(component_ids))
                 .all())
    version_ids = [row.project_version_id for row in links]
    versions = []
    if version_ids:
        versions = (session.query(models.ProjectVersion)
                    .filter(models.ProjectVersion.id.in_(version_ids)).all())
    version_map = {row.id: row for row in versions}
    labels_by_component: dict[str, set[str]] = {}
    for link in links:
        version_row = version_map.get(link.project_version_id)
        if version_row is not None:
            labels_by_component.setdefault(link.component_id, set()).add(
                version_row.version)

    imports = {}
    if version_ids:
        for row in (session.query(models.SbomImport)
                    .filter(models.SbomImport.project_version_id.in_(version_ids))
                    .order_by(models.SbomImport.created_at.desc()).all()):
            imports.setdefault(row.project_version_id, row)

    builds = []
    for link in links[:LIMIT_BUILDS]:
        version = version_map.get(link.project_version_id)
        if version is None:
            continue
        slug, name = _project_label(session, version.project_id)
        imp = imports.get(version.id)
        builds.append({
            "project_version_id": version.id,
            "project": slug,
            "project_name": name,
            "component_id": link.component_id,
            "version": version.version,
            "revision": None,
            "sbom_imported_at": _iso(imp.created_at) if imp else None,
            "sbom_sha256": imp.content_sha256 if imp else None,
            "sbom_components": imp.components_received if imp else None,
            "direct": link.is_direct,
            "manifest_path": link.manifest_path,
            "confidence": "sbom" if imp else "declared",
        })
    if not builds:
        unknown.append("no build links this component to a version")

    project_ids = sorted({version_map[link.project_version_id].project_id
                          for link in links if link.project_version_id in version_map})
    deployments = _deployment_matches(session, org.id, component_ids, version_ids,
                                      labels_by_component, limit_note)
    service_ids: list[str] = []
    for dep in deployments:
        row = session.get(models.Deployment, dep["id"])
        if row is not None and row.service_id:
            service_ids.append(row.service_id)
    if not deployments:
        unknown.append("no deployment runs this version")

    assets = _asset_edges(session, org.id, [dep["id"] for dep in deployments],
                          service_ids, project_ids)
    if not assets:
        unknown.append("no asset is linked to this deployment or project")
    observations = _observation_edges(session, org.id,
                                      [row["id"] for row in assets], limit_note)
    if assets and not observations:
        unknown.append("assets are linked but never observed (exposure unknown)")
    for asset_row in assets:
        if asset_row["classification_status"] == "unclassified":
            unknown.append(f"asset {asset_row['value']} is unclassified "
                           "(ownership unconfirmed)")
    findings = _finding_edges(session, org.id, component_ids, limit_note)
    if not findings:
        unknown.append("no finding recorded for these builds "
                       "(never analysed is not clean)")

    freshness = [row["sbom_imported_at"] for row in builds]
    freshness += [row["last_checked_at"] for row in deployments]
    freshness += [row["observed_at"] for row in observations]
    freshness += [row["last_seen_at"] for row in assets]

    return {
        "query": {"purl": purl, "component": component, "project": project,
                  "asset": None},
        "as_of": _weakest_date(freshness),
        "edges": {
            "components": [{"id": row.id, "name": row.name, "purl": row.purl,
                            "version": row.version, "license": row.license,
                            "manifest_path": row.manifest_path}
                           for row in components],
            "builds": builds,
            "deployments": deployments,
            "assets": assets,
            "observations": observations,
            "findings": findings,
        },
        "completeness": {
            "has_sbom": any(row["sbom_imported_at"] for row in builds),
            "has_deployment": bool(deployments),
            "has_asset": bool(assets),
            "has_observation": bool(observations),
            "unknown_edges": unknown,
            "truncated": limit_note,
        },
        "ages_days": {
            "sbom": _age_days(_latest(builds, "sbom_imported_at"), now),
            "deployment_check": _age_days(_latest(deployments, "last_checked_at"), now),
            "observation": _age_days(_latest(observations, "observed_at"), now),
        },
    }


def _asset_payload(row: models.Asset) -> dict:
    return {"id": row.id, "type": row.type, "value": row.value,
            "classification_status": row.classification_status,
            "owner": row.owner, "source": row.source,
            "last_seen_at": _iso(row.last_seen_at)}


def _parse(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def _latest(rows: list[dict], key: str) -> datetime | None:
    values = [_parse(row.get(key)) for row in rows]
    values = [value for value in values if value is not None]
    return max(values) if values else None


def _weakest_date(values: list[str | None]) -> str | None:
    parsed = [_parse(value) for value in values]
    parsed = [value for value in parsed if value is not None]
    return _iso(min(parsed)) if parsed else None


def _weakest(values: list[datetime | None]) -> str | None:
    present = [value for value in values if value is not None]
    return _iso(min(present)) if present else None

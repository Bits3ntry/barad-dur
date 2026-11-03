"""Business impact: what the open work costs, per application.

Every number here is counted from rows that already exist (findings, assets,
deployments). Nothing is scored or weighted: this organization has no
criticality model yet, so inventing an "impact score" would be a number with no
source. What the screen answers instead is: for this application, how much open
work is there, how much of it is past its SLA, how many assets and production
deployments carry it, and which CVEs reach it.
"""
import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app import auth, models
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1", tags=["impact"])

OPEN_STATUSES = ("open", "acknowledged")
PRODUCTION_ENVIRONMENTS = ("production", "prod", "live")
PRIORITY_CLASSES = ("P0", "P1", "P2", "P3")


def _deployment_project(session, org_id: str) -> dict[str, str]:
    """deployment id → project id, via component or artifact → version."""
    mapping: dict[str, str] = {}
    rows = (session.query(models.Deployment, models.ApplicationComponent)
            .join(models.ApplicationComponent,
                  models.ApplicationComponent.id
                  == models.Deployment.application_component_id)
            .filter(models.Deployment.org_id == org_id).all())
    for deployment, component in rows:
        mapping[deployment.id] = component.project_id
    rows = (session.query(models.Deployment, models.ProjectVersion)
            .join(models.Artifact, models.Artifact.id == models.Deployment.artifact_id)
            .join(models.ProjectVersion,
                  models.ProjectVersion.id == models.Artifact.project_version_id)
            .filter(models.Deployment.org_id == org_id).all())
    for deployment, version in rows:
        mapping.setdefault(deployment.id, version.project_id)
    return mapping


@router.get("/business-impact")
def business_impact(org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    now = models.utcnow()
    projects = (session.query(models.Project).filter_by(org_id=org.id)
                .order_by(models.Project.name).all())
    by_project = {project.id: project for project in projects}

    # A CVE lives on the advisory, not on the finding: the join is explicit so
    # a finding without an advisory is never counted as one.
    findings = (session.query(models.Finding, models.Vulnerability.cve_id)
                .outerjoin(models.Vulnerability,
                           models.Vulnerability.id == models.Finding.vulnerability_id)
                .filter(models.Finding.org_id == org.id,
                        models.Finding.status.in_(OPEN_STATUSES))
                .all())
    buckets: dict[str, dict] = {
        project_id: {
            "project": project.slug, "name": project.name,
            "open_findings": 0,
            "by_priority": {cls: 0 for cls in PRIORITY_CLASSES},
            "untriaged": 0, "sla_breached": 0, "unassigned": 0,
            "cves": set(), "last_seen": None,
        }
        for project_id, project in by_project.items()
    }
    for finding, cve_id in findings:
        bucket = buckets.get(finding.project_id)
        if bucket is None:
            continue
        bucket["open_findings"] += 1
        if finding.priority in bucket["by_priority"]:
            bucket["by_priority"][finding.priority] += 1
        else:
            bucket["untriaged"] += 1
        deadline = finding.sla_deadline
        if deadline is not None:
            # SQLite hands back naive datetimes; the comparison must be aware.
            if deadline.tzinfo is None:
                deadline = deadline.replace(tzinfo=datetime.timezone.utc)
            if deadline < now:
                bucket["sla_breached"] += 1
        if not finding.assignee:
            bucket["unassigned"] += 1
        if cve_id:
            bucket["cves"].add(cve_id)
        seen = finding.last_seen_at
        if seen is not None and (bucket["last_seen"] is None or seen > bucket["last_seen"]):
            bucket["last_seen"] = seen

    deployment_project = _deployment_project(session, org.id)
    assets: dict[str, set] = {project_id: set() for project_id in by_project}
    production: dict[str, set] = {project_id: set() for project_id in by_project}
    for deployment in (session.query(models.Deployment)
                       .filter(models.Deployment.org_id == org.id).all()):
        project_id = deployment_project.get(deployment.id)
        if project_id not in assets:
            continue
        if deployment.status == "active" and \
                (deployment.environment or "").lower() in PRODUCTION_ENVIRONMENTS:
            production[project_id].add(deployment.id)

    linked = (session.query(models.AssetLink)
              .filter(models.AssetLink.org_id == org.id,
                      models.AssetLink.removed_at.is_(None)).all())
    for link in linked:
        if link.entity_type == "project" and link.entity_id in assets:
            assets[link.entity_id].add(link.asset_id)
        elif link.entity_type == "deployment":
            project_id = deployment_project.get(link.entity_id)
            if project_id in assets:
                assets[project_id].add(link.asset_id)

    org_assets = (session.query(models.Asset)
                  .filter(models.Asset.org_id == org.id,
                          models.Asset.archived_at.is_(None)).all())
    asset_ids = {asset.id for asset in org_assets}
    project_linked = {link.asset_id for link in linked if link.entity_type == "project"}
    deployment_linked = {link.asset_id for link in linked if link.entity_type == "deployment"}
    # An asset can also carry its project on the row; both paths count, because
    # the inventory treats them as the same identity.
    for asset in org_assets:
        if asset.project_id:
            project_linked.add(asset.id)
            if asset.project_id in assets:
                assets[asset.project_id].add(asset.id)

    data = []
    for project_id, bucket in buckets.items():
        data.append({
            "project": bucket["project"],
            "name": bucket["name"],
            "open_findings": bucket["open_findings"],
            "by_priority": bucket["by_priority"],
            "untriaged": bucket["untriaged"],
            "sla_breached": bucket["sla_breached"],
            "unassigned": bucket["unassigned"],
            "cves": len(bucket["cves"]),
            "assets": len(assets.get(project_id, ())),
            "production_deployments": len(production.get(project_id, ())),
            "last_seen_at": bucket["last_seen"].isoformat() if bucket["last_seen"] else None,
        })
    data.sort(key=lambda row: (-row["open_findings"], row["name"]))

    production_ids = {deployment_id for ids in production.values() for deployment_id in ids}
    return {
        "data": data,
        "total": len(data),
        "totals": {
            "open_findings": len(findings),
            "projects": len(data),
            "assets": len(asset_ids),
            "production_deployments": len(production_ids),
        },
        "coverage": {
            "assets_without_project": len(asset_ids - project_linked - deployment_linked),
            "projects_without_assets": sum(1 for row in data if row["assets"] == 0),
            "deployments_without_project": sum(
                1 for deployment_id in deployment_project
                if deployment_id and deployment_project[deployment_id] not in by_project),
        },
        "model": {
            "criticality": "not modelled",
            "note": ("counts come from open findings, asset links and active "
                     "deployments; there is no business-criticality field yet, so "
                     "no impact score is computed"),
        },
    }

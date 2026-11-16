"""The plan a cycle is built on: jewels → threat model → techniques → capabilities.

A cycle used to freeze a list of projects and assets; that answers "what will we
look at" but not "what will we do to it". This module joins the three pieces the
operator already declared — crown jewels, their ATT&CK techniques, and the attacker
profiles that choose them — into one answer:

    jewels        the components this cycle is about
    techniques    every technique declared on those jewels, deduped
    state         ready (capability granted) / blocked (no grant) / untestable
    capabilities  what a run would need, in grant vocabulary
    gaps          the reasons it cannot be fully executed today

Nothing here dispatches work and nothing authorizes: it is the arithmetic that
makes a cycle's charter honest before somebody launches a scan.
"""
import datetime

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app import models

OPEN_STATUSES = ("open", "acknowledged")


def granted_capabilities(session: Session, org_id: str,
                         now: datetime.datetime | None = None) -> set[str]:
    """Capabilities some active grant carries, as the engine would read them."""
    now = now or models.utcnow()
    granted: set[str] = set()
    for grant in (session.query(models.ScanGrant)
                  .filter(models.ScanGrant.org_id == org_id,
                          models.ScanGrant.status == "active").all()):
        valid_from, valid_until = grant.valid_from, grant.valid_until
        if valid_from and valid_from.tzinfo is None:
            valid_from = valid_from.replace(tzinfo=datetime.timezone.utc)
        if valid_until and valid_until.tzinfo is None:
            valid_until = valid_until.replace(tzinfo=datetime.timezone.utc)
        if valid_from and valid_from > now:
            continue
        if valid_until and valid_until < now:
            continue
        for part in (grant.capabilities or "").split(","):
            if part.strip():
                granted.add(part.strip())
    return granted


def state_of(capability: str | None, granted: set[str]) -> str:
    if not capability:
        return "untestable"
    return "ready" if capability in granted else "blocked"


def assets_for_components(session: Session, org_id: str,
                         component_ids: list[str]) -> dict[str, set[str]]:
    """component id → the assets it carries, directly or through a deployment.

    One implementation, used by the plan and by cycle activation: two copies would
    disagree about which host belongs to which jewel.
    """
    index: dict[str, set[str]] = {cid: set() for cid in component_ids}
    if not component_ids:
        return index
    links = (session.query(models.AssetLink)
             .filter(models.AssetLink.org_id == org_id,
                     models.AssetLink.removed_at.is_(None)).all())
    by_entity: dict[tuple, set[str]] = {}
    for link in links:
        by_entity.setdefault((link.entity_type, link.entity_id), set()).add(link.asset_id)
    for (entity_type, entity_id), assets in by_entity.items():
        if entity_type == "application_component" and entity_id in index:
            index[entity_id] |= assets
    for deployment in (session.query(models.Deployment)
                       .filter(models.Deployment.org_id == org_id).all()):
        component_id = deployment.application_component_id
        if component_id in index:
            index[component_id] |= by_entity.get(("deployment", deployment.id), set())
    return index


def plan(session: Session, org: models.Organization,
         component_ids: list[str] | None = None,
         profile_ids: list[str] | None = None) -> dict:
    """Join jewels, their techniques and the profiles into one plan."""
    component_ids = [cid for cid in (component_ids or []) if cid]
    profiles = []
    selected_techniques: set[str] = set()
    if profile_ids:
        for profile in (session.query(models.AttackerProfile)
                        .filter(models.AttackerProfile.org_id == org.id,
                                models.AttackerProfile.id.in_(profile_ids)).all()):
            import json
            techniques = json.loads(profile.techniques or "[]")
            selected_techniques.update(techniques)
            profiles.append({"id": profile.id, "name": profile.name,
                             "origin": profile.origin or "custom",
                             "techniques": techniques})

    jewels = []
    techniques: dict[str, dict] = {}
    jewel_assets: dict[str, set[str]] = {}
    if component_ids:
        components = (session.query(models.ApplicationComponent)
                      .filter(models.ApplicationComponent.org_id == org.id,
                              models.ApplicationComponent.id.in_(component_ids)).all())
        projects = {row.id: row for row in
                    session.query(models.Project).filter_by(org_id=org.id).all()}
        jewel_assets = assets_for_components(session, org.id, component_ids)
        for component in components:
            assets = jewel_assets.get(component.id, set())
            rows = (session.query(models.ThreatEntry, models.AttackTechnique)
                    .join(models.AttackTechnique,
                          models.AttackTechnique.id == models.ThreatEntry.technique_id)
                    .filter(models.ThreatEntry.org_id == org.id,
                            models.ThreatEntry.component_id == component.id).all())
            project = projects.get(component.project_id)
            jewels.append({"id": component.id, "name": component.name,
                           "project": project.slug if project else None,
                           "criticality": component.criticality,
                           "techniques": len(rows), "assets": len(assets)})
            for _entry, technique in rows:
                item = techniques.setdefault(technique.id, {
                    "id": technique.id, "name": technique.name,
                    "tactic": technique.tactic, "capability": technique.capability,
                    "jewels": []})
                if component.name not in item["jewels"]:
                    item["jewels"].append(component.name)

    # A profile may name techniques no jewel declares yet: they are part of the
    # plan, and they are exactly the ones the threat model is missing.
    if selected_techniques:
        known = {row.id for row in
                 session.query(models.AttackTechnique)
                 .filter(models.AttackTechnique.id.in_(selected_techniques)).all()}
        for technique in (session.query(models.AttackTechnique)
                          .filter(models.AttackTechnique.id.in_(known)).all()):
            item = techniques.setdefault(technique.id, {
                "id": technique.id, "name": technique.name,
                "tactic": technique.tactic, "capability": technique.capability,
                "jewels": []})
            item["profile_only"] = technique.id in selected_techniques and not item["jewels"]

    granted = granted_capabilities(session, org.id)
    rows = []
    for item in techniques.values():
        rows.append({**item, "state": state_of(item["capability"], granted)})
    rows.sort(key=lambda row: (row["state"], row["tactic"], row["id"]))
    capabilities = sorted({row["capability"] for row in rows if row["capability"]})

    asset_ids = set().union(*jewel_assets.values()) if jewel_assets else set()
    scope_targets = (session.query(models.ScopeTarget)
                     .filter_by(org_id=org.id, status="active").count())
    grants = (session.query(models.ScanGrant)
              .filter_by(org_id=org.id, status="active").count())
    observed = 0
    if asset_ids:
        observed = (session.query(func.count(func.distinct(models.Observation.asset_id)))
                    .filter(models.Observation.org_id == org.id,
                            models.Observation.asset_id.in_(asset_ids)).scalar() or 0)

    gaps = []
    for row in rows:
        if row["state"] == "blocked":
            gaps.append(f"{row['id']} {row['name']}: {row['capability']} is not granted")
        elif row["state"] == "untestable":
            gaps.append(f"{row['id']} {row['name']}: no capability can test it")
    if not component_ids:
        gaps.append("no crown jewel selected: the plan has nothing to anchor on")

    return {
        "jewels": jewels,
        "profiles": profiles,
        "techniques": rows,
        "coverage": {
            "declared": len(rows),
            "ready": sum(1 for row in rows if row["state"] == "ready"),
            "blocked": sum(1 for row in rows if row["state"] == "blocked"),
            "untestable": sum(1 for row in rows if row["state"] == "untestable"),
        },
        "capabilities": capabilities,
        "granted_capabilities": sorted(granted),
        "scope": {"targets": scope_targets, "grants": grants,
                  "assets": len(asset_ids), "observed_assets": observed},
        "gaps": gaps,
        "runnable": bool(rows) and all(row["state"] == "ready" for row in rows),
    }

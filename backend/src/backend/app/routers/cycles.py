"""Cycles: a time-boxed evaluation with a charter and a frozen reference.

Rules that hold:
  * a cycle is created in `planning`; activation requires an explicit selection
    (or `whole_org: true`), because an empty selection is incomplete, not "all";
  * activation freezes the charter and the resolved membership — later group
    edits never rewrite the historical reference;
  * findings link to the cycle without being duplicated: the cycle reads the
    same finding ids everything else does;
  * review records results and criteria verdicts; close keeps the history;
  * a cycle never grants an authorization.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models, projects as projects_ref, severity as severity_vocab
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/cycles", tags=["cycles"])

TRANSITIONS = {
    "activate": ("planning", "active"),
    "review": ("active", "review"),
    "close": ("review", "closed"),
}
CRITERIA_VERDICTS = {"met", "not_met", "not_measurable", "pending"}


def _ts(value: str | None, name: str) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"{name} must be ISO-8601") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _cycle_or_404(session: Session, org_id: str, cycle_id: str) -> models.Cycle:
    cycle = session.get(models.Cycle, cycle_id)
    if cycle is None or cycle.org_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "cycle not found")
    return cycle


def _resolve_selection(session: Session, org: models.Organization,
                       selection: dict) -> tuple[list[dict], list[str]]:
    """Resolve the cycle's declaration into concrete members.

    Returns (members, gaps). A gap says why something could not be resolved, so
    the preview can be honest instead of silently smaller.
    """
    members: dict[tuple, dict] = {}
    gaps: list[str] = []

    def add(entity_type: str, entity_id: str, label: str | None):
        members[(entity_type, entity_id)] = {
            "entity_type": entity_type, "entity_id": entity_id, "label": label}

    if selection.get("whole_org"):
        for project in (session.query(models.Project)
                        .filter_by(org_id=org.id).all()):
            add("project", project.id, project.slug)
        for asset in (session.query(models.Asset)
                      .filter_by(org_id=org.id)
                      .filter(models.Asset.archived_at.is_(None)).all()):
            add("asset", asset.id, asset.value)

    for slug in selection.get("projects") or []:
        project = projects_ref.by_ref(session, org.id, slug)
        if project is None:
            gaps.append(f"project {slug} does not exist in this organization")
            continue
        add("project", project.id, project.slug)
        for asset in (session.query(models.Asset)
                      .filter_by(org_id=org.id, project_id=project.id)
                      .filter(models.Asset.archived_at.is_(None)).all()):
            add("asset", asset.id, asset.value)

    for group_ref in selection.get("groups") or []:
        group = (session.query(models.InventoryGroup)
                 .filter(models.InventoryGroup.org_id == org.id,
                         (models.InventoryGroup.id == group_ref)
                         | (models.InventoryGroup.name == group_ref))
                 .one_or_none())
        if group is None:
            gaps.append(f"group {group_ref} does not exist in this organization")
            continue
        add("group", group.id, group.name)
        rows = (session.query(models.InventoryGroupMember)
                .filter_by(group_id=group.id, removed_at=None).all())
        for row in rows:
            asset = session.get(models.Asset, row.asset_id)
            if asset is not None and asset.org_id == org.id:
                add("asset", asset.id, asset.value)

    for environment in selection.get("environments") or []:
        deployments = (session.query(models.Deployment)
                       .filter_by(org_id=org.id, environment=environment).all())
        if not deployments:
            gaps.append(f"no deployment recorded for environment {environment}")
        for deployment in deployments:
            add("deployment", deployment.id, f"{deployment.name} ({environment})")
            for link in (session.query(models.AssetLink)
                         .filter_by(org_id=org.id, entity_type="deployment",
                                    entity_id=deployment.id, removed_at=None).all()):
                asset = session.get(models.Asset, link.asset_id)
                if asset is not None:
                    add("asset", asset.id, asset.value)
    return list(members.values()), gaps


def _cycle_data(session: Session, cycle: models.Cycle) -> dict:
    members = (session.query(models.CycleMembership)
               .filter_by(cycle_id=cycle.id).count())
    linked = (session.query(models.CycleFinding)
              .filter_by(cycle_id=cycle.id).count())
    return {"id": cycle.id, "name": cycle.name, "description": cycle.description,
            "owner": cycle.owner, "state": cycle.state,
            "starts_on": cycle.starts_on.isoformat() if cycle.starts_on else None,
            "ends_on": cycle.ends_on.isoformat() if cycle.ends_on else None,
            "charter": cycle.charter or {}, "selection": cycle.selection or {},
            "snapshot": cycle.snapshot or {},
            "snapshot_at": cycle.snapshot_at.isoformat() if cycle.snapshot_at else None,
            "activated_at": cycle.activated_at.isoformat()
            if cycle.activated_at else None,
            "review": cycle.review or {},
            "closed_at": cycle.closed_at.isoformat() if cycle.closed_at else None,
            "members": members, "linked_findings": linked,
            "grants_authorization": False}


class CycleIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=8192)
    owner: str | None = Field(default=None, max_length=255)
    starts_on: str | None = None
    ends_on: str | None = None
    charter: dict = Field(default_factory=dict)
    selection: dict = Field(default_factory=dict)
    actor: str = Field(default="system", max_length=255)


class CyclePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=8192)
    owner: str | None = Field(default=None, max_length=255)
    starts_on: str | None = None
    ends_on: str | None = None
    charter: dict | None = None
    selection: dict | None = None
    actor: str = Field(default="system", max_length=255)


class LinkFindingsIn(BaseModel):
    finding_ids: list[str] = Field(default_factory=list, max_length=2000)
    auto: bool = False
    actor: str = Field(default="system", max_length=255)


class ReviewIn(BaseModel):
    results: str | None = Field(default=None, max_length=20000)
    criteria: list[dict] = Field(default_factory=list, max_length=100)
    learnings: str | None = Field(default=None, max_length=20000)
    actor: str = Field(default="system", max_length=255)


@router.get("")
def list_cycles(state_filter: str | None = Query(default=None, alias="state"),
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    query = session.query(models.Cycle).filter_by(org_id=org.id)
    if state_filter:
        query = query.filter(models.Cycle.state == state_filter)
    rows = query.order_by(models.Cycle.created_at.desc()).all()
    return {"data": [_cycle_data(session, row) for row in rows], "total": len(rows)}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_cycle(payload: CycleIn = None,
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    name = payload.name.strip()
    if (session.query(models.Cycle)
            .filter_by(org_id=org.id, name=name).one_or_none()):
        raise HTTPException(status.HTTP_409_CONFLICT, "a cycle with that name exists")
    cycle = models.Cycle(
        org_id=org.id, name=name, description=payload.description,
        owner=payload.owner, state="planning",
        starts_on=_ts(payload.starts_on, "starts_on"),
        ends_on=_ts(payload.ends_on, "ends_on"),
        charter=payload.charter or {}, selection=payload.selection or {},
        created_by=payload.actor)
    session.add(cycle)
    session.flush()
    _audit_log(session, org.id, payload.actor, "cycle.created", "cycle", cycle.id, name)
    session.commit()
    return {"data": _cycle_data(session, cycle)}


@router.get("/{cycle_id}")
def get_cycle(cycle_id: str,
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    cycle = _cycle_or_404(session, org.id, cycle_id)
    members = (session.query(models.CycleMembership)
               .filter_by(cycle_id=cycle.id, removed_at=None)
               .order_by(models.CycleMembership.entity_type).all())
    findings = (session.query(models.CycleFinding)
                .filter_by(cycle_id=cycle.id).all())
    finding_rows = []
    for link in findings:
        finding = session.get(models.Finding, link.finding_id)
        if finding is None:
            continue
        finding_rows.append({"id": finding.id, "title": finding.title,
                             "severity": severity_vocab.canonical(finding.severity),
                             "status": finding.status,
                             "source": link.source,
                             "linked_at": link.linked_at.isoformat()})
    return {"data": {**_cycle_data(session, cycle),
                     "membership": [{"entity_type": row.entity_type,
                                     "entity_id": row.entity_id,
                                     "label": row.label,
                                     "included_at": row.included_at.isoformat()}
                                    for row in members],
                     "findings": finding_rows}}


@router.patch("/{cycle_id}")
def patch_cycle(cycle_id: str, payload: CyclePatch = None,
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    cycle = _cycle_or_404(session, org.id, cycle_id)
    if cycle.state != "planning":
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "an activated cycle is frozen; changing it needs a new cycle or an "
            "explicit amendment (post-v0)")
    changes = []
    for field_name in ("name", "description", "owner"):
        value = getattr(payload, field_name)
        if value is not None:
            setattr(cycle, field_name, value)
            changes.append(field_name)
    for field_name in ("starts_on", "ends_on"):
        value = getattr(payload, field_name)
        if value is not None:
            setattr(cycle, field_name, _ts(value, field_name))
            changes.append(field_name)
    if payload.charter is not None:
        cycle.charter = payload.charter
        changes.append("charter")
    if payload.selection is not None:
        cycle.selection = payload.selection
        changes.append("selection")
    if not changes:
        return {"data": _cycle_data(session, cycle), "changed": False}
    cycle.updated_at = models.utcnow()
    _audit_log(session, org.id, payload.actor, "cycle.updated", "cycle", cycle.id,
               ", ".join(changes))
    session.commit()
    return {"data": _cycle_data(session, cycle), "changed": True}


@router.post("/{cycle_id}/preview")
def preview(cycle_id: str,
            org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    """What activation would freeze, plus what is still missing."""
    cycle = _cycle_or_404(session, org.id, cycle_id)
    selection = cycle.selection or {}
    members, gaps = _resolve_selection(session, org, selection)
    targets = (session.query(models.ScopeTarget)
               .filter_by(org_id=org.id, status="active").all())
    assets = [member for member in members if member["entity_type"] == "asset"]
    needs_review = (session.query(models.Asset)
                    .filter_by(org_id=org.id)
                    .filter(models.Asset.classification_status.in_(
                        ["unclassified", "pending"])).count())
    grants = (session.query(models.ScanGrant).filter_by(org_id=org.id).count())
    incomplete = not members and not selection.get("whole_org")
    if incomplete:
        gaps.append("selection is empty: an empty selection is incomplete, "
                    "not 'the whole organization'")
    return {"data": {"cycle": cycle.id, "state": cycle.state,
                     "members": len(members), "assets": len(assets),
                     "by_type": {kind: sum(1 for item in members
                                           if item["entity_type"] == kind)
                                 for kind in {item["entity_type"] for item in members}},
                     "members_preview": members[:50],
                     "scope_targets": len(targets),
                     "pending_review_assets": needs_review,
                     "recorded_grants": grants,
                     "incomplete": incomplete,
                     "gaps": gaps,
                     "grants_authorization": False,
                     "note": ("a cycle describes what will be evaluated; it does not "
                              "authorize anything. Active testing still needs a scope "
                              "target and a scan grant.")}}


@router.post("/{cycle_id}/activate")
def activate(cycle_id: str, actor: str = Query(default="console"),
             org: models.Organization = Depends(auth.require_org),
             session: Session = Depends(get_session)):
    cycle = _cycle_or_404(session, org.id, cycle_id)
    if cycle.state != "planning":
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"only a planning cycle can be activated (state {cycle.state})")
    members, gaps = _resolve_selection(session, org, cycle.selection or {})
    if not members:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "empty selection: choose projects, groups or environments, or set "
            "whole_org explicitly")
    now = models.utcnow()
    for member in members:
        session.add(models.CycleMembership(
            org_id=org.id, cycle_id=cycle.id,
            entity_type=member["entity_type"], entity_id=member["entity_id"],
            label=member["label"], included_at=now))
    cycle.snapshot = {"charter": cycle.charter or {},
                      "selection": cycle.selection or {},
                      "members": len(members),
                      "by_type": {kind: sum(1 for item in members
                                            if item["entity_type"] == kind)
                                  for kind in {item["entity_type"] for item in members}},
                      "gaps": gaps, "frozen_at": now.isoformat()}
    cycle.snapshot_at = now
    cycle.activated_at = now
    cycle.state = "active"
    cycle.updated_at = now
    _audit_log(session, org.id, actor, "cycle.activated", "cycle", cycle.id,
               f"{len(members)} members frozen")
    session.commit()
    return {"data": _cycle_data(session, cycle),
            "membership": len(members), "gaps": gaps}


@router.post("/{cycle_id}/link-findings")
def link_findings(cycle_id: str, payload: LinkFindingsIn = None,
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    """Link findings by id, or auto-link everything in the frozen projects."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    cycle = _cycle_or_404(session, org.id, cycle_id)
    if cycle.state == "planning":
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "activate the cycle before linking findings")
    linked, skipped = [], []
    candidates = set(payload.finding_ids)
    memberships = (session.query(models.CycleMembership)
                   .filter_by(cycle_id=cycle.id).all())
    project_ids = {row.entity_id for row in memberships
                   if row.entity_type == "project"}
    frozen_assets = {row.entity_id for row in memberships
                     if row.entity_type == "asset"}
    frozen_deployments = {row.entity_id for row in memberships
                          if row.entity_type == "deployment"}
    # An environment/asset selection still implies the projects those resources
    # belong to; otherwise auto-link would search an empty project set and link
    # nothing at all.
    for asset_id in frozen_assets:
        asset = session.get(models.Asset, asset_id)
        if asset is not None and asset.project_id:
            project_ids.add(asset.project_id)
    for deployment_id in frozen_deployments:
        for link in (session.query(models.AssetLink)
                     .filter_by(org_id=org.id, entity_type="deployment",
                                entity_id=deployment_id, removed_at=None).all()):
            asset = session.get(models.Asset, link.asset_id)
            if asset is not None and asset.project_id:
                project_ids.add(asset.project_id)
    selection = cycle.selection or {}
    # A project (or whole-org) selection is already the declared scope; assets
    # frozen alongside it are convenience members, not a narrower filter. An
    # asset/group/environment selection is narrower than the project and must be
    # respected when auto-linking.
    declared_projects = bool(selection.get("projects")) or bool(selection.get("whole_org"))
    narrow = bool(frozen_assets or frozen_deployments) and not declared_projects
    if not project_ids and not narrow:
        # Nothing resolved: the cycle froze no project and no resource.
        project_ids = set()
    if payload.auto:
        for finding in (session.query(models.Finding)
                        .filter(models.Finding.org_id == org.id,
                                models.Finding.project_id.in_(project_ids)).all()):
            if narrow:
                contexts = (session.query(models.FindingContext)
                            .filter_by(finding_id=finding.id, removed_at=None).all())
                in_scope = any(
                    (row.entity_type == "asset" and row.entity_id in frozen_assets)
                    or (row.entity_type == "deployment"
                        and row.entity_id in frozen_deployments)
                    for row in contexts)
                if not in_scope:
                    skipped.append({
                        "finding_id": finding.id,
                        "reason": ("the cycle froze specific assets or deployments and "
                                   "this finding has no location among them")})
                    continue
            candidates.add(finding.id)
    for finding_id in candidates:
        finding = session.get(models.Finding, finding_id)
        if finding is None or finding.org_id != org.id:
            skipped.append({"finding_id": finding_id,
                            "reason": "not found in this organization"})
            continue
        existing = (session.query(models.CycleFinding)
                    .filter_by(cycle_id=cycle.id, finding_id=finding.id).one_or_none())
        if existing is not None:
            continue
        session.add(models.CycleFinding(
            org_id=org.id, cycle_id=cycle.id, finding_id=finding.id,
            source="auto" if payload.auto and finding_id not in payload.finding_ids
            else "manual"))
        linked.append(finding.id)
    _audit_log(session, org.id, payload.actor, "cycle.findings_linked", "cycle",
               cycle.id, f"{len(linked)} linked, {len(skipped)} skipped")
    session.commit()
    return {"data": {"linked": len(linked), "skipped": skipped}}


@router.get("/{cycle_id}/candidates")
def candidates(cycle_id: str,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """Resources discovered after the frozen reference: next cycle's input."""
    cycle = _cycle_or_404(session, org.id, cycle_id)
    if cycle.snapshot_at is None:
        return {"data": [], "total": 0,
                "note": "the cycle has not been activated; there is no reference yet"}
    snapshot_at = cycle.snapshot_at
    if snapshot_at.tzinfo is None:
        snapshot_at = snapshot_at.replace(tzinfo=timezone.utc)
    member_ids = {row.entity_id for row in
                  session.query(models.CycleMembership)
                  .filter_by(cycle_id=cycle.id).all()}
    rows = []
    for asset in (session.query(models.Asset)
                  .filter_by(org_id=org.id).all()):
        discovered = asset.discovered_at if asset.discovered_at.tzinfo \
            else asset.discovered_at.replace(tzinfo=timezone.utc)
        if discovered > snapshot_at and asset.id not in member_ids:
            project = session.get(models.Project, asset.project_id) \
                if asset.project_id else None
            rows.append({"asset": {"id": asset.id, "value": asset.value,
                                   "type": asset.type},
                         "discovered_at": asset.discovered_at.isoformat(),
                         "project": project.slug if project else None,
                         "recommended_for": "next cycle"})
    return {"data": rows, "total": len(rows),
            "note": ("candidates are outside this cycle's frozen reference; v0 shows "
                     "them here and expects them in the next cycle")}


@router.post("/{cycle_id}/review")
def submit_review(cycle_id: str, payload: ReviewIn = None,
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    cycle = _cycle_or_404(session, org.id, cycle_id)
    if cycle.state != "active":
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"only an active cycle can move to review (state {cycle.state})")
    criteria = []
    for item in payload.criteria:
        verdict = item.get("verdict", "pending")
        if verdict not in CRITERIA_VERDICTS:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"criterion verdict must be one of "
                                f"{sorted(CRITERIA_VERDICTS)}")
        criteria.append({"name": item.get("name"), "verdict": verdict,
                         "note": item.get("note")})
    cycle.review = {"results": payload.results, "criteria": criteria,
                    "learnings": payload.learnings,
                    "recorded_at": models.utcnow().isoformat()}
    cycle.state = "review"
    cycle.updated_at = models.utcnow()
    _audit_log(session, org.id, payload.actor, "cycle.review_recorded", "cycle",
               cycle.id, f"{len(criteria)} criteria recorded")
    session.commit()
    return {"data": _cycle_data(session, cycle)}


@router.post("/{cycle_id}/close")
def close_cycle(cycle_id: str, actor: str = Query(default="console"),
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    cycle = _cycle_or_404(session, org.id, cycle_id)
    if cycle.state != "review":
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"only a cycle in review can be closed (state {cycle.state})")
    cycle.state = "closed"
    cycle.closed_at = models.utcnow()
    cycle.updated_at = cycle.closed_at
    _audit_log(session, org.id, actor, "cycle.closed", "cycle", cycle.id,
               "history kept; the inventory keeps running")
    session.commit()
    return {"data": _cycle_data(session, cycle)}

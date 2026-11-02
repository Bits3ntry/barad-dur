"""v0 inventory groups and the activity feed.

Inventory groups organize *resources* — they are not access groups, and adding
an asset to one grants nobody a permission. Membership is N:M and soft-removed
so that "taken out of a group" never destroys the asset, its links, or the
activity trail.

The activity feed reads the org's hash-chained audit ledger; it is a filtered
view of the same rows the Audit trail screen shows, not a second log.
"""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1", tags=["inventory"])

MAX_MEMBERS_PER_CALL = 500


def _group_or_404(session: Session, org_id: str, group_id: str) -> models.InventoryGroup:
    group = session.get(models.InventoryGroup, group_id)
    if group is None or group.org_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "group not found")
    return group


def _stakeholders(session: Session, group_id: str) -> list[dict]:
    rows = (session.query(models.InventoryGroupStakeholder)
            .filter_by(group_id=group_id).order_by(models.InventoryGroupStakeholder.added_at).all())
    return [{"actor": row.actor, "role": row.role,
             "added_at": row.added_at.isoformat()} for row in rows]


def _members(session: Session, group_id: str, include_removed: bool = False) -> list[dict]:
    query = (session.query(models.InventoryGroupMember)
             .filter_by(group_id=group_id))
    if not include_removed:
        query = query.filter(models.InventoryGroupMember.removed_at.is_(None))
    rows = query.order_by(models.InventoryGroupMember.added_at).all()
    data = []
    for row in rows:
        asset = session.get(models.Asset, row.asset_id)
        data.append({
            "asset_id": row.asset_id,
            "type": asset.type if asset else None,
            "value": asset.value if asset else None,
            "source": asset.source if asset else None,
            "added_by": row.added_by,
            "added_at": row.added_at.isoformat(),
            "removed_at": row.removed_at.isoformat() if row.removed_at else None,
        })
    return data


def _group_data(session: Session, group: models.InventoryGroup) -> dict:
    members = _members(session, group.id)
    return {
        "id": group.id,
        "name": group.name,
        "description": group.description,
        "notes": group.notes,
        "tags": group.tags or [],
        "created_by": group.created_by,
        "created_at": group.created_at.isoformat(),
        "updated_at": group.updated_at.isoformat(),
        "member_count": len(members),
        "members": members,
        "stakeholders": _stakeholders(session, group.id),
    }


class GroupCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=4096)
    notes: str | None = Field(default=None, max_length=8192)
    tags: list[str] = Field(default_factory=list)
    actor: str | None = Field(default=None, max_length=255)


class GroupPatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=4096)
    notes: str | None = Field(default=None, max_length=8192)
    tags: list[str] | None = None
    actor: str | None = Field(default=None, max_length=255)


class GroupAssets(BaseModel):
    asset_ids: list[str] = Field(min_length=1, max_length=MAX_MEMBERS_PER_CALL)
    actor: str | None = Field(default=None, max_length=255)


class StakeholderIn(BaseModel):
    actor: str = Field(min_length=1, max_length=255)
    role: str = Field(default="collaborator")
    changed_by: str | None = Field(default=None, max_length=255)


@router.get("/inventory/groups")
def list_groups(org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    rows = (session.query(models.InventoryGroup)
            .filter_by(org_id=org.id)
            .order_by(models.InventoryGroup.name).all())
    data = []
    for group in rows:
        members = _members(session, group.id)
        data.append({
            "id": group.id, "name": group.name, "description": group.description,
            "notes": group.notes, "tags": group.tags or [],
            "created_by": group.created_by,
            "updated_at": group.updated_at.isoformat(),
            "member_count": len(members),
            "stakeholders": _stakeholders(session, group.id),
        })
    return {"data": data, "total": len(data)}


@router.post("/inventory/groups", status_code=status.HTTP_201_CREATED)
def create_group(payload: GroupCreate = None,
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    name = payload.name.strip()
    existing = (session.query(models.InventoryGroup)
                .filter_by(org_id=org.id, name=name).one_or_none())
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "a group with that name exists")
    group = models.InventoryGroup(
        org_id=org.id, name=name, description=payload.description,
        notes=payload.notes, tags=list(payload.tags or []),
        created_by=payload.actor)
    session.add(group)
    session.flush()
    _audit_log(session, org.id, payload.actor or "system", "inventory_group.created",
               "inventory_group", group.id, name)
    session.commit()
    return {"data": _group_data(session, group)}


@router.get("/inventory/groups/{group_id}")
def get_group(group_id: str,
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    group = _group_or_404(session, org.id, group_id)
    data = _group_data(session, group)
    data["removed_members"] = _members(session, group.id, include_removed=True)
    data["removed_members"] = [m for m in data["removed_members"] if m["removed_at"]]
    return {"data": data}


@router.patch("/inventory/groups/{group_id}")
def patch_group(group_id: str, payload: GroupPatch = None,
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    group = _group_or_404(session, org.id, group_id)
    changes = []
    if payload.name is not None and payload.name.strip() != group.name:
        name = payload.name.strip()
        clash = (session.query(models.InventoryGroup)
                 .filter(models.InventoryGroup.org_id == org.id,
                         models.InventoryGroup.name == name,
                         models.InventoryGroup.id != group.id).one_or_none())
        if clash is not None:
            raise HTTPException(status.HTTP_409_CONFLICT, "a group with that name exists")
        changes.append(f"name={name}")
        group.name = name
    for field_name in ("description", "notes"):
        value = getattr(payload, field_name)
        if value is not None:
            changes.append(field_name)
            setattr(group, field_name, value)
    if payload.tags is not None:
        group.tags = list(payload.tags)
        changes.append("tags")
    if not changes:
        return {"data": _group_data(session, group), "changed": False}
    group.updated_at = models.utcnow()
    _audit_log(session, org.id, payload.actor or "system", "inventory_group.updated",
               "inventory_group", group.id, ", ".join(changes))
    session.commit()
    return {"data": _group_data(session, group), "changed": True}


@router.delete("/inventory/groups/{group_id}", status_code=status.HTTP_200_OK)
def delete_group(group_id: str,
                 actor: str | None = Query(default=None),
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """Deleting a group never touches its assets; only the grouping disappears."""
    group = _group_or_404(session, org.id, group_id)
    name = group.name
    member_count = len(_members(session, group.id))
    session.delete(group)
    _audit_log(session, org.id, actor or "system", "inventory_group.deleted",
               "inventory_group", group_id, f"{name} ({member_count} members kept)")
    session.commit()
    return {"deleted": group_id, "name": name, "members_kept": member_count}


@router.post("/inventory/groups/{group_id}/assets")
def add_assets(group_id: str, payload: GroupAssets = None,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """Attach assets individually or in bulk; re-adding a removed one revives it."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    group = _group_or_404(session, org.id, group_id)
    added, already, missing = [], [], []
    for asset_id in payload.asset_ids:
        asset = session.get(models.Asset, asset_id)
        if asset is None or asset.org_id != org.id:
            missing.append(asset_id)
            continue
        row = (session.query(models.InventoryGroupMember)
               .filter_by(group_id=group.id, asset_id=asset.id).one_or_none())
        if row is None:
            row = models.InventoryGroupMember(
                org_id=org.id, group_id=group.id, asset_id=asset.id,
                added_by=payload.actor, added_at=models.utcnow())
            session.add(row)
            added.append(asset.value)
        elif row.removed_at is not None:
            row.removed_at = None
            row.added_by = payload.actor
            row.added_at = models.utcnow()
            added.append(asset.value)
        else:
            already.append(asset.value)
    if missing:
        session.rollback()
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            f"assets not found in this organization: {missing}")
    if added:
        _audit_log(session, org.id, payload.actor or "system",
                   "inventory_group.assets_added", "inventory_group", group.id,
                   f"{len(added)} assets: {', '.join(added[:5])}")
    session.commit()
    return {"data": _group_data(session, group),
            "added": added, "already_member": already}


@router.delete("/inventory/groups/{group_id}/assets/{asset_id}",
               status_code=status.HTTP_200_OK)
def remove_asset(group_id: str, asset_id: str,
                 actor: str | None = Query(default=None),
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    group = _group_or_404(session, org.id, group_id)
    row = (session.query(models.InventoryGroupMember)
           .filter_by(group_id=group.id, asset_id=asset_id,
                      removed_at=None).one_or_none())
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset is not a member of this group")
    asset = session.get(models.Asset, asset_id)
    row.removed_at = models.utcnow()
    _audit_log(session, org.id, actor or "system", "inventory_group.asset_removed",
               "inventory_group", group.id,
               asset.value if asset else asset_id)
    session.commit()
    return {"data": _group_data(session, group), "removed": asset_id}


@router.post("/inventory/groups/{group_id}/stakeholders",
             status_code=status.HTTP_201_CREATED)
def add_stakeholder(group_id: str, payload: StakeholderIn = None,
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.role not in models.INVENTORY_GROUP_ROLES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"role must be one of {sorted(models.INVENTORY_GROUP_ROLES)}")
    group = _group_or_404(session, org.id, group_id)
    row = (session.query(models.InventoryGroupStakeholder)
           .filter_by(group_id=group.id, actor=payload.actor).one_or_none())
    if row is None:
        row = models.InventoryGroupStakeholder(
            org_id=org.id, group_id=group.id, actor=payload.actor, role=payload.role)
        session.add(row)
        action = "inventory_group.stakeholder_added"
    else:
        row.role = payload.role
        action = "inventory_group.stakeholder_role_changed"
    _audit_log(session, org.id, payload.changed_by or payload.actor, action,
               "inventory_group", group.id, f"{payload.actor} ({payload.role})")
    session.commit()
    return {"data": _group_data(session, group)}


@router.delete("/inventory/groups/{group_id}/stakeholders/{actor}")
def remove_stakeholder(group_id: str, actor: str,
                       changed_by: str | None = Query(default=None),
                       org: models.Organization = Depends(auth.require_org),
                       session: Session = Depends(get_session)):
    group = _group_or_404(session, org.id, group_id)
    row = (session.query(models.InventoryGroupStakeholder)
           .filter_by(group_id=group.id, actor=actor).one_or_none())
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "stakeholder not found")
    session.delete(row)
    _audit_log(session, org.id, changed_by or actor, "inventory_group.stakeholder_removed",
               "inventory_group", group.id, actor)
    session.commit()
    return {"data": _group_data(session, group)}


@router.get("/activity")
def activity(resource_type: str | None = Query(default=None),
             resource_id: str | None = Query(default=None),
             asset_id: str | None = Query(default=None),
             action: str | None = Query(default=None),
             actor: str | None = Query(default=None),
             limit: int = Query(default=50, ge=1, le=200),
             offset: int = Query(default=0, ge=0),
             org: models.Organization = Depends(auth.require_org),
             session: Session = Depends(get_session)):
    """One feed for "what happened here": audit rows filtered by resource.

    `asset_id` is a convenience: it matches audit rows about the asset itself
    and about any group it moved in or out of, because a reader asking "what
    happened to this host" means both.
    """
    query = session.query(models.AuditLog).filter(models.AuditLog.org_id == org.id)
    if resource_type:
        query = query.filter(models.AuditLog.resource_type == resource_type)
    if resource_id:
        query = query.filter(models.AuditLog.resource_id == resource_id)
    if action:
        query = query.filter(models.AuditLog.action.like(f"{action}%"))
    if actor:
        query = query.filter(models.AuditLog.actor == actor)
    if asset_id:
        asset = session.get(models.Asset, asset_id)
        if asset is None or asset.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
        group_ids = [row.group_id for row in
                     session.query(models.InventoryGroupMember).filter_by(asset_id=asset.id)]
        values = [asset_id, *group_ids]
        query = query.filter(models.AuditLog.resource_id.in_(values))
    total = query.count()
    rows = (query.order_by(models.AuditLog.chain_position.desc())
            .offset(offset).limit(limit).all())
    return {"data": [{
        "id": row.id, "at": row.created_at.isoformat(), "actor": row.actor,
        "action": row.action, "resource_type": row.resource_type,
        "resource_id": row.resource_id, "detail": row.detail,
        "chain_position": row.chain_position,
    } for row in rows], "total": total}

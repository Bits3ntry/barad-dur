"""B2: org members (roles) and the per-org hash-chained audit ledger."""
import datetime
import hashlib
import json

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import text as sql_text
from sqlalchemy.orm import Session

from backend.app import auth, models
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1", tags=["identity"])

GENESIS_HASH = "0" * 64
ROLE_WRITE = {"owner", "admin"}  # who may add/remove members


class MemberAdd(BaseModel):
    identity: str = Field(min_length=3, max_length=255)
    role: str = "viewer"
    added_by: str | None = Field(default=None, max_length=255)


class MemberPatch(BaseModel):
    role: str
    changed_by: str | None = None


def _audit(session: Session, org_id: str, actor: str, action: str,
           resource_type: str | None = None, resource_id: str | None = None,
           detail: str | None = None) -> models.AuditLog:
    """Append one chain entry; serialized by an advisory lock per org (Postgres;
    SQLite's single-writer lock covers the tests the same way)."""
    if session.get_bind().dialect.name == "postgresql":
        lock = session.execute(sql_text("SELECT pg_advisory_xact_lock(hashtext(:k))"),
                               {"k": f"audit:{org_id}"})
        del lock
    last = (session.query(models.AuditLog)
            .filter_by(org_id=org_id)
            .order_by(models.AuditLog.chain_position.desc())
            .first())
    position = (last.chain_position + 1) if last else 1
    prev_hash = last.hash if last else GENESIS_HASH
    payload = json.dumps({
        "actor": actor, "action": action,
        "resource_type": resource_type, "resource_id": resource_id,
        "detail": detail,
    }, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(f"{prev_hash}|{position}|".encode() + payload.encode()).hexdigest()
    entry = models.AuditLog(
        org_id=org_id, actor=actor, action=action, resource_type=resource_type,
        resource_id=resource_id, detail=detail, chain_position=position,
        prev_hash=prev_hash, hash=digest)
    session.add(entry)
    session.flush()
    return entry


def _require_writer(org: models.Organization, actor: str | None) -> None:
    """The POC stays API-key authenticated; writes are limited to the key's
    org, and membership changes must name an accountable actor."""
    if not actor or not actor.strip():
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "changed_by/added_by is required (accountability)")


@router.get("/members")
def list_members(org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    rows = (session.query(models.OrgMember)
            .filter_by(org_id=org.id)
            .order_by(models.OrgMember.created_at).all())
    return {"data": [{"id": r.id, "identity": r.identity, "role": r.role,
                      "added_by": r.added_by, "status": r.status} for r in rows],
            "total": len(rows)}


@router.post("/members")
def add_member(payload: MemberAdd = None,
               org: models.Organization = Depends(auth.require_admin),
               session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.role not in models.ROLES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"role must be one of {sorted(models.ROLES)}")
    _require_writer(org, payload.added_by)
    existing = (session.query(models.OrgMember)
                .filter_by(org_id=org.id, identity=payload.identity).one_or_none())
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "member exists")
    member = models.OrgMember(org_id=org.id, identity=payload.identity,
                              role=payload.role, added_by=payload.added_by,
                              created_at=models.utcnow(), updated_at=models.utcnow())
    session.add(member)
    session.flush()
    _audit(session, org.id, payload.added_by, "member.added",
           "member", member.id, f"{payload.identity} as {payload.role}")
    session.commit()
    return {"data": {"id": member.id, "identity": member.identity,
                     "role": member.role, "status": member.status}}


@router.patch("/members/{member_id}")
def patch_member(member_id: str, payload: MemberPatch = None,
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.role not in models.ROLES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"role must be one of {sorted(models.ROLES)}")
    _require_writer(org, payload.changed_by)
    member = session.get(models.OrgMember, member_id)
    if member is None or member.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "member not found")
    previous = member.role
    member.role = payload.role
    member.updated_at = models.utcnow()
    _audit(session, org.id, payload.changed_by or "system", "member.role_changed",
           "member", member.id, f"{member.identity}: {previous} -> {payload.role}")
    session.commit()
    return {"data": {"id": member.id, "identity": member.identity, "role": member.role}}


@router.delete("/members/{member_id}")
def remove_member(member_id: str, changed_by: str = "",
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    _require_writer(org, changed_by or None)
    member = session.get(models.OrgMember, member_id)
    if member is None or member.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "member not found")
    member.status = "removed"
    member.updated_at = models.utcnow()
    _audit(session, org.id, changed_by, "member.removed", "member", member.id,
           member.identity)
    session.commit()
    return {"data": {"id": member.id, "status": member.status}}


@router.get("/audit")
def read_audit(actor: str | None = None, action: str | None = None,
               since: str | None = None, until: str | None = None,
               q: str | None = None,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """Filtered read; filters are server-side (actor, action prefix, window,
    free text on the recorded detail)."""
    query = (session.query(models.AuditLog)
             .filter_by(org_id=org.id))
    if actor:
        query = query.filter(models.AuditLog.actor.contains(actor))
    if action:
        query = query.filter(models.AuditLog.action.contains(action))
    if since:
        query = query.filter(models.AuditLog.created_at >= _parse_ts(since))
    if until:
        query = query.filter(models.AuditLog.created_at <= _parse_ts(until))
    rows = query.order_by(models.AuditLog.chain_position).all()
    if q:
        needle = q.lower()
        rows = [r for r in rows if needle in (r.detail or "").lower()
                or needle in r.action.lower()]
    rows_in_full_chain = session.query(models.AuditLog).filter_by(org_id=org.id)
    full_rows = rows_in_full_chain.order_by(models.AuditLog.chain_position).all()
    # The verification ALWAYS walks the complete per-org ledger, no matter
    # which filters or pages the caller displays — a tampered entry outside
    # the filtered window cannot hide behind `chain_ok: true`.
    chain_ok = True
    verify_hash = GENESIS_HASH
    for entry in full_rows:
        payload = json.dumps({
            "actor": entry.actor, "action": entry.action,
            "resource_type": entry.resource_type, "resource_id": entry.resource_id,
            "detail": entry.detail,
        }, sort_keys=True, separators=(",", ":"))
        expected = hashlib.sha256(f"{verify_hash}|{entry.chain_position}|".encode() + payload.encode()).hexdigest()
        if entry.prev_hash != verify_hash or entry.hash != expected:
            chain_ok = False
            break
        verify_hash = entry.hash
    return {"data": [{"position": r.chain_position, "actor": r.actor, "action": r.action,
                      "resource_type": r.resource_type, "resource_id": r.resource_id,
                      "detail": r.detail, "hash": r.hash, "prev_hash": r.prev_hash,
                      "at": r.created_at.isoformat()} for r in rows],
            "total": len(full_rows), "shown": len(rows), "chain_ok": chain_ok,
            "chain_position": full_rows[-1].chain_position if full_rows else 0}


def _parse_ts(value: str) -> datetime.datetime:
    from datetime import datetime as dt

    parsed = dt.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed

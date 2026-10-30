"""Static scope endpoints: what may be audited or analyzed (F3, no letters)."""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from backend.app import auth, models
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1/scope", tags=["scope"])

SCOPE_TYPES = {"repository", "service", "host", "domain", "api"}


class ScopeEntry(BaseModel):
    target_type: str
    value: str = Field(min_length=1, max_length=1024)
    note: str | None = None
    reason: str | None = None

    @field_validator("target_type")
    @classmethod
    def type_known(cls, value):
        if value not in SCOPE_TYPES:
            raise ValueError(f"target_type must be one of {sorted(SCOPE_TYPES)}")
        return value


def _target_data(row: models.ScopeTarget) -> dict:
    return {"id": row.id, "target_type": row.target_type, "value": row.value,
            "status": row.status, "note": row.note,
            "created_at": row.created_at.isoformat()}


def _exclusion_data(row: models.ScopeExclusion) -> dict:
    return {"id": row.id, "target_type": row.target_type, "value": row.value,
            "reason": row.reason, "created_at": row.created_at.isoformat()}


@router.get("/targets")
def targets(org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    rows = (session.query(models.ScopeTarget)
            .filter_by(org_id=org.id)
            .order_by(models.ScopeTarget.target_type, models.ScopeTarget.value).all())
    return {"data": [_target_data(row) for row in rows], "total": len(rows)}


@router.post("/targets")
def add_target(payload: ScopeEntry = None,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    existing = (session.query(models.ScopeTarget)
                .filter_by(org_id=org.id, target_type=payload.target_type,
                           value=payload.value).one_or_none())
    if existing is not None:
        return {"data": _target_data(existing)}
    row = models.ScopeTarget(
        org_id=org.id, target_type=payload.target_type, value=payload.value,
        note=payload.note, created_at=models.utcnow(), updated_at=models.utcnow())
    session.add(row)
    session.commit()
    return {"data": _target_data(row)}


@router.get("/exclusions")
def exclusions(org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    rows = (session.query(models.ScopeExclusion)
            .filter_by(org_id=org.id)
            .order_by(models.ScopeExclusion.target_type, models.ScopeExclusion.value).all())
    return {"data": [_exclusion_data(row) for row in rows], "total": len(rows)}


@router.post("/exclusions")
def add_exclusion(payload: ScopeEntry = None,
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if not payload.reason:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "reason required")
    existing = (session.query(models.ScopeExclusion)
                .filter_by(org_id=org.id, target_type=payload.target_type,
                           value=payload.value).one_or_none())
    if existing is not None:
        return {"data": _exclusion_data(existing)}
    row = models.ScopeExclusion(
        org_id=org.id, target_type=payload.target_type, value=payload.value,
        reason=payload.reason, created_at=models.utcnow(), updated_at=models.utcnow())
    session.add(row)
    session.commit()
    return {"data": _exclusion_data(row)}


@router.get("/resolved")
def resolved(org: models.Organization = Depends(auth.require_org),
             session: Session = Depends(get_session)):
    """Active targets minus excluded values, matching type AND value."""
    active = (session.query(models.ScopeTarget)
              .filter_by(org_id=org.id, status="active").all())
    excluded = {(row.target_type, row.value)
                for row in session.query(models.ScopeExclusion)
                .filter_by(org_id=org.id).all()}
    got = [_target_data(row) for row in active if (row.target_type, row.value) not in excluded]
    excluded_rows = (session.query(models.ScopeExclusion)
                     .filter_by(org_id=org.id).all())
    return {"data": got, "total": len(got),
            "excluded": [_exclusion_data(row) for row in excluded_rows],
            "excluded_count": len(excluded_rows)}

"""Organization settings and API-key lifecycle (create/list/revoke)."""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/org", tags=["organization"])


def _org_data(row: models.Organization) -> dict:
    return {"id": row.id, "slug": row.slug, "name": row.name,
            "description": row.description, "website": row.website,
            "logo": row.logo,
            "onboarding_completed_at": (row.onboarding_completed_at.isoformat()
                                        if row.onboarding_completed_at else None),
            "created_at": row.created_at.isoformat() if row.created_at else None}


def _key_data(row: models.ApiKey) -> dict:
    return {"id": row.id, "label": row.label,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "revoked_at": row.revoked_at.isoformat() if row.revoked_at else None}


@router.get("")
def get_org(org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    return {"data": _org_data(org)}


class OrgPatch(BaseModel):
    # Every field is optional so the onboarding form can save one block at a
    # time; `name` stays here because Settings edits it in place.
    name: str | None = Field(default=None, min_length=2, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    website: str | None = Field(default=None, max_length=255)
    logo: str | None = Field(default=None, max_length=200_000)
    actor: str = Field(min_length=2, max_length=255)


@router.patch("")
def patch_org(payload: OrgPatch = None,
              org: models.Organization = Depends(auth.require_admin),
              session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if all(value is None for value in
           (payload.name, payload.description, payload.website, payload.logo)):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "nothing to update")
    if payload.website and not payload.website.startswith(("http://", "https://")):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "website must start with http:// or https://")
    if payload.logo and not payload.logo.startswith(("http://", "https://",
                                                     "data:image/")):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "logo must be an https URL or an inline image")
    changed = []
    if payload.name is not None and payload.name.strip() != org.name:
        changed.append(f"name {org.name} -> {payload.name.strip()}")
        org.name = payload.name.strip()
    if payload.description is not None and payload.description.strip() != (org.description or ""):
        org.description = payload.description.strip() or None
        changed.append("description")
    if payload.website is not None and payload.website.strip().rstrip("/") != (org.website or ""):
        org.website = payload.website.strip().rstrip("/") or None
        changed.append("website")
    if payload.logo is not None and payload.logo.strip() != (org.logo or ""):
        org.logo = payload.logo.strip() or None
        changed.append("logo")
    if changed:
        _audit_log(session, org.id, payload.actor, "org.updated", "organization",
                   org.id, ", ".join(changed)[:500])
        session.commit()
    return {"data": _org_data(org)}


@router.get("/keys")
def list_keys(org: models.Organization = Depends(auth.require_admin),
              session: Session = Depends(get_session)):
    rows = (session.query(models.ApiKey).filter_by(org_id=org.id)
            .order_by(models.ApiKey.created_at).all())
    return {"data": [_key_data(row) for row in rows], "total": len(rows)}


class KeyIn(BaseModel):
    label: str = Field(default="service", max_length=255)
    actor: str = Field(min_length=2, max_length=255)


@router.post("/keys")
def create_org_key(payload: KeyIn = None,
                   org: models.Organization = Depends(auth.require_admin),
                   session: Session = Depends(get_session)):
    """Mint a service identity. The raw key is returned exactly once."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    raw = auth.generate_api_key()
    row = models.ApiKey(org_id=org.id, key_hash=auth.key_hash(raw),
                        label=payload.label, created_at=models.utcnow())
    session.add(row)
    session.flush()
    _audit_log(session, org.id, payload.actor, "org.key_created", "api_key",
               row.id, payload.label)
    session.commit()
    return {"data": {**_key_data(row), "key": raw}}


class KeyRevokeIn(BaseModel):
    actor: str = Field(min_length=2, max_length=255)
    reason: str | None = None


@router.post("/keys/{key_id}/revoke")
def revoke_org_key(key_id: str, payload: KeyRevokeIn = None,
                   org: models.Organization = Depends(auth.require_admin),
                   session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    row = session.get(models.ApiKey, key_id)
    if row is None or row.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "key not found")
    if row.revoked_at is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "key already revoked")
    live = (session.query(models.ApiKey)
            .filter_by(org_id=org.id).filter(models.ApiKey.revoked_at.is_(None))
            .count())
    if live <= 1:
        # Never lock the org out of its own API.
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "cannot revoke the last active API key")
    row.revoked_at = models.utcnow()
    _audit_log(session, org.id, payload.actor, "org.key_revoked", "api_key",
               row.id, (payload.reason or "")[:200])
    session.commit()
    return {"data": _key_data(row)}

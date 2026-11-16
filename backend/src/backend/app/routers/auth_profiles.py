"""Reusable session recipes: how a tester gets in.

A login is an artifact of the engagement, not of one finding. Keeping it here means
one place to rotate a token, and forty findings that say `auth_profile_id` instead of
forty copies of a bearer header pasted into a report.
"""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/auth-profiles", tags=["auth-profiles"])

AUTH_KINDS = {"none", "bearer", "cookie", "header", "basic", "form_login", "oauth", "mtls"}


class AuthProfileIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    kind: str = Field(default="bearer", max_length=32)
    headers: str | None = Field(default=None, max_length=20000)
    login_steps: str | None = Field(default=None, max_length=20000)
    notes: str | None = Field(default=None, max_length=20000)
    actor: str = Field(default="console", max_length=255)


def _data(profile: models.AuthProfile) -> dict:
    return {"id": profile.id, "name": profile.name, "kind": profile.kind,
            "headers": profile.headers, "login_steps": profile.login_steps,
            "notes": profile.notes, "created_by": profile.created_by,
            "created_at": profile.created_at.isoformat() if profile.created_at else None}


@router.get("")
def list_auth_profiles(org: models.Organization = Depends(auth.require_org),
                       session: Session = Depends(get_session)):
    rows = (session.query(models.AuthProfile)
            .filter_by(org_id=org.id).order_by(models.AuthProfile.name).all())
    return {"data": [_data(row) for row in rows]}


@router.post("", status_code=status.HTTP_201_CREATED)
def create_auth_profile(payload: AuthProfileIn,
                        org: models.Organization = Depends(auth.require_org),
                        session: Session = Depends(get_session)):
    if payload.kind not in AUTH_KINDS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"kind must be one of {sorted(AUTH_KINDS)}")
    existing = (session.query(models.AuthProfile)
                .filter_by(org_id=org.id, name=payload.name.strip()).one_or_none())
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "an authentication profile with that name already exists")
    profile = models.AuthProfile(
        org_id=org.id, name=payload.name.strip(), kind=payload.kind,
        headers=payload.headers, login_steps=payload.login_steps,
        notes=payload.notes, created_by=payload.actor)
    session.add(profile)
    _audit_log(session, org.id, payload.actor, "auth_profile.created",
               "auth_profile", profile.id, profile.name)
    session.commit()
    return {"data": _data(profile)}


@router.patch("/{profile_id}")
def update_auth_profile(profile_id: str, payload: AuthProfileIn,
                        org: models.Organization = Depends(auth.require_org),
                        session: Session = Depends(get_session)):
    profile = session.get(models.AuthProfile, profile_id)
    if profile is None or profile.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "auth profile not found")
    if payload.kind not in AUTH_KINDS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"kind must be one of {sorted(AUTH_KINDS)}")
    profile.name = payload.name.strip()
    profile.kind = payload.kind
    profile.headers = payload.headers
    profile.login_steps = payload.login_steps
    profile.notes = payload.notes
    _audit_log(session, org.id, payload.actor, "auth_profile.updated",
               "auth_profile", profile.id, profile.name)
    session.commit()
    return {"data": _data(profile)}


@router.delete("/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_auth_profile(profile_id: str, actor: str = "console",
                        org: models.Organization = Depends(auth.require_org),
                        session: Session = Depends(get_session)):
    profile = session.get(models.AuthProfile, profile_id)
    if profile is None or profile.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "auth profile not found")
    in_use = (session.query(models.Finding)
              .filter_by(auth_profile_id=profile.id).count())
    if in_use:
        # Deleting would silently strip the how-to-reproduce from findings that
        # already rely on it.
        raise HTTPException(status.HTTP_409_CONFLICT,
                            f"the profile is used by {in_use} findings")
    _audit_log(session, org.id, actor, "auth_profile.deleted",
               "auth_profile", profile.id, profile.name)
    session.delete(profile)
    session.commit()
    return None

"""The organisations a person may work in, and creating a new one.

Two operations, both about the same fact: an account is a person, and a person
has seats. `GET` answers "where can I work, and with which role"; `POST` opens a
new organisation and seats the caller as its owner — the same act onboarding
does for the first one, minus the wizard.

An API key is not a person: it belongs to one organisation and creating another
with it would leave nobody able to log into the new one.
"""
from __future__ import annotations

import re
import unicodedata

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app import auth, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/orgs", tags=["orgs"])

SLUG = re.compile(r"[^a-z0-9]+")


def _slug_for(session: Session, name: str) -> str:
    # `verificación` → `verificacion`: NFKD splits the accent off and the regex
    # drops it, instead of turning the letter into a dash.
    plain = unicodedata.normalize("NFKD", name or "")
    plain = "".join(char for char in plain if not unicodedata.combining(char))
    base = SLUG.sub("-", plain.strip().lower()).strip("-")[:48] or "org"
    candidate, suffix = base, 1
    while (session.query(models.Organization)
           .filter_by(slug=candidate).one_or_none()) is not None:
        suffix += 1
        candidate = f"{base}-{suffix}"
    return candidate


def _rows_for(session: Session, principal: dict) -> list[dict]:
    """Every seat, with the numbers that make an organisation recognisable."""
    if principal["kind"] == "user":
        memberships = (session.query(models.OrganizationMember)
                       .filter_by(user_id=principal["user_id"]).all())
        seats = [(member.org_id, member.role) for member in memberships]
        # The home organisation is always a seat: a menu that omits where the
        # person is would make the screen they are looking at unlisted.
        if all(org_id != principal["org_id"] for org_id, _role in seats):
            seats.append((principal["org_id"], principal["role"]))
    else:
        seats = [(principal["org_id"], principal["role"])]

    rows = []
    for org_id, role in seats:
        org = session.get(models.Organization, org_id)
        if org is None:
            continue
        rows.append({
            "id": org.id, "name": org.name, "slug": org.slug,
            "logo": getattr(org, "logo", None),
            "role": role,
            "active": org.id == principal["org_id"],
            "members": session.query(func.count(models.OrganizationMember.id))
                             .filter_by(org_id=org.id).scalar() or 0,
            "projects": session.query(func.count(models.Project.id))
                              .filter_by(org_id=org.id).scalar() or 0,
            "findings": session.query(func.count(models.Finding.id))
                              .filter_by(org_id=org.id).scalar() or 0,
        })
    rows.sort(key=lambda row: (not row["active"], row["name"].lower()))
    return rows


@router.get("")
def list_orgs(request_org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session),
              x_api_key: str = Header(default="", alias="X-API-Key"),
              authorization: str = Header(default=""),
              x_org: str = Header(default="", alias="X-Org")):
    """Resolve the caller again: this endpoint lists seats, so it needs the
    principal, not only the organisation the dependency already picked."""
    principal = auth.resolve_principal(session, x_api_key, authorization,
                                       requested_org=x_org)
    rows = _rows_for(session, principal)
    return {"data": rows, "total": len(rows)}


class OrgCreateIn(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    description: str | None = Field(default=None, max_length=2000)
    actor: str = Field(default="console", max_length=255)


@router.post("", status_code=status.HTTP_201_CREATED)
def create_org(payload: OrgCreateIn = None,
               session: Session = Depends(get_session),
               x_api_key: str = Header(default="", alias="X-API-Key"),
               authorization: str = Header(default=""),
               x_org: str = Header(default="", alias="X-Org")):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    principal = auth.resolve_principal(session, x_api_key, authorization,
                                       requested_org=x_org)
    if principal["kind"] != "user" or not principal.get("user_id"):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "an API key belongs to one organisation; sign in to create another")

    org = models.Organization(slug=_slug_for(session, payload.name),
                              name=payload.name.strip(),
                              description=payload.description)
    session.add(org)
    session.flush()
    session.add(models.OrganizationMember(org_id=org.id, user_id=principal["user_id"],
                                          role="owner"))
    _audit_log(session, org.id, payload.actor, "org.created", "organization", org.id,
               f"{org.name} · by {principal.get('email') or principal['user_id']}")
    session.commit()
    # `active` is where the caller *is*, not where they could go: creating an
    # organisation does not move them, the console's switch does.
    row = next(item for item in _rows_for(session, principal) if item["id"] == org.id)
    return {"data": row}

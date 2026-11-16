"""Threat model: the techniques that threaten one crown jewel, and who would use them.

The jewel is the anchor (`AUREA > Backend`), the technique is ATT&CK's name for what
would happen to it, and the capability is the only thing that makes a technique
testable at all. Coverage is then arithmetic over declared × capability × grant:

    untestable  nothing we run can reach this technique
    blocked     the platform can test it, no active grant carries the capability
    ready       capability granted, ready for a cycle to select it
    ran         a run cited it — not measured yet, and said so instead of 0

Attacker profiles are org-scoped bundles of techniques: they outlive a cycle, so a
cycle cites one instead of redefining it.
"""
import json
import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app import auth, models, threat_plan
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/threat-model", tags=["threat-model"])


def _jewel_or_404(session: Session, org_id: str, component_id: str) -> models.ApplicationComponent:
    component = session.get(models.ApplicationComponent, component_id)
    if component is None or component.org_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "crown jewel not found")
    return component


def _granted_capabilities(session: Session, org_id: str) -> set[str]:
    """Capabilities some active grant carries, as the engine would read them."""
    now = models.utcnow()
    granted: set[str] = set()
    rows = (session.query(models.ScanGrant)
            .filter(models.ScanGrant.org_id == org_id,
                    models.ScanGrant.status == "active").all())
    for grant in rows:
        valid_from = grant.valid_from
        valid_until = grant.valid_until
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


def _state(technique: models.AttackTechnique, granted: set[str]) -> str:
    if not technique.capability:
        return "untestable"
    return "ready" if technique.capability in granted else "blocked"


def _entry_row(entry: models.ThreatEntry, technique: models.AttackTechnique,
               granted: set[str]) -> dict:
    return {"id": entry.id, "technique_id": technique.id, "name": technique.name,
            "tactic": technique.tactic, "capability": technique.capability,
            "description": technique.description, "reason": entry.reason,
            "added_by": entry.added_by, "state": _state(technique, granted)}


class PlanIn(BaseModel):
    components: list[str] = Field(default_factory=list, max_length=200)
    profile_ids: list[str] = Field(default_factory=list, max_length=50)


@router.post("/plan")
def preview_plan(payload: PlanIn = None,
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """What a cycle built on these jewels and profiles would execute.

    Stateless on purpose: the create dialog needs the answer *before* the cycle
    exists, so an operator sees the coverage they are buying into while filling the
    form, not after activating it.
    """
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    return {"data": threat_plan.plan(session, org, payload.components,
                                     payload.profile_ids)}


@router.get("/crown-jewels")
def crown_jewels(org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """The jewels a threat model can be written for."""
    rows = (session.query(models.ApplicationComponent)
            .filter(models.ApplicationComponent.org_id == org.id,
                    models.ApplicationComponent.criticality.isnot(None))
            .order_by(models.ApplicationComponent.criticality,
                      models.ApplicationComponent.name).all())
    projects = {row.id: row for row in
                session.query(models.Project).filter_by(org_id=org.id).all()}
    declared = dict(session.query(models.ThreatEntry.component_id,
                                 func.count(models.ThreatEntry.id))
                    .filter(models.ThreatEntry.org_id == org.id)
                    .group_by(models.ThreatEntry.component_id).all())
    return {"data": [{"id": row.id, "name": row.name, "slug": row.slug,
                      "kind": row.kind, "criticality": row.criticality,
                      "project_slug": projects[row.project_id].slug
                      if row.project_id in projects else None,
                      "project_name": projects[row.project_id].name
                      if row.project_id in projects else None,
                      "techniques": declared.get(row.id, 0)} for row in rows],
            "total": len(rows)}


@router.get("/catalog")
def catalog(q: str | None = Query(default=None, description="technique id, name or tactic"),
            jewel: str | None = Query(default=None,
                                      description="exclude what this jewel already declares"),
            limit: int = Query(default=80, ge=1, le=200),
            org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    query = session.query(models.AttackTechnique)
    if q and q.strip():
        needle = f"%{q.strip()}%"
        query = query.filter(models.AttackTechnique.id.ilike(needle)
                             | models.AttackTechnique.name.ilike(needle)
                             | models.AttackTechnique.tactic.ilike(needle))
    declared = set()
    if jewel:
        _jewel_or_404(session, org.id, jewel)
        declared = {row[0] for row in
                    session.query(models.ThreatEntry.technique_id)
                    .filter(models.ThreatEntry.component_id == jewel).all()}
    rows = [row for row in
            query.order_by(models.AttackTechnique.tactic,
                           models.AttackTechnique.id).limit(limit).all()
            if row.id not in declared]
    granted = _granted_capabilities(session, org.id)
    return {"data": [{"id": row.id, "name": row.name, "tactic": row.tactic,
                      "capability": row.capability,
                      "description": row.description,
                      "state": _state(row, granted)} for row in rows]}


@router.get("")
def threat_model(jewel: str | None = Query(default=None),
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """One jewel's model: its techniques, the coverage arithmetic, and the profiles."""
    profiles = (session.query(models.AttackerProfile)
                .filter(models.AttackerProfile.org_id == org.id)
                .order_by(models.AttackerProfile.name).all())
    profile_rows = [{"id": row.id, "name": row.name, "description": row.description,
                     "origin": row.origin or "custom",
                     "techniques": json.loads(row.techniques or "[]"),
                     "tools": json.loads(row.tools or "[]"),
                     "created_by": row.created_by} for row in profiles]
    if not jewel:
        return {"jewel": None, "entries": [], "profiles": profile_rows,
                "coverage": None,
                "note": "Pick a crown jewel: a threat model is written for one service."}
    component = _jewel_or_404(session, org.id, jewel)
    project = session.get(models.Project, component.project_id)
    granted = _granted_capabilities(session, org.id)
    rows = (session.query(models.ThreatEntry, models.AttackTechnique)
            .join(models.AttackTechnique,
                  models.AttackTechnique.id == models.ThreatEntry.technique_id)
            .filter(models.ThreatEntry.org_id == org.id,
                    models.ThreatEntry.component_id == component.id)
            .order_by(models.AttackTechnique.tactic, models.AttackTechnique.id).all())
    entries = [_entry_row(entry, technique, granted) for entry, technique in rows]
    states = [item["state"] for item in entries]
    coverage = {
        "declared": len(entries),
        "testable": sum(1 for item in entries if item["capability"]),
        "ready": states.count("ready"),
        "blocked": states.count("blocked"),
        "untestable": states.count("untestable"),
        # Nothing writes a technique onto a run yet: the number is not 0, it is
        # unmeasured, and a screen that prints 0 would claim a failed coverage.
        "ran": None,
        "note": ("Coverage is arithmetic over what we declared and what a grant "
                 "allows. `ran` stays unmeasured until a run cites the technique it "
                 "closed."),
    }
    return {"jewel": {"id": component.id, "name": component.name,
                      "slug": component.slug, "kind": component.kind,
                      "criticality": component.criticality,
                      "project_slug": project.slug if project else None,
                      "project_name": project.name if project else None},
            "entries": entries, "coverage": coverage, "profiles": profile_rows,
            "granted_capabilities": sorted(granted)}


class EntryIn(BaseModel):
    component_id: str
    technique_id: str = Field(min_length=2, max_length=24)
    reason: str | None = Field(default=None, max_length=2000)
    actor: str = Field(default="console", max_length=255)


@router.post("/entries", status_code=status.HTTP_201_CREATED)
def add_entry(payload: EntryIn = None, response: Response = None,
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    component = _jewel_or_404(session, org.id, payload.component_id)
    technique = session.get(models.AttackTechnique, payload.technique_id)
    if technique is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "unknown technique: pick one from the ATT&CK catalogue")
    existing = (session.query(models.ThreatEntry)
                .filter_by(component_id=component.id,
                           technique_id=technique.id).one_or_none())
    if existing is not None:
        if response is not None:
            response.status_code = status.HTTP_200_OK
        return {"data": {"id": existing.id, "technique_id": technique.id},
                "created": False}
    entry = models.ThreatEntry(org_id=org.id, component_id=component.id,
                               technique_id=technique.id, reason=payload.reason,
                               added_by=payload.actor)
    session.add(entry)
    _audit_log(session, org.id, payload.actor, "threat.entry_added",
               "application_component", component.id,
               f"{technique.id} {technique.name}")
    session.commit()
    return {"data": {"id": entry.id, "technique_id": technique.id,
                     "name": technique.name, "tactic": technique.tactic,
                     "capability": technique.capability,
                     "reason": entry.reason,
                     "state": _state(technique, _granted_capabilities(session, org.id))},
            "created": True}


@router.delete("/entries/{entry_id}", status_code=status.HTTP_200_OK)
def remove_entry(entry_id: str, actor: str = Query(default="console"),
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    entry = session.get(models.ThreatEntry, entry_id)
    if entry is None or entry.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "threat entry not found")
    session.delete(entry)
    _audit_log(session, org.id, actor, "threat.entry_removed",
               "application_component", entry.component_id, entry.technique_id)
    session.commit()
    return {"data": {"id": entry_id, "removed": True}}


PROFILE_ORIGINS = ("custom", "external", "none")


class ProfileIn(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    # Where the profile comes from: written here, lifted from a report, or unknown.
    origin: str = Field(default="custom", max_length=16)
    techniques: list[str] = Field(default_factory=list, max_length=100)
    # Tooling the actor is known for; free text, stored as a list.
    tools: list[str] = Field(default_factory=list, max_length=50)
    actor: str = Field(default="console", max_length=255)


@router.post("/profiles", status_code=status.HTTP_201_CREATED)
def add_profile(payload: ProfileIn = None,
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    name = payload.name.strip()
    if payload.origin not in PROFILE_ORIGINS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"origin must be one of {list(PROFILE_ORIGINS)}")
    if (session.query(models.AttackerProfile)
            .filter_by(org_id=org.id, name=name).one_or_none()):
        raise HTTPException(status.HTTP_409_CONFLICT, "a profile with that name exists")
    unknown = [tid for tid in payload.techniques
               if session.get(models.AttackTechnique, tid) is None]
    if unknown:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"unknown techniques: {unknown[:5]}")
    tools = [item.strip() for item in payload.tools if item and item.strip()]
    profile = models.AttackerProfile(
        org_id=org.id, name=name, description=payload.description,
        origin=payload.origin,
        techniques=json.dumps(sorted(set(payload.techniques))),
        tools=json.dumps(tools),
        created_by=payload.actor)
    session.add(profile)
    _audit_log(session, org.id, payload.actor, "threat.profile_created",
               "attacker_profile", profile.id, name)
    session.commit()
    return {"data": {"id": profile.id, "name": profile.name,
                     "description": profile.description,
                     "origin": profile.origin,
                     "techniques": json.loads(profile.techniques or "[]"),
                     "tools": json.loads(profile.tools or "[]")}}


@router.delete("/profiles/{profile_id}", status_code=status.HTTP_200_OK)
def remove_profile(profile_id: str, actor: str = Query(default="console"),
                   org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    profile = session.get(models.AttackerProfile, profile_id)
    if profile is None or profile.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "profile not found")
    name = profile.name
    session.delete(profile)
    _audit_log(session, org.id, actor, "threat.profile_removed",
               "attacker_profile", profile_id, name)
    session.commit()
    return {"data": {"id": profile_id, "removed": True}}

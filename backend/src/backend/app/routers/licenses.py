"""BL-060 endpoints: license inventory, policies, evaluation, exceptions."""
import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from backend.app.versions import pick_version
from backend.app import auth, licenses, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1", tags=["licenses"])

UNKNOWN_ACTIONS = {"allow", "warn", "deny"}


def _policy_data(row: models.LicensePolicy) -> dict:
    return {"id": row.id, "name": row.name, "scope_type": row.scope_type,
            "scope_id": row.scope_id, "allow_list": row.allow_list,
            "deny_list": row.deny_list, "unknown_action": row.unknown_action,
            "status": row.status}


class PolicyIn(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    scope_type: str = "org"
    scope_id: str | None = None
    allow_list: str | None = None
    deny_list: str | None = None
    unknown_action: str = "warn"
    actor: str | None = None

    @field_validator("scope_type")
    @classmethod
    def scope_known(cls, value):
        if value not in {"org", "project"}:
            raise ValueError("scope_type must be org or project")
        return value

    @field_validator("unknown_action")
    @classmethod
    def action_known(cls, value):
        if value not in UNKNOWN_ACTIONS:
            raise ValueError(f"unknown_action must be one of {sorted(UNKNOWN_ACTIONS)}")
        return value


@router.get("/license-policies")
def list_policies(org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    rows = (session.query(models.LicensePolicy).filter_by(org_id=org.id)
            .order_by(models.LicensePolicy.created_at.desc()).all())
    return {"data": [_policy_data(r) for r in rows], "total": len(rows)}


@router.post("/license-policies")
def create_policy(payload: PolicyIn = None,
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.scope_type == "project":
        project = session.get(models.Project, payload.scope_id) if payload.scope_id else None
        if project is None or project.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    existing = (session.query(models.LicensePolicy)
                .filter_by(org_id=org.id, name=payload.name).one_or_none())
    if existing is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "policy name exists")
    policy = models.LicensePolicy(
        org_id=org.id, name=payload.name, scope_type=payload.scope_type,
        scope_id=payload.scope_id, allow_list=payload.allow_list,
        deny_list=payload.deny_list, unknown_action=payload.unknown_action,
        created_at=models.utcnow(), updated_at=models.utcnow())
    session.add(policy)
    session.flush()
    _audit_log(session, org.id, payload.actor or "system", "license.policy_created",
               "license_policy", policy.id, f"{payload.name} ({payload.scope_type})")
    session.commit()
    return {"data": _policy_data(policy)}


@router.post("/license-policies/{policy_id}/status")
def set_policy_status(policy_id: str, status_value: str = Query(alias="status"),
                      actor: str = Query(default="system"),
                      org: models.Organization = Depends(auth.require_org),
                      session: Session = Depends(get_session)):
    if status_value not in {"active", "disabled"}:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "status must be active | disabled")
    policy = session.get(models.LicensePolicy, policy_id)
    if policy is None or policy.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "policy not found")
    policy.status = status_value
    policy.updated_at = models.utcnow()
    _audit_log(session, org.id, actor, "license.policy_status",
               "license_policy", policy.id, status_value)
    session.commit()
    return {"data": _policy_data(policy)}


class EvaluateIn(BaseModel):
    project: str = Field(min_length=1)
    version: str = Field(min_length=1)


@router.post("/license-policies/evaluate")
def evaluate(payload: EvaluateIn = None,
             org: models.Organization = Depends(auth.require_org),
             session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    project = (session.query(models.Project)
               .filter_by(org_id=org.id, slug=payload.project).one_or_none())
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    version = (pick_version(session, project.id, payload.version))
    if version is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")
    return {"data": licenses.evaluate_project_version(session, org.id, project, version)}


@router.get("/license-inventory")
def inventory(project: str = Query(...), version: str | None = Query(default=None),
              license: str | None = Query(default=None),
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    """License rows per component (optionally filtered to one version/license)."""
    proj = (session.query(models.Project)
            .filter_by(org_id=org.id, slug=project).one_or_none())
    if proj is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    query = (session.query(models.ComponentLicense, models.Component)
             .join(models.Component, models.ComponentLicense.component_id == models.Component.id)
             .filter(models.ComponentLicense.org_id == org.id,
                     models.Component.org_id == org.id))
    if version is not None:
        pv = (pick_version(session, proj.id, version))
        if pv is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")
        query = query.join(
            models.VersionComponent,
            models.VersionComponent.component_id == models.Component.id).filter(
            models.VersionComponent.project_version_id == pv.id)
    else:
        query = query.filter(models.VersionComponent.component_id == models.Component.id)
    if license is not None:
        query = query.filter(models.ComponentLicense.license_id == license)
    rows = query.all()
    data, seen = [], set()
    for lic, component in rows:
        key = (component.id, lic.license_id)
        if key in seen:
            continue
        seen.add(key)
        data.append({"component": component.name, "version": component.version,
                     "purl": component.purl, "license": lic.license_id,
                     "identity_key": component.identity_key})
    return {"data": data, "total": len(data)}


class ExceptionIn(BaseModel):
    component_identity: str = Field(min_length=2, max_length=1100)
    license_id: str = Field(min_length=1, max_length=255)
    reason: str = Field(min_length=4, max_length=4096)
    approved_by: str = Field(min_length=2, max_length=255)
    expires_in_days: int = Field(default=90, ge=1, le=3650)


@router.get("/license-exceptions")
def list_exceptions(org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    rows = (session.query(models.LicenseException).filter_by(org_id=org.id)
            .order_by(models.LicenseException.created_at.desc()).all())
    return {"data": [{"id": r.id, "component_identity": r.component_identity,
                      "license_id": r.license_id, "reason": r.reason,
                      "approved_by": r.approved_by,
                      "expires_at": r.expires_at.isoformat() if r.expires_at else None}
                     for r in rows], "total": len(rows)}


@router.post("/license-exceptions")
def create_exception(payload: ExceptionIn = None,
                     org: models.Organization = Depends(auth.require_org),
                     session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    row = models.LicenseException(
        org_id=org.id, component_identity=payload.component_identity,
        license_id=payload.license_id, reason=payload.reason,
        approved_by=payload.approved_by,
        expires_at=models.utcnow() + datetime.timedelta(days=payload.expires_in_days),
        created_at=models.utcnow(), updated_at=models.utcnow())
    session.add(row)
    session.flush()
    _audit_log(session, org.id, payload.approved_by, "license.exception_created",
               "license_exception", row.id,
               f"{payload.component_identity} / {payload.license_id}")
    session.commit()
    return {"data": {"id": row.id, "expires_at": row.expires_at.isoformat()}}

"""BL-015 endpoints: the authorization plane (v0 contract surface).

Reuses scope_exclusions as the explicit-deny list; grants never bypass it.
Every issuance, revocation and decision leaves an audit-chain entry.
"""
import json

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, authorization, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/authorization", tags=["authorization"])


class TargetIn(BaseModel):
    type: str
    value: str = Field(min_length=1, max_length=1024)


class GrantIn(BaseModel):
    principal: str = Field(min_length=2, max_length=255)
    capabilities: list[str] = Field(min_length=1)
    targets: list[TargetIn] = Field(min_length=1)
    environment: str | None = Field(default=None, max_length=64)
    tools: list[str] | None = None
    conditions: dict | None = None
    issued_by: str = Field(min_length=2, max_length=255)
    justification: str = Field(min_length=4, max_length=4096)
    hours: int = Field(default=168, ge=1, le=8760)


class RevokeIn(BaseModel):
    reason: str = Field(min_length=4, max_length=2048)
    actor: str = Field(min_length=2, max_length=255)


class AuthorizeIn(BaseModel):
    principal: str = Field(min_length=2, max_length=255)
    capability: str = Field(min_length=4, max_length=128)
    targets: list[TargetIn] = Field(min_length=1)
    tool: str | None = None
    environment: str | None = None
    grant_id: str | None = None  # exact revalidation path


def grant_data(grant: models.ScanGrant) -> dict:
    return {"id": grant.id, "principal": grant.principal,
            "capabilities": [c.strip() for c in grant.capabilities.split(",")],
            "tools": ([t.strip() for t in grant.tools.split(",")] if grant.tools else None),
            "environment": grant.environment,
            "targets": [{"type": t.target_type, "value": t.target_value}
                        for t in grant.targets],
            "conditions": json.loads(grant.conditions) if grant.conditions else None,
            "issued_by": grant.issued_by, "justification": grant.justification,
            "policy_version": grant.policy_version,
            "status": grant.status,
            "valid_from": grant.valid_from.isoformat(),
            "valid_until": grant.valid_until.isoformat(),
            "revoked_at": grant.revoked_at.isoformat() if grant.revoked_at else None}


@router.get("/capabilities")
def capabilities(org: models.Organization = Depends(auth.require_org)):
    """The capability catalog with its per-capability bar (policy constant)."""
    return {"data": [{"id": cap, "description": desc,
                      "invasive": cap in ("active_verification",
                                          "vulnerability_analysis",
                                          "intrusive_testing")}
                     for cap, desc in authorization.CAPABILITIES.items()],
            "policy_version": authorization.POLICY_VERSION}


@router.post("/grants")
def create_grant(payload: GrantIn = None,
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    try:
        from datetime import timedelta

        grant = authorization.issue_grant(
            session, org.id, payload.principal, payload.capabilities,
            [{"type": t.type, "value": t.value} for t in payload.targets],
            issued_by=payload.issued_by, justification=payload.justification,
            environment=payload.environment, tools=payload.tools,
            conditions=payload.conditions,
            valid_until=models.utcnow() + timedelta(hours=payload.hours))
    except ValueError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from None
    _audit_log(session, org.id, payload.issued_by, "authorization.granted",
               "scan_grant", grant.id,
               f"{payload.principal}: {payload.capabilities} x "
               f"{len(payload.targets)} targets, {payload.hours}h")
    session.commit()
    return {"data": grant_data(grant)}


@router.get("/grants")
def list_grants(status: str | None = Query(default=None),
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    query = session.query(models.ScanGrant).filter_by(org_id=org.id)
    if status is not None:
        query = query.filter_by(status=status)
    rows = query.order_by(models.ScanGrant.created_at.desc()).all()
    return {"data": [grant_data(g) for g in rows], "total": len(rows)}


@router.post("/grants/{grant_id}/revoke")
def revoke(grant_id: str, payload: RevokeIn = None,
           org: models.Organization = Depends(auth.require_org),
           session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    grant = session.get(models.ScanGrant, grant_id)
    if grant is None or grant.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "grant not found")
    if grant.status == "revoked":
        return {"data": grant_data(grant), "already_revoked": True}
    authorization.revoke_grant(session, grant, payload.actor, payload.reason)
    _audit_log(session, org.id, payload.actor, "authorization.revoked",
               "scan_grant", grant.id, payload.reason[:120])
    session.commit()
    return {"data": grant_data(grant)}


@router.post("/authorize")
def authorize_endpoint(payload: AuthorizeIn = None,
                       org: models.Organization = Depends(auth.require_org),
                       session: Session = Depends(get_session)):
    """Versioned decision point: default deny, exclusion priority, explainable
    verdict with the policy version. Rechecks validity on every call, so a
    long-running job must re-call before continuing."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    targets = [{"type": t.type, "value": t.value} for t in payload.targets]
    if payload.grant_id:
        result = authorization.revalidate(session, payload.grant_id,
                                          payload.principal, payload.capability,
                                          targets)
    else:
        result = authorization.authorize(session, org.id, payload.principal,
                                         payload.capability, targets,
                                         tool=payload.tool,
                                         environment=payload.environment)
    _audit_log(session, org.id, payload.principal,
               "authorization.decision", "capability", payload.capability,
               f"{result['decision']}: {result['reason'][:120]}")
    session.commit()
    return result


@router.post("/grants/{grant_id}/revalidate")
def revalidate_grant(grant_id: str, payload: AuthorizeIn = None,
                     org: models.Organization = Depends(auth.require_org),
                     session: Session = Depends(get_session)):
    if payload is None or not payload.targets:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "targets required")
    targets = [{"type": t.type, "value": t.value} for t in payload.targets]
    result = authorization.revalidate(session, grant_id, payload.principal,
                                      payload.capability, targets)
    _audit_log(session, org.id, payload.principal, "authorization.revalidated",
               "scan_grant", grant_id,
               f"{result['decision']}: {result['reason'][:120]}")
    session.commit()
    return result

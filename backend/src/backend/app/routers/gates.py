"""BL-055 endpoints: gate policies and deterministic evaluation."""
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from backend.app import auth, gates, models
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1", tags=["gates"])

SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


def _policy_data(row: models.GatePolicy) -> dict:
    return {"id": row.id, "name": row.name, "scope_type": row.scope_type,
            "scope_id": row.scope_id, "max_severity": row.max_severity,
            "block_kev": row.block_kev,
            "block_license_denied": row.block_license_denied,
            "include_suppressed": row.include_suppressed, "status": row.status}


class GatePolicyIn(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    scope_type: str = "org"
    scope_id: str | None = None
    max_severity: str = "HIGH"
    block_kev: bool = False
    block_license_denied: bool = False
    include_suppressed: bool = False
    actor: str | None = None

    @field_validator("scope_type")
    @classmethod
    def scope_known(cls, value):
        if value not in {"org", "project"}:
            raise ValueError("scope_type must be org or project")
        return value

    @field_validator("max_severity")
    @classmethod
    def severity_known(cls, value):
        upper = value.upper()
        if upper not in SEVERITIES:
            raise ValueError(f"max_severity must be one of {sorted(SEVERITIES)}")
        return upper


@router.get("/gate-policies")
def list_policies(org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    rows = (session.query(models.GatePolicy).filter_by(org_id=org.id)
            .order_by(models.GatePolicy.created_at.desc()).all())
    return {"data": [_policy_data(r) for r in rows], "total": len(rows)}


@router.post("/gate-policies")
def create_policy(payload: GatePolicyIn = None,
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.scope_type == "project":
        project = session.get(models.Project, payload.scope_id) if payload.scope_id else None
        if project is None or project.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    if (session.query(models.GatePolicy)
            .filter_by(org_id=org.id, name=payload.name).one_or_none()) is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "policy name exists")
    policy = models.GatePolicy(
        org_id=org.id, name=payload.name, scope_type=payload.scope_type,
        scope_id=payload.scope_id, max_severity=payload.max_severity,
        block_kev=payload.block_kev,
        block_license_denied=payload.block_license_denied,
        include_suppressed=payload.include_suppressed,
        created_at=models.utcnow(), updated_at=models.utcnow())
    session.add(policy)
    session.flush()
    _audit_log(session, org.id, payload.actor or "system", "gate.policy_created",
               "gate_policy", policy.id, f"{payload.name} ({payload.max_severity})")
    session.commit()
    return {"data": _policy_data(policy)}


class EvaluateIn(BaseModel):
    project: str = Field(min_length=1)
    version: str | None = None


@router.post("/gates/evaluate")
def evaluate_gate(payload: EvaluateIn = None,
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    """Deterministic verdict for one project (optionally one version)."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    project = (session.query(models.Project)
               .filter_by(org_id=org.id, slug=payload.project).one_or_none())
    if project is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    version = None
    if payload.version is not None:
        version = (session.query(models.ProjectVersion)
                   .filter_by(project_id=project.id, version=payload.version)
                   .one_or_none())
        if version is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")
    result = gates.evaluate(session, org.id, project, version)
    _audit_log(session, org.id, "gate", "gate.evaluated", "project", project.id,
               f"{project.slug}{'@' + payload.version if payload.version else ''}: "
               f"{result['verdict']}")
    session.commit()
    return {"data": result}


@router.get("/gates/ci-summary")
def ci_summary(org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """Execution health of the CI plane: verdicts per pipeline."""
    rows = (session.query(models.CiRun)
            .filter_by(org_id=org.id).order_by(models.CiRun.started_at.desc())
            .limit(50).all())
    verdicts = {"pass": 0, "fail": 0, "pending": 0}
    for run in rows:
        key = run.verdict if run.verdict in verdicts else "pending"
        verdicts[key] += 1
    return {"data": {"runs": len(rows), "verdicts": verdicts},
            "recent": [{"id": r.id, "pipeline_id": r.pipeline_id,
                        "verdict": r.verdict, "started_at": r.started_at.isoformat()}
                       for r in rows[:10]]}

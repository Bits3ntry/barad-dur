"""Finding endpoints: list, multi-kind ingest, status lifecycle (F2)."""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

from backend.app import auth, ci, incidents, models, vulns
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1", tags=["findings"])

ALLOWED_STATUSES = {"open", "acknowledged", "false_positive", "accepted_risk"}
INGEST_SOURCES = incidents.INGEST_SOURCES


def _resolve_or_404(session: Session, org_id: str, project: str, version: str):
    project_row = (session.query(models.Project)
                   .filter_by(org_id=org_id, slug=project).one_or_none())
    if project_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    version_row = (session.query(models.ProjectVersion)
                   .filter_by(project_id=project_row.id, version=version).one_or_none())
    if version_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")
    return project_row, version_row


@router.post("/analyze")
def analyze_version(
    project: str = Query(...),
    version: str = Query(...),
    org: models.Organization = Depends(auth.require_org),
    session: Session = Depends(get_session),
):
    """Match the version inventory against OSV and upsert deduped findings.

    Synchronous on purpose at POC scale (one querybatch call); a queue-based
    ingest path follows the F2/F3 shape instead of blocking here forever.
    """
    project_row = (session.query(models.Project)
                   .filter_by(org_id=org.id, slug=project).one_or_none())
    if project_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    project_version = _version(session, project_row, version)
    if project_version is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")
    counters = vulns.analyze(session, org.id, project_row, project_version)
    session.commit()
    return {"status": "analyzed" if "error" not in counters else "error",
            "project": project_row.name, "version": project_version.version,
            "counts": counters}


@router.post("/findings/ingest")
def ingest_findings(
    project: str = Query(...),
    version: str = Query(...),
    payload: incidents.FindingsPayload = None,
    source: str = Query(default="api"),
    run_id: str | None = Query(default=None, description="CI run to attach findings to"),
    org: models.Organization = Depends(auth.require_org),
    session: Session = Depends(get_session),
):
    """Ingest a `barad-findings-v1` payload for one project version.

    Idempotent on per-kind fingerprints; new findings are evaluated against
    approved suppression rules at creation time. With `run_id`, created and
    refreshed findings attach to that CI run for the gate verdict.
    """
    if source not in INGEST_SOURCES:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "invalid source")
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    project_row, version_row = _resolve_or_404(session, org.id, project, version)
    ci_run = None
    if run_id:
        ci_run = session.get(models.CiRun, run_id)
        if ci_run is None or ci_run.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "ci run not found")
    counters = incidents.ingest_payload(session, org, project_row, version_row,
                                        payload, source=source)
    session.commit()
    if ci_run is not None:
        linked = (session.query(models.Finding)
                  .filter(models.Finding.org_id == org.id,
                          models.Finding.project_id == project_row.id,
                          models.Finding.last_seen_version_id == version_row.id,
                          models.Finding.status != "suppressed").all())
        for finding in linked:
            ci.attach_finding(session, ci_run, finding)
        session.commit()
    return {"status": "ingested", "project": project_row.name,
            "version": version_row.version, "source": source, "counts": counters}


class FindingStatusPatch(BaseModel):
    status: str
    reason: str | None = Field(default=None, max_length=1024)
    actor: str = Field(min_length=1, max_length=255)


@router.patch("/findings/{finding_id}/status")
def set_status(
    finding_id: str,
    patch: FindingStatusPatch = None,
    org: models.Organization = Depends(auth.require_org),
    session: Session = Depends(get_session),
):
    """Manual disposition. Suppressed findings must change through their rule
    review, not here; false_positive/accepted_risk stay reserved for that too.
    """
    if patch is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if patch.status not in ALLOWED_STATUSES:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"status must be one of {sorted(ALLOWED_STATUSES)}")
    finding = session.get(models.Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    if finding.status == "suppressed" and patch.status != "open":
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "suppressed findings change along with their rule, not here")

    finding.status = patch.status
    finding.status_reason = patch.reason
    finding.status_changed_at = datetime.now(timezone.utc)
    finding.updated_at = finding.status_changed_at
    session.commit()
    return {"data": {"id": finding.id, "status": finding.status,
                     "reason": finding.status_reason}}


class SuppressionCreate(BaseModel):
    kind: str | None = None
    rule_id: str | None = None
    path_pattern: str | None = None
    suppression_type: str
    reason: str = Field(min_length=4, max_length=2048)
    project: str | None = None
    requested_by: str = Field(min_length=1, max_length=255)
    expires_at: str | None = None

    @field_validator("suppression_type")
    @classmethod
    def type_known(cls, value):
        if value not in {"false_positive", "accepted_risk"}:
            raise ValueError("suppression_type must be false_positive or accepted_risk")
        return value


class SuppressionReview(BaseModel):
    approver: str = Field(min_length=1, max_length=255, description="""
    Approver identity. A requester's self-approval is refused by contract: two
    distinct identities are required for the four-eyes pair.""")
    reason: str | None = None


def _rule_data(session, org: models.Organization, rule: models.SuppressionRule):
    project = session.get(models.Project, rule.project_id) if rule.project_id else None
    return {"id": rule.id, "kind": rule.kind, "rule_id": rule.rule_id,
            "path_pattern": rule.path_pattern,
            "suppression_type": rule.suppression_type, "reason": rule.reason,
            "status": rule.status, "requested_by": rule.requested_by,
            "approved_by": rule.approved_by,
            "rejection_reason": rule.rejection_reason,
            "project": project.name if project else None,
            "expires_at": rule.expires_at.isoformat() if rule.expires_at else None}


@router.post("/suppressions")
def create_suppression(
    payload: SuppressionCreate = None,
    org: models.Organization = Depends(auth.require_org),
    session: Session = Depends(get_session),
):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if not (payload.kind or payload.rule_id or payload.path_pattern):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "at least one criterion (kind, rule_id, path_pattern) is required")
    project_id = None
    if payload.project:
        project_row = (session.query(models.Project)
                       .filter_by(org_id=org.id, slug=payload.project).one_or_none())
        if project_row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
        project_id = project_row.id
    expires = None
    if payload.expires_at:
        try:
            expires = datetime.fromisoformat(payload.expires_at.replace("Z", "+00:00"))
        except ValueError:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                "expires_at must be an ISO timestamp") from None
    rule = models.SuppressionRule(
        org_id=org.id, project_id=project_id, kind=payload.kind,
        rule_id=payload.rule_id, path_pattern=payload.path_pattern,
        suppression_type=payload.suppression_type, reason=payload.reason,
        status="pending", requested_by=payload.requested_by, expires_at=expires,
        created_at=models.utcnow(), updated_at=models.utcnow())
    session.add(rule)
    session.commit()
    return {"data": _rule_data(session, org, rule)}


@router.get("/suppressions")
def list_suppressions(org: models.Organization = Depends(auth.require_org),
                      session: Session = Depends(get_session)):
    rules = (session.query(models.SuppressionRule)
             .filter_by(org_id=org.id)
             .order_by(models.SuppressionRule.created_at.desc()).all())
    return {"data": [_rule_data(session, org, rule) for rule in rules],
            "total": len(rules)}


@router.post("/suppressions/{rule_id}/approve")
def approve_suppression(
    rule_id: str,
    review: SuppressionReview = None,
    org: models.Organization = Depends(auth.require_org),
    session: Session = Depends(get_session),
):
    if review is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    rule = session.get(models.SuppressionRule, rule_id)
    if rule is None or rule.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "suppression rule not found")
    try:
        suppressed = incidents.approve_rule(session, rule, review.approver)
    except ValueError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from None
    session.commit()
    return {"data": _rule_data(session, org, rule), "findings_suppressed": suppressed}


@router.post("/suppressions/{rule_id}/reject")
def reject_suppression(
    rule_id: str,
    review: SuppressionReview = None,
    org: models.Organization = Depends(auth.require_org),
    session: Session = Depends(get_session),
):
    if review is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    rule = session.get(models.SuppressionRule, rule_id)
    if rule is None or rule.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "suppression rule not found")
    try:
        incidents.reject_rule(session, rule, review.approver,
                              review.reason or "rejected without reason")
    except ValueError as error:
        raise HTTPException(status.HTTP_409_CONFLICT, str(error)) from None
    session.commit()
    return {"data": _rule_data(session, org, rule)}


@router.get("/findings")
def list_findings(
    project: str | None = Query(default=None),
    version: str | None = Query(default=None),
    kind: str | None = Query(default=None),
    include_suppressed: bool = Query(default=False,
                                     description="approved suppressions leave the default view"),
    status_filter: str | None = Query(default=None, alias="status"),
    org: models.Organization = Depends(auth.require_org),
    session: Session = Depends(get_session),
):
    query = (session.query(models.Finding)
             .join(models.Project, models.Finding.project_id == models.Project.id)
             .filter(models.Finding.org_id == org.id))
    if not include_suppressed:
        query = query.filter(models.Finding.status != "suppressed")
    if status_filter:
        query = query.filter(models.Finding.status == status_filter)
    if project or version:
        if not (project and version):
            raise HTTPException(status.HTTP_400_BAD_REQUEST,
                                "project and version filters go together")
        project_version = _resolve(session, org.id, project, version)
        if project_version is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")
        # Scan context: the finding's stamp is refreshed on every ingest/scan
        # that still sees it, so the version view shows what that scan found.
        query = query.filter(models.Finding.last_seen_version_id == project_version.id)
    if kind:
        query = query.filter(models.Finding.kind == kind)
    rows = query.order_by(models.Finding.last_seen_at.desc()).all()

    data = []
    for finding in rows:
        component = session.get(models.Component, finding.component_id) \
            if finding.component_id else None
        vulnerability = session.get(models.Vulnerability, finding.vulnerability_id) \
            if finding.vulnerability_id else None
        data.append({
            "id": finding.id,
            "kind": finding.kind,
            "status": finding.status,
            "status_reason": finding.status_reason,
            "severity": finding.severity,
            "title": finding.title,
            "fingerprint": finding.fingerprint,
            "source": finding.source,
            "tool": finding.tool,
            "rule_id": finding.rule_id,
            "path": finding.path,
            "line": finding.line,
            "source_id": vulnerability.source_id if vulnerability else None,
            "cve_id": vulnerability.cve_id if vulnerability else None,
            "source_url": vulnerability.url if vulnerability else None,
            "component_purl": (component.purl or component.identity_key) if component else None,
            "first_seen_at": finding.first_seen_at.isoformat(),
            "last_seen_at": finding.last_seen_at.isoformat(),
        })
    return {"data": data, "total": len(data)}


def _resolve(session, org_id: str, project: str, version: str):
    project_row = (session.query(models.Project)
                   .filter_by(org_id=org_id, slug=project).one_or_none())
    if project_row is None:
        return None
    return (session.query(models.ProjectVersion)
            .filter_by(project_id=project_row.id, version=version).one_or_none())


def _version(session, project_row, version: str):
    return (session.query(models.ProjectVersion)
            .filter_by(project_id=project_row.id, version=version).one_or_none())

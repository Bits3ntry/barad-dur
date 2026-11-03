<<<<<<< Updated upstream
"""Finding endpoints: list, manual creation, ingest, lifecycle, comments,
evidence, ownership."""
import hashlib
=======
"""Finding endpoints: list, multi-kind ingest, status lifecycle (F2)."""
>>>>>>> Stashed changes
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy.orm import Session

<<<<<<< Updated upstream
from backend.app import auth, ci, incidents, models, projects as projects_ref, severity as severity_vocab, vulns
=======
from backend.app import auth, ci, incidents, models, vulns
>>>>>>> Stashed changes
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1", tags=["findings"])

ALLOWED_STATUSES = {"open", "acknowledged", "resolved", "false_positive", "accepted_risk"}
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
    try:
        counters = incidents.ingest_payload(session, org, project_row, version_row,
                                            payload, source=source)
    except ValueError as error:
        # ingest_payload raises only for bounded-limit violations.
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from None
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


@router.get("/findings/{finding_id}")
def get_finding(finding_id: str,
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    finding = session.get(models.Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    component = session.get(models.Component, finding.component_id) \
        if finding.component_id else None
    vulnerability = session.get(models.Vulnerability, finding.vulnerability_id) \
        if finding.vulnerability_id else None
<<<<<<< Updated upstream
    # The run that last evaluated this finding is where a reviewer goes to see
    # the code and the diff; without it the viewer is a dead end.
    run = (session.get(models.AnalysisRun, finding.last_evaluated_run_id)
           if finding.last_evaluated_run_id else None)
=======
>>>>>>> Stashed changes
    return {"data": {
        "id": finding.id, "kind": finding.kind, "status": finding.status,
        "status_reason": finding.status_reason, "severity": finding.severity,
        "title": finding.title, "detail": finding.detail,
        "tool": finding.tool, "rule_id": finding.rule_id,
        "path": finding.path, "line": finding.line,
<<<<<<< Updated upstream
        "assignee": finding.assignee, "cwe": finding.cwe,
        "impact": finding.impact, "recommendation": finding.recommendation,
        "reproduction": finding.reproduction,
        "project_id": finding.project_id,
        "fingerprint": finding.fingerprint, "first_seen_at": finding.first_seen_at.isoformat(),
        "last_seen_at": finding.last_seen_at.isoformat(),
        "comments": (session.query(models.FindingComment)
                     .filter_by(finding_id=finding.id).count()),
        "attachments": (session.query(models.FindingAttachment)
                        .filter_by(finding_id=finding.id).count()),
=======
        "fingerprint": finding.fingerprint, "first_seen_at": finding.first_seen_at.isoformat(),
>>>>>>> Stashed changes
        "component_purl": (component.purl or component.identity_key) if component else None,
        "source_id": vulnerability.source_id if vulnerability else None,
        "cve_id": vulnerability.cve_id if vulnerability else None,
        "source_url": vulnerability.url if vulnerability else None,
<<<<<<< Updated upstream
        "analysis_run": ({
            "id": run.id, "revision": run.revision, "branch": run.branch,
            "pull_request": run.pull_request, "tool": run.tool,
            "coverage": run.coverage,
        } if run else None),
=======
>>>>>>> Stashed changes
    }}


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
    _audit_log(session, org.id, review.approver, "suppression.approved",
               "suppression_rule", rule.id,
               f"{rule.rule_id} @ {rule.path_pattern}")
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
<<<<<<< Updated upstream
    q: str | None = Query(default=None, description="title / rule / path / cve text"),
    severity: str | None = Query(default=None),
    priority: str | None = Query(default=None),
    assignee: str | None = Query(default=None),
    source: str | None = Query(default=None),
    include_suppressed: bool = Query(default=False,
                                     description="approved suppressions leave the default view"),
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
=======
    include_suppressed: bool = Query(default=False,
                                     description="approved suppressions leave the default view"),
    status_filter: str | None = Query(default=None, alias="status"),
>>>>>>> Stashed changes
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
<<<<<<< Updated upstream
    if severity:
        query = query.filter(models.Finding.severity.in_(
            severity_vocab.raw_variants(severity)))
    if priority:
        query = query.filter(models.Finding.priority == priority.upper())
    if assignee:
        query = query.filter(models.Finding.assignee == assignee)
    if source:
        query = query.filter(models.Finding.source == source)
    if q:
        needle = f"%{q.strip()}%"
        query = (query.outerjoin(models.Vulnerability,
                                 models.Finding.vulnerability_id == models.Vulnerability.id)
                 .filter(models.Finding.title.ilike(needle)
                         | models.Finding.rule_id.ilike(needle)
                         | models.Finding.path.ilike(needle)
                         | models.Vulnerability.cve_id.ilike(needle)
                         | models.Vulnerability.source_id.ilike(needle)))
=======
>>>>>>> Stashed changes
    if project or version:
        if not (project and version):
            # Project-only filter is a legitimate view: every version's
            # findings, no completeness requirement on the pair.
<<<<<<< Updated upstream
            project_row = projects_ref.by_ref(session, org.id, project)
=======
            project_row = (session.query(models.Project)
                           .filter_by(org_id=org.id, slug=project).one_or_none())
>>>>>>> Stashed changes
            if project_row is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
            query = query.filter(models.Finding.project_id == project_row.id)
        else:
            project_version = _resolve(session, org.id, project, version)
            if project_version is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")
            # Scan context: the finding's stamp is refreshed on every ingest/scan
            # that still sees it, so the version view shows what that scan found.
            query = query.filter(models.Finding.last_seen_version_id == project_version.id)
    if kind:
        query = query.filter(models.Finding.kind == kind)
<<<<<<< Updated upstream
    total = query.count()
    rows = (query.order_by(models.Finding.last_seen_at.desc())
            .offset(offset).limit(limit).all())
=======
    rows = query.order_by(models.Finding.last_seen_at.desc()).all()
>>>>>>> Stashed changes

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
            "project_id": finding.project_id,
            "priority": finding.priority,
            "priority_reason": finding.priority_reason,
<<<<<<< Updated upstream
            "assignee": finding.assignee,
=======
>>>>>>> Stashed changes
            "sla_deadline": finding.sla_deadline.isoformat() if finding.sla_deadline else None,
            "first_seen_at": finding.first_seen_at.isoformat(),
            "last_seen_at": finding.last_seen_at.isoformat(),
        })
<<<<<<< Updated upstream
    return {"data": data, "total": total, "limit": limit, "offset": offset}


def _resolve(session, org_id: str, project: str, version: str):
    project_row = projects_ref.by_ref(session, org_id, project)
=======
    return {"data": data, "total": len(data)}


def _resolve(session, org_id: str, project: str, version: str):
    project_row = (session.query(models.Project)
                   .filter_by(org_id=org_id, slug=project).one_or_none())
>>>>>>> Stashed changes
    if project_row is None:
        return None
    return (session.query(models.ProjectVersion)
            .filter_by(project_id=project_row.id, version=version).one_or_none())


def _version(session, project_row, version: str):
    return (session.query(models.ProjectVersion)
            .filter_by(project_id=project_row.id, version=version).one_or_none())
<<<<<<< Updated upstream


# ─────────────── v0: manual findings, ownership, comments, evidence ───────────────

MANUAL_KINDS = {"secret", "misconfiguration", "code-weakness"}
MAX_ATTACHMENT_CHARS = 200_000


class ManualFindingIn(BaseModel):
    """A finding a human observed. An IDOR without a CVE is exactly this: a
    concrete problem at a concrete location, with no advisory behind it."""

    project: str = Field(min_length=1, max_length=128)
    kind: str
    title: str = Field(min_length=3, max_length=1024)
    severity: str | None = None
    detail: str | None = Field(default=None, max_length=20000)
    path: str | None = Field(default=None, max_length=1024)
    line: int | None = Field(default=None, ge=1)
    cwe: str | None = Field(default=None, max_length=64)
    impact: str | None = Field(default=None, max_length=20000)
    recommendation: str | None = Field(default=None, max_length=20000)
    reproduction: str | None = Field(default=None, max_length=20000)
    assignee: str | None = Field(default=None, max_length=255)
    actor: str = Field(default="system", max_length=255)

    @field_validator("kind")
    @classmethod
    def kind_known(cls, value):
        if value not in MANUAL_KINDS:
            raise ValueError(f"kind must be one of {sorted(MANUAL_KINDS)}")
        return value


@router.post("/findings", status_code=status.HTTP_201_CREATED)
def create_manual_finding(payload: ManualFindingIn = None,
                          org: models.Organization = Depends(auth.require_org),
                          session: Session = Depends(get_session)):
    """Manual creation shares the finding identity space with imports.

    The fingerprint recipe is its own (`manual|…`) so a hand-recorded weakness
    is never fused with an advisory-derived finding; repeating the same manual
    report in the same project returns the existing row instead of a duplicate.
    """
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    project_row = (session.query(models.Project)
                   .filter_by(org_id=org.id, slug=payload.project).one_or_none())
    if project_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    recipe = "|".join(["manual", org.id, project_row.id, payload.kind,
                       payload.title.strip(), payload.path or "", str(payload.line or "")])
    fingerprint = hashlib.sha256(recipe.encode()).hexdigest()
    existing = (session.query(models.Finding)
                .filter_by(org_id=org.id, fingerprint=fingerprint).one_or_none())
    if existing is not None:
        existing.last_seen_at = models.utcnow()
        session.commit()
        return {"data": {"id": existing.id, "status": existing.status},
                "already_known": True}
    finding = models.Finding(
        org_id=org.id, project_id=project_row.id, kind=payload.kind,
        fingerprint=fingerprint, source="manual",
        title=payload.title.strip(),
        detail=payload.detail,
        severity=severity_vocab.canonical(payload.severity),
        path=payload.path, line=payload.line, cwe=payload.cwe,
        impact=payload.impact, recommendation=payload.recommendation,
        reproduction=payload.reproduction, assignee=payload.assignee,
        status="open", first_seen_at=models.utcnow(), last_seen_at=models.utcnow())
    session.add(finding)
    session.flush()
    _audit_log(session, org.id, payload.actor, "finding.created", "finding",
               finding.id, f"{payload.kind}: {finding.title}")
    session.commit()
    return {"data": {"id": finding.id, "kind": finding.kind,
                     "severity": finding.severity, "status": finding.status,
                     "cve_id": None}, "already_known": False}


class AssigneeIn(BaseModel):
    assignee: str | None = Field(default=None, max_length=255)
    actor: str = Field(min_length=1, max_length=255)


@router.patch("/findings/{finding_id}/assignee")
def assign_finding(finding_id: str, payload: AssigneeIn = None,
                   org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    finding = session.get(models.Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    finding.assignee = (payload.assignee or "").strip() or None
    _audit_log(session, org.id, payload.actor, "finding.assigned", "finding",
               finding.id, finding.assignee or "unassigned")
    session.commit()
    return {"data": {"id": finding.id, "assignee": finding.assignee}}


class CommentIn(BaseModel):
    body: str = Field(min_length=1, max_length=20000)
    author: str = Field(min_length=1, max_length=255)


@router.get("/findings/{finding_id}/comments")
def list_comments(finding_id: str,
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    finding = session.get(models.Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    rows = (session.query(models.FindingComment)
            .filter_by(finding_id=finding.id)
            .order_by(models.FindingComment.created_at).all())
    return {"data": [{"id": row.id, "author": row.author, "body": row.body,
                      "created_at": row.created_at.isoformat()} for row in rows],
            "total": len(rows)}


@router.post("/findings/{finding_id}/comments", status_code=status.HTTP_201_CREATED)
def add_comment(finding_id: str, payload: CommentIn = None,
                org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    finding = session.get(models.Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    comment = models.FindingComment(org_id=org.id, finding_id=finding.id,
                                    author=payload.author, body=payload.body)
    session.add(comment)
    session.flush()
    _audit_log(session, org.id, payload.author, "finding.comment_added", "finding",
               finding.id, payload.body[:120])
    session.commit()
    return {"data": {"id": comment.id, "author": comment.author,
                     "body": comment.body,
                     "created_at": comment.created_at.isoformat()}}


class AttachmentIn(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    media_type: str = Field(default="text/plain", max_length=128)
    content: str = Field(min_length=1, max_length=MAX_ATTACHMENT_CHARS)
    added_by: str = Field(min_length=1, max_length=255)


def _attachment_meta(row: models.FindingAttachment) -> dict:
    return {"id": row.id, "name": row.name, "media_type": row.media_type,
            "size_bytes": row.size_bytes, "sha256": row.sha256,
            "redaction_state": row.redaction_state, "added_by": row.added_by,
            "created_at": row.created_at.isoformat()}


@router.get("/findings/{finding_id}/attachments")
def list_attachments(finding_id: str,
                     org: models.Organization = Depends(auth.require_org),
                     session: Session = Depends(get_session)):
    """Metadata only: reading the bytes is a separate, explicit call."""
    finding = session.get(models.Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    rows = (session.query(models.FindingAttachment)
            .filter_by(finding_id=finding.id)
            .order_by(models.FindingAttachment.created_at).all())
    return {"data": [_attachment_meta(row) for row in rows], "total": len(rows)}


@router.post("/findings/{finding_id}/attachments",
             status_code=status.HTTP_201_CREATED)
def add_attachment(finding_id: str, payload: AttachmentIn = None,
                   org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    """Evidence is stored bounded and marked `unreviewed`; v0 does not detect
    secrets inside it, and the badge says so rather than implying a check."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    finding = session.get(models.Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    digest = hashlib.sha256(payload.content.encode()).hexdigest()
    row = models.FindingAttachment(
        org_id=org.id, finding_id=finding.id, name=payload.name,
        media_type=payload.media_type, size_bytes=len(payload.content.encode()),
        sha256=digest, content=payload.content, added_by=payload.added_by)
    session.add(row)
    session.flush()
    _audit_log(session, org.id, payload.added_by, "finding.attachment_added",
               "finding", finding.id, f"{payload.name} ({row.size_bytes} bytes)")
    session.commit()
    return {"data": _attachment_meta(row)}


@router.get("/findings/{finding_id}/attachments/{attachment_id}")
def read_attachment(finding_id: str, attachment_id: str,
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    finding = session.get(models.Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    row = session.get(models.FindingAttachment, attachment_id)
    if row is None or row.org_id != org.id or row.finding_id != finding.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "attachment not found")
    return {"data": {**_attachment_meta(row), "content": row.content}}


@router.get("/findings/{finding_id}/history")
def finding_history(finding_id: str,
                    limit: int = Query(default=200, ge=1, le=500),
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    """One merged timeline: status/disposition changes, sightings and comments.

    The audit ledger is the source of truth for who changed what; occurrences
    carry when the weakness was actually seen; comments are the conversation.
    Nothing here is synthesised — an empty list means nothing has happened yet.
    """
    finding = session.get(models.Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    events = []
    for row in (session.query(models.AuditLog)
                .filter_by(org_id=org.id, resource_type="finding", resource_id=finding.id)
                .all()):
        events.append({"at": row.created_at.isoformat(), "kind": "audit",
                       "actor": row.actor, "action": row.action,
                       "detail": row.detail, "ref": f"chain:{row.chain_position}"})
    for row in (session.query(models.Occurrence)
                .filter_by(finding_id=finding.id)
                .order_by(models.Occurrence.seen_at.desc()).all()):
        events.append({"at": row.seen_at.isoformat(), "kind": "sighting",
                       "actor": row.tool or row.source or "scanner",
                       "action": "finding.observed",
                       "detail": row.evidence,
                       "ref": f"occurrence:{row.id}"})
    for row in (session.query(models.FindingComment)
                .filter_by(finding_id=finding.id).all()):
        events.append({"at": row.created_at.isoformat(), "kind": "comment",
                       "actor": row.author, "action": "finding.comment_added",
                       "detail": row.body, "ref": f"comment:{row.id}"})
    for row in (session.query(models.FindingAttachment)
                .filter_by(finding_id=finding.id).all()):
        events.append({"at": row.created_at.isoformat(), "kind": "attachment",
                       "actor": row.added_by, "action": "finding.attachment_added",
                       "detail": f"{row.name} ({row.size_bytes} bytes, "
                                 f"{row.redaction_state})",
                       "ref": f"attachment:{row.id}"})
    events.sort(key=lambda event: event["at"], reverse=True)
    return {"data": events[:limit], "total": len(events),
            "first_seen_at": finding.first_seen_at.isoformat(),
            "last_seen_at": finding.last_seen_at.isoformat(),
            "last_evaluated_run_id": finding.last_evaluated_run_id}
=======
>>>>>>> Stashed changes

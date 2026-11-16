"""Finding endpoints: list, manual creation, ingest, lifecycle, comments,
evidence, ownership."""
import hashlib
import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import case, func, or_
from sqlalchemy.orm import Session

from backend.app.versions import pick_version
from backend.app import (auth, claims, ci, incidents, models, projects as projects_ref,
                         repeat, severity as severity_vocab, vulns)
from backend.app.ai import authz
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log
from backend.app.status import CLOSED_STATUSES

router = APIRouter(prefix="/api/v1", tags=["findings"])

ALLOWED_STATUSES = {"open", "acknowledged", "resolved", "false_positive", "accepted_risk"}
INGEST_SOURCES = incidents.INGEST_SOURCES


def _resolve_or_404(session: Session, org_id: str, project: str, version: str):
    project_row = (session.query(models.Project)
                   .filter_by(org_id=org_id, slug=project).one_or_none())
    if project_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    version_row = (pick_version(session, project_row.id, version))
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
    # The run that last evaluated this finding is where a reviewer goes to see
    # the code and the diff; without it the viewer is a dead end.
    run = (session.get(models.AnalysisRun, finding.last_evaluated_run_id)
           if finding.last_evaluated_run_id else None)
    # The detail is the shared shape plus what only a page needs. It used to be a
    # second copy — and it had drifted: no priority, no SLA, no build, no CVSS, no
    # component name/version. The finding page is built on those fields, so the
    # copy is gone.
    data = finding_data(session, finding)
    data.update({
        "detail": finding.detail,
        "comments": (session.query(models.FindingComment)
                     .filter_by(finding_id=finding.id).count()),
        "attachments": (session.query(models.FindingAttachment)
                        .filter_by(finding_id=finding.id).count()),
        "analysis_run": ({
            "id": run.id, "revision": run.revision, "branch": run.branch,
            "pull_request": run.pull_request, "tool": run.tool,
            "coverage": run.coverage,
        } if run else None),
    })
    return {"data": data}


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
    q: str | None = Query(default=None, description="title / rule / path / cve text"),
    severity: str | None = Query(default=None),
    priority: str | None = Query(default=None),
    assignee: str | None = Query(default=None),
    source: str | None = Query(default=None),
    vector: str | None = Query(default=None,
                               description="dependency-cve | credential | sast | misconfig"),
    include_suppressed: bool = Query(default=False,
                                     description="approved suppressions leave the default view"),
    # The build a finding was last seen in. The finding page asks for it to show
    # every claim that version carries — the question an operator actually has
    # when deciding whether one CVE is the fix or just the first.
    version_id: str | None = Query(default=None),
    status_filter: str | None = Query(default=None, alias="status"),
    # `status` is one word; this is the question the screens actually ask
    # ("what is still open"), and it has to mean the same thing as the count that
    # sent the reader here — five spellings of closure, one set.
    open_only: bool = Query(default=False, alias="open",
                            description="only findings nobody has closed yet"),
    origin: str | None = Query(default=None,
                               description="scanner | pentest-external | "
                                           "pentest-internal | shauron-ai | manual"),
    cycle: str | None = Query(default=None,
                              description="only the findings of that cycle's ledger"),
    triage_status: str | None = Query(default=None,
                                      description="new | triaged | rejected | "
                                                  "duplicate | accepted"),
    evidence_level: str | None = Query(default=None,
                                       description="hypothesis | static | observed | "
                                                   "demonstrated"),
    exploit_state: str | None = Query(default=None,
                                      description="none | attempted | reproduced | "
                                                  "effect_proven"),
    queue: bool = Query(default=False,
                        description="only rows waiting for a human (triage_status=new)"),
    limit: int = Query(default=200, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    sort: str | None = Query(default=None,
                             description="severity — worst first; the default is newest first"),
    org: models.Organization = Depends(auth.require_org),
    session: Session = Depends(get_session),
):
    # Outer join since F3: an asset-only finding has no project and must still
    # appear. An inner join silently hid exactly the rows the pentesters file.
    query = (session.query(models.Finding)
             .outerjoin(models.Project, models.Finding.project_id == models.Project.id)
             .filter(models.Finding.org_id == org.id))
    if not include_suppressed:
        query = query.filter(models.Finding.status != "suppressed")
    if origin:
        query = query.filter(models.Finding.origin == origin)
    if cycle:
        cycle_row = session.get(models.Cycle, cycle)
        if cycle_row is None or cycle_row.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "cycle not found")
        query = (query.join(models.CycleFinding,
                            models.CycleFinding.finding_id == models.Finding.id)
                 .filter(models.CycleFinding.cycle_id == cycle))
    if triage_status:
        query = query.filter(models.Finding.triage_status == triage_status)
    if evidence_level:
        query = query.filter(models.Finding.evidence_level == evidence_level)
    if exploit_state:
        query = query.filter(models.Finding.exploit_state == exploit_state)
    if status_filter:
        query = query.filter(models.Finding.status == status_filter)
    if open_only:
        query = query.filter(models.Finding.status.notin_(CLOSED_STATUSES))
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
    if project or version:
        if not (project and version):
            # Project-only filter is a legitimate view: every version's
            # findings, no completeness requirement on the pair.
            project_row = projects_ref.by_ref(session, org.id, project)
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
    if version_id:
        query = query.filter(models.Finding.last_seen_version_id == version_id)
    if kind:
        query = query.filter(models.Finding.kind == kind)
    if vector:
        query = query.filter(models.Finding.vector == vector)
    # The triage rule runs last, on the *filtered* query, so the counter and the
    # list share one scope. Counting the queue org-wide beside a project-scoped
    # list printed "1 awaiting triage" with nothing to open.
    queue_total = query.filter(models.Finding.triage_status == "new").count()
    # A claim a cycle is still holding is not an estate finding yet: it sits in the
    # queue and in the cycle ledger, where the decision is made. Scanner claims keep
    # their own lifecycle — hiding every `new` row would have made a fresh scan
    # invisible in `#findings`, which is a different defect, not this one.
    if queue:
        query = query.filter(models.Finding.triage_status == "new")
    elif not cycle and not triage_status:
        held = (session.query(models.CycleFinding.finding_id)
                .filter(models.CycleFinding.org_id == org.id))
        query = query.filter(or_(models.Finding.triage_status.is_(None),
                                 models.Finding.triage_status != "new",
                                 ~models.Finding.id.in_(held)))
    total = query.count()
    ordering = [models.Finding.last_seen_at.desc()]
    if sort == "severity":
        ordering.insert(0, _severity_order())
    rows = query.order_by(*ordering).offset(offset).limit(limit).all()

    data = [finding_data(session, finding) for finding in rows]
    return {"data": data, "total": total, "limit": limit, "offset": offset,
            "counters": {"queue": queue_total, "listed": total}}


def _severity_order():
    """Worst first, in SQL.

    The list is paginated, so ordering the page the platform returned would
    order a slice and call it an order. The CASE is built from the shared
    vocabulary (severity.py) rather than the stored spelling, because producers
    do not agree on names and a raw 'MODERATE' must not sort as unknown.
    """
    return case(
        *[(func.upper(models.Finding.severity).in_(severity_vocab.raw_variants(name)), rank)
          for rank, name in enumerate(severity_vocab.SEVERITIES)],
        else_=len(severity_vocab.SEVERITIES),
    )


def finding_data(session, finding: models.Finding) -> dict:
    """One finding exactly as the API returns it.

    Shared on purpose: a second reader (the scan drawer) must not grow its own
    copy of this shape and drift from the list screen.
    """
    component = session.get(models.Component, finding.component_id) \
        if finding.component_id else None
    vulnerability = session.get(models.Vulnerability, finding.vulnerability_id) \
        if finding.vulnerability_id else None
    # A claim a cycle holds answers "where did this come from" with the cycle, the
    # same way a scan answers it with the run. Without it the drawer could only say
    # `manual`, which is how a pentest finding looked hand-typed.
    link = (session.query(models.CycleFinding)
            .filter_by(finding_id=finding.id).one_or_none())
    cycle = session.get(models.Cycle, link.cycle_id) if link is not None else None
    evidence: dict = {}
    if finding.detail and finding.detail.strip().startswith("{"):
        try:
            parsed = json.loads(finding.detail)
            if isinstance(parsed, dict):
                evidence = parsed
        except ValueError:
            evidence = {}
    return {
            "id": finding.id,
            "kind": finding.kind,
            # The class says what it is; the vector says how it is closed.
            "vector": finding.vector,
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
            "component_name": component.name if component else None,
            "component_version": component.version if component else None,
            "recommendation": finding.recommendation,
            "cwe": finding.cwe,
            "impact": finding.impact,
            "reproduction": finding.reproduction,
            "url": finding.url or (vulnerability.url if vulnerability else None),
            # Where it was seen and how it was reached: the record a reader needs
            # to reproduce it without asking the person who wrote it.
            "endpoint": finding.endpoint,
            "http_method": finding.http_method,
            "auth_required": finding.auth_required,
            "auth_profile_id": finding.auth_profile_id,
            "auth_profile_name": (session.get(models.AuthProfile, finding.auth_profile_id).name
                                  if finding.auth_profile_id else None),
            "product_component_id": finding.product_component_id,
            "product_component_name": (
                session.get(models.ApplicationComponent, finding.product_component_id).name
                if finding.product_component_id else None),
            "expected_result": finding.expected_result,
            "observed_result": finding.observed_result,
            "validation_output": finding.validation_output,
            "proof_request": finding.proof_request,
            "proof_response": finding.proof_response,
            # Evidence the scanner stated about this occurrence (CVSS, fixed
            # version, advisory). Parsed once here so no screen re-parses it.
            "evidence": evidence,
            "cvss_score": evidence.get("cvss_score"),
            "cvss_vector": evidence.get("cvss_vector"),
            "fixed_version": evidence.get("fixed_version"),
            "project_id": finding.project_id,
            # The package is the object a dependency finding is really about: its
            # sheet lists every advisory that applies to this exact version,
            # which is a different question from "what else does this build carry".
            "component_id": finding.component_id,
            # Both spellings: the name is what a reader sees, the slug is what a
            # select can send back.
            "project_slug": (session.get(models.Project, finding.project_id).slug
                             if finding.project_id else None),
            "project": (session.get(models.Project, finding.project_id).name
                        if finding.project_id else None),
            "version": (session.get(models.ProjectVersion,
                                    finding.last_seen_version_id).version
                        if finding.last_seen_version_id else None),
            "asset_id": finding.asset_id,
            # F3: four independent facts about the same row (D29). `status` is the
            # lifecycle; these are who/whether/strong/how-far.
            "origin": finding.origin,
            "cycle": ({"id": cycle.id, "name": cycle.name, "kind": cycle.kind}
                      if cycle is not None else None),
            # The build it was seen in: the anchor a pentest claim names and a
            # dependency advisory inherits from the scan.
            "last_seen_version_id": finding.last_seen_version_id,
            "triage_status": finding.triage_status,
            "evidence_level": finding.evidence_level,
            "exploit_state": finding.exploit_state,
            "evidence_id": finding.evidence_id,
            "triaged_by": finding.triaged_by,
            "triaged_at": finding.triaged_at.isoformat() if finding.triaged_at else None,
            "triage_note": finding.triage_note,
            "priority": finding.priority,
            "priority_reason": finding.priority_reason,
            "assignee": finding.assignee,
            "sla_deadline": finding.sla_deadline.isoformat() if finding.sla_deadline else None,
            "first_seen_at": finding.first_seen_at.isoformat(),
            "last_seen_at": finding.last_seen_at.isoformat(),
    }


def _resolve(session, org_id: str, project: str, version: str):
    project_row = projects_ref.by_ref(session, org_id, project)
    if project_row is None:
        return None
    return (pick_version(session, project_row.id, version))


def _version(session, project_row, version: str):
    return (pick_version(session, project_row.id, version))


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
        # A hand-recorded finding is already a person's verdict: origin is manual and
        # the queue entry starts triaged, with the author recorded. An agent's row
        # would start `new` and wait for exactly this.
        origin="manual", triage_status="triaged", triaged_by=payload.actor,
        triaged_at=models.utcnow(), evidence_level="observed",
        exploit_state="none",
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


@router.post("/findings/record", status_code=status.HTTP_201_CREATED)
def record_finding(payload: claims.ClaimIn = None,
                   response: Response = None,
                   org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    """Record a vulnerability by hand, with or without a cycle.

    Same act as a cycle's ledger entry — same fields, same fingerprint, same
    `triage_status = new` — because the operator writes the record once and decides
    later which engagement it belongs to. `cycle_id` links it to a ledger when it
    has one; without it the finding still says where it lives (project, build,
    component, asset), which is what a replayable record needs.
    """
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    cycle = None
    if payload.cycle_id:
        cycle = session.get(models.Cycle, payload.cycle_id)
        if cycle is None or cycle.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "cycle not found")
        if cycle.state == "closed":
            raise HTTPException(status.HTTP_409_CONFLICT,
                                "a closed cycle takes no new findings; open the next one")
    try:
        finding, created = claims.record_claim(session, org, payload, cycle)
    except ValueError as error:
        message = str(error)
        code = (status.HTTP_404_NOT_FOUND if message.endswith("not found")
                else status.HTTP_422_UNPROCESSABLE_ENTITY)
        raise HTTPException(code, message) from None
    data = {
        "id": finding.id, "kind": finding.kind, "severity": finding.severity,
        "status": finding.status, "triage_status": finding.triage_status,
        "project_id": finding.project_id, "asset_id": finding.asset_id,
        "version_id": finding.last_seen_version_id,
        "cycle_id": cycle.id if cycle is not None else None,
    }
    if not created:
        if response is not None:
            response.status_code = status.HTTP_200_OK
        return {"data": data, "created": False}
    _audit_log(session, org.id, payload.actor, "finding.recorded", "finding",
               finding.id, finding.title or "")
    session.commit()
    return {"data": data, "created": True}


class AssigneeIn(BaseModel):
    assignee: str | None = Field(default=None, max_length=255)
    actor: str = Field(min_length=1, max_length=255)


class ProjectAttachIn(BaseModel):
    #: Slug or id. Empty detaches: a finding can belong to nobody, that is a fact.
    project: str | None = Field(default=None, max_length=160)
    actor: str = Field(default="", max_length=255)


@router.patch("/findings/{finding_id}/project")
def set_finding_project(finding_id: str, payload: ProjectAttachIn = None,
                        principal: dict = Depends(authz.principal),
                        org: models.Organization = Depends(auth.require_org),
                        session: Session = Depends(get_session)):
    """Attach a finding to a project, or detach it.

    A cycle's findings are about hosts; a project is what the estate is organised by.
    Without this the operator's only options were "it belongs to whatever asset the
    ingest matched" or nothing at all.
    """
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    finding = session.get(models.Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    actor = (payload.actor or "").strip() or authz.actor_of(principal)
    reference = (payload.project or "").strip()
    if not reference:
        finding.project_id = None
    else:
        project = (session.query(models.Project)
                   .filter(models.Project.org_id == org.id,
                           (models.Project.id == reference) | (models.Project.slug == reference))
                   .one_or_none())
        if project is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
        finding.project_id = project.id
    _audit_log(session, org.id, actor, "finding.project_attached", "finding",
               finding.id, reference or "detached")
    session.commit()
    return {"data": {"id": finding.id, "project": reference or None}}


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


# ─────────────────────────── triage: the gate (F3, D29–D30) ───────────────────

class TriageIn(BaseModel):
    """One move of the queue. Every axis is optional and independent.

    `triage_status` is a human verdict and always records who. `evidence_level` and
    `exploit_state` are claims about artifacts, and the gate verifies the artifact
    exists before it records the claim.
    """

    triage_status: str | None = Field(default=None)
    evidence_level: str | None = Field(default=None)
    exploit_state: str | None = Field(default=None)
    evidence_id: str | None = Field(default=None)
    note: str | None = Field(default=None, max_length=4000)
    actor: str = Field(min_length=1, max_length=255)


def _finding_for(session: Session, org: models.Organization,
                 finding_id: str) -> models.Finding:
    finding = (session.query(models.Finding)
               .filter_by(id=finding_id, org_id=org.id).one_or_none())
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    return finding


def _attachment_for(session: Session, finding: models.Finding,
                    evidence_id: str) -> models.FindingAttachment:
    row = session.get(models.FindingAttachment, evidence_id)
    if row is None or row.finding_id != finding.id:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"evidence_id {evidence_id} is not an attachment of this finding")
    return row


def _require_artifact(session: Session, finding: models.Finding, level: str,
                      evidence_id: str | None) -> None:
    """Proof is not a label; it is a thing that exists (D51).

    `static` needs a rule firing at file:line, `observed` needs something the scan
    produced (an attachment, or a run that evaluated it), `demonstrated` needs the
    effect. `hypothesis` needs nothing — that is what makes it a hypothesis.
    """
    if level == "hypothesis":
        return
    if level == "static":
        if not finding.path or finding.line is None:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "evidence_level=static needs a path and a line: a rule firing at "
                "file:line is the artifact")
        return
    if level == "observed":
        attachments = (session.query(models.FindingAttachment)
                       .filter_by(finding_id=finding.id).count())
        if not evidence_id and not attachments and not finding.last_evaluated_run_id:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "evidence_level=observed needs an artifact: attach the response or "
                "record the run that produced it")
        if evidence_id:
            _attachment_for(session, finding, evidence_id)
        return
    if level == "demonstrated":
        if not evidence_id:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                "evidence_level=demonstrated needs evidence_id: attach the effect")
        _attachment_for(session, finding, evidence_id)


@router.post("/findings/{finding_id}/triage")
def triage_finding(finding_id: str, payload: TriageIn = None,
                   org: models.Organization = Depends(auth.require_org),
                   session: Session = Depends(get_session)):
    """Move the three axes. The agent can never call this: it needs an actor."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    finding = _finding_for(session, org, finding_id)
    changed: list[str] = []

    level = payload.evidence_level or finding.evidence_level
    if payload.evidence_level is not None:
        if payload.evidence_level not in models.EVIDENCE_LEVELS:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"evidence_level must be one of {sorted(models.EVIDENCE_LEVELS)}")
        _require_artifact(session, finding, payload.evidence_level,
                          payload.evidence_id)

    if payload.evidence_id is not None:
        _attachment_for(session, finding, payload.evidence_id)
        finding.evidence_id = payload.evidence_id
        changed.append("evidence_id")

    if payload.evidence_level is not None:
        finding.evidence_level = payload.evidence_level
        # A proof stronger than `hypothesis` also settles the queue for the row: the
        # person handling it is the actor of this call.
        if payload.evidence_level in {"static", "observed", "demonstrated"}:
            if finding.triage_status == "new":
                finding.triage_status = "triaged"
                finding.triaged_by = payload.actor
                finding.triaged_at = models.utcnow()
                changed.append("triage_status")
        changed.append("evidence_level")

    if payload.exploit_state is not None:
        if payload.exploit_state not in models.EXPLOIT_STATES:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"exploit_state must be one of {sorted(models.EXPLOIT_STATES)}")
        if payload.exploit_state != "none":
            if level not in {"observed", "demonstrated"}:
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    "impact needs proof: raise evidence_level to observed or "
                    "demonstrated before recording exploitation")
            if not (payload.evidence_id or finding.evidence_id):
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    "exploit_state needs evidence_id: which artifact proves it?")
            if payload.exploit_state == "effect_proven" and level != "demonstrated":
                raise HTTPException(
                    status.HTTP_422_UNPROCESSABLE_ENTITY,
                    "effect_proven needs evidence_level=demonstrated")
        finding.exploit_state = payload.exploit_state
        changed.append("exploit_state")

    if payload.triage_status is not None:
        if payload.triage_status not in models.TRIAGE_STATUSES:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"triage_status must be one of {sorted(models.TRIAGE_STATUSES)}")
        # A row that leaves `new` needs a name against it. This is the
        # "si pasan triage son válidos" line, and it is a person's line.
        finding.triage_status = payload.triage_status
        finding.triaged_by = payload.actor
        finding.triaged_at = models.utcnow()
        finding.triage_note = payload.note
        changed.append("triage_status")

    if not changed:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "nothing to change: send triage_status, evidence_level, "
                            "exploit_state or evidence_id")
    finding.last_seen_at = finding.last_seen_at or models.utcnow()
    _audit_log(session, org.id, payload.actor, "finding.triaged", "finding",
               finding.id, ", ".join(sorted(set(changed))))
    session.commit()
    return {"data": finding_data(session, finding), "changed": sorted(set(changed))}


# ── REPEAT: send what the finding claims, with the login it needs ────────────

class RepeatStepIn(BaseModel):
    """One request in the chain, written the way a person writes it.

    `extract` is what turns a login into a reusable session: take `token` from
    `authentication.token` (JSON), a header, or a regex, then any later step may
    reference it as `{{token}}` in its url, headers or body.
    """

    label: str | None = Field(default=None, max_length=120)
    method: str = Field(default="GET", max_length=8)
    url: str = Field(min_length=8, max_length=2048)
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = Field(default=None, max_length=200000)
    extract: list[dict] = Field(default_factory=list, max_length=20)


class RepeatIn(BaseModel):
    # No steps means "seed it from the finding": its login profile, then its own
    # request. The screen always sends what the operator edited.
    steps: list[RepeatStepIn] = Field(default_factory=list, max_length=25)
    actor: str = Field(default="console", max_length=255)
    # Who the authorization engine is asked as. The console runs its own actions as
    # `console`, which honours the grants the platform's collector holds.
    principal: str | None = Field(default=None, max_length=255)
    environment: str | None = Field(default=None, max_length=64)


def _repeat_data(row: models.RepeatRun) -> dict:
    return {
        "id": row.id, "finding_id": row.finding_id, "actor": row.actor,
        "result": row.result, "error": row.error,
        "steps": json.loads(row.steps or "[]"),
        "variables": json.loads(row.variables or "{}"),
        "created_at": row.created_at.isoformat() if row.created_at else None,
    }


@router.get("/findings/{finding_id}/repeat")
def list_repeats(finding_id: str,
                 limit: int = Query(default=10, ge=1, le=50),
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """The chains already executed against this finding, newest first."""
    finding = session.get(models.Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    rows = (session.query(models.RepeatRun)
            .filter_by(org_id=org.id, finding_id=finding.id)
            .order_by(models.RepeatRun.created_at.desc()).limit(limit).all())
    return {"data": [_repeat_data(row) for row in rows], "total": len(rows)}


@router.post("/findings/{finding_id}/repeat", status_code=status.HTTP_201_CREATED)
def run_repeat(finding_id: str, payload: RepeatIn = None,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """Execute a chain for this finding and keep the run.

    The authorization gate lives in `repeat.run`: every step is asked for
    `active_verification`, mutating methods additionally for `intrusive_testing`.
    A denied step is stored as a run — "we tried and were not allowed" is a fact
    the next reader needs.
    """
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    finding = session.get(models.Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")

    steps = [step.model_dump() for step in payload.steps] or repeat.chain_from_finding(
        session, finding)
    if not steps:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "no chain: the finding states no request to replay")
    # A finding a field agent produced is replayed under the agent identity: the
    # person approved the mission, the machine holds the intrusive grant. Replaying
    # as the console asked a human grant to mirror an agent's, and every click on a
    # real finding ended in "a step is not authorized".
    principal = "agents" if finding.agent_mission_id else payload.principal
    try:
        outcome = repeat.run(session, org, steps, actor=payload.actor,
                             principal=principal,
                             environment=payload.environment)
    except repeat.ChainError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from None

    row = models.RepeatRun(
        org_id=org.id, finding_id=finding.id, actor=payload.actor,
        result=outcome["result"], steps=json.dumps(outcome["steps"]),
        variables=json.dumps({name: {"chars": len(str(value))}
                              for name, value in (outcome["variables"] or {}).items()}),
        error=outcome.get("error"), created_at=models.utcnow())
    session.add(row)
    session.flush()
    _audit_log(session, org.id, payload.actor, "finding.repeated", "finding",
               finding.id, f"{outcome['result']}: {len(outcome['steps'])} step(s)")
    session.commit()
    return {"data": _repeat_data(row)}

@router.get("/findings/{finding_id}/trace")
def finding_trace(finding_id: str,
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    """The story behind an autonomous finding: who was authorised, what it ran.

    A scanner finding's provenance is a run id; an agent's is a mission, a task and
    the events in between. This is the same shape for both: the envelope, the
    ordered events (tool → observation → decision), the gate verdicts and every
    repeat that already tried to reproduce it.
    """
    finding = session.get(models.Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")

    mission = (session.get(models.AgentMission, finding.agent_mission_id)
               if finding.agent_mission_id else None)
    task = (session.get(models.AgentTask, finding.agent_task_id)
            if finding.agent_task_id else None)
    events = []
    if task is not None:
        events = [{"seq": row.seq, "kind": row.kind, "tool": row.tool,
                   "payload": json.loads(row.payload or "{}"),
                   "at": row.created_at.isoformat()}
                  for row in (session.query(models.AgentTaskEvent)
                              .filter_by(task_id=task.id)
                              .order_by(models.AgentTaskEvent.seq).all())]
    gates = []
    if finding.agent_candidate_id:
        gates = [{"stage": row.stage, "verdict": row.verdict, "reason": row.reason,
                  "at": row.created_at.isoformat() if row.created_at else None}
                 for row in (session.query(models.GateRun)
                             .filter_by(candidate_id=finding.agent_candidate_id)
                             .order_by(models.GateRun.created_at).all())]
    repeats = [{"id": row.id, "result": row.result, "error": row.error,
                "steps": len(json.loads(row.steps or "[]")),
                "at": row.created_at.isoformat()}
               for row in (session.query(models.RepeatRun)
                           .filter_by(finding_id=finding.id)
                           .order_by(models.RepeatRun.created_at.desc()).all())]
    return {"data": {
        "finding": {"id": finding.id, "title": finding.title,
                    "severity": finding.severity, "evidence_level": finding.evidence_level,
                    "exploit_state": finding.exploit_state,
                    "triage_status": finding.triage_status, "url": finding.url},
        "mission": ({"id": mission.id, "goal": mission.goal,
                     "capability": mission.capability, "profile": mission.profile,
                     "actor": mission.actor, "approved_by": mission.approved_by,
                     "status": mission.status,
                     "budget": json.loads(mission.budget or "{}")}
                    if mission is not None else None),
        "task": ({"id": task.id, "kind": task.kind,
                  "target": json.loads(task.target or "{}"),
                  "worker": task.worker, "status": task.status,
                  "attempts": task.attempts} if task is not None else None),
        "events": events, "gates": gates, "repeats": repeats,
        # Usable is not "we found something": it is an observation with a locator
        # that the gates accepted, which is what makes Repeat worth pressing.
        "usable": bool(finding.exploit_state in {"reproduced", "effect_proven"}
                       or finding.evidence_level == "demonstrated"),
    }}


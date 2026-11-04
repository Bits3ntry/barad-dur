"""F2: normalized multi-kind finding ingestion and the suppression workflow.

Ingestion contract `barad-findings-v1`: the caller (CLI from sanitized
evidence, web upload, CI) posts a normalized payload; the platform owns the
per-kind fingerprint recipes, dedup, suppression application and counters.
Secret contents must be redacted BEFORE they reach this endpoint (the CLI's
sanitizer already does) — the platform stores what sanitized evidence carries
and never expects raw secret material.
"""
import fnmatch
import hashlib
import json

from pydantic import BaseModel, Field, ValidationError, field_validator

from backend.app import lifecycle, models

INGEST_KINDS = {"secret", "misconfiguration", "code-weakness"}
INGEST_SOURCES = {"cli", "web", "ci", "api"}
INGEST_TOOLS = {"trivy", "opengrep", "other"}
# One CLI sanitized report is tens of findings; a large CI upload is hundreds.
# 1000 keeps a single request bounded without punishing real reports.
MAX_FINDINGS_PER_INGEST = 1000


class IngestedFinding(BaseModel):
    kind: str
    title: str = Field(min_length=1, max_length=1024)
    severity: str | None = None
    tool: str | None = None
    rule_id: str | None = None
    path: str | None = None
    line: int | None = None
    detail: str | None = None

    @field_validator("kind")
    @classmethod
    def kind_known(cls, value):
        if value not in INGEST_KINDS:
            raise ValueError(f"kind must be one of {sorted(INGEST_KINDS)}")
        return value

    @field_validator("severity")
    @classmethod
    def severity_known(cls, value):
        if value is None:
            return value
        value = value.upper()
        if value not in {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}:
            raise ValueError("severity must be UNKNOWN|LOW|MEDIUM|HIGH|CRITICAL")
        return value

    @field_validator("tool")
    @classmethod
    def tool_known(cls, value):
        if value is None:
            return value
        if value not in INGEST_TOOLS:
            raise ValueError(f"tool must be one of {sorted(INGEST_TOOLS)}")
        return value


class FindingsPayload(BaseModel):
    contract: str = Field(alias="schema")
    tool: str | None = None
    findings: list[IngestedFinding] = Field(min_length=1)

    @field_validator("contract")
    @classmethod
    def contract_v1(cls, value):
        if value != "barad-findings-v1":
            raise ValueError("schema must be barad-findings-v1")
        return value

    model_config = {"populate_by_name": True}


def recipe_fingerprint(kind: str, org_id: str, project_id: str, rule_id: str | None,
                       path: str | None) -> str:
    """Per-kind recipe: rule + location identity; engine-agnostic on purpose."""
    base = f"v1|{kind}|{org_id}|{project_id}|{rule_id}|{path}"
    return hashlib.sha256(base.encode("utf-8")).hexdigest()


def error_of(exception: ValidationError) -> str:
    """Bounded, client-safe validation summary."""
    first = exception.errors()[0]
    location = ".".join(str(part) for part in first["loc"]) or "<root>"
    return f"{location}: {first['msg']}"


def ingest_payload(session, org, project, project_version, payload: FindingsPayload,
                   *, source: str) -> dict:
    findings = payload.findings
    if len(findings) > MAX_FINDINGS_PER_INGEST:
        raise ValueError(f"ingest carries {len(findings)} findings; limit is {MAX_FINDINGS_PER_INGEST}")
    counters = {"received": len(findings), "created": 0, "refreshed": 0,
                "suppressed_by_rule": 0, "skipped_missing_identity": 0}
    rules = _approved_rules(session, org.id)
    now = models.utcnow()
    for item in findings:
        grouped = payload.tool or (item.tool or "other")
        if not item.rule_id and not item.path:
            counters["skipped_missing_identity"] += 1
            continue
        fingerprint = recipe_fingerprint(item.kind, org.id, project.id,
                                         item.rule_id, item.path)
        finding = (session.query(models.Finding)
                   .filter_by(org_id=org.id, fingerprint=fingerprint).one_or_none())
        if finding is None:
            finding = models.Finding(
                org_id=org.id, project_id=project.id, kind=item.kind,
                fingerprint=fingerprint, source=source,
                title=item.title, severity=item.severity, url=None,
                detail=item.detail, tool=grouped, rule_id=item.rule_id,
                path=item.path, line=item.line,
                last_seen_version_id=project_version.id,
                first_seen_at=now, last_seen_at=now, updated_at=now)
            session.add(finding)
            session.flush()
            lifecycle.apply_lifecycle(session, org.id, finding)
            counters["created"] += 1
            # A brand-new finding is evaluated against every approved rule.
            applied = _apply_suppressions(session, finding, rules)
            counters["suppressed_by_rule"] += applied
        else:
            finding.last_seen_at = now
            finding.last_seen_version_id = project_version.id
            finding.title = item.title
            finding.severity = item.severity
            finding.line = item.line
            finding.updated_at = now
            counters["refreshed"] += 1
        _record_occurrence(session, org.id, finding, project_version.id,
                           grouped, source, item, now)
    return counters


def _record_occurrence(session, org_id: str, finding: models.Finding,
                       project_version_id: str, tool: str, source: str,
                       item, now) -> None:
    """One occurrence row per sighting; identical repeats stay one row via
    the (finding, sighting_key) pair (idempotent ingest)."""
    record_occurrence(
        session, org_id, finding, project_version_id, tool, source,
        kind=item.kind, rule_id=item.rule_id, path=item.path, line=item.line,
        detail=item.detail, now=now)


def sighting_key(kind, rule_id, path, line, tool, source, version_id) -> str:
    sighting = {
        "v": "1", "kind": kind, "rule": rule_id, "path": path,
        "line": line, "tool": tool, "source": source, "ver": version_id,
    }
    return hashlib.sha256(json.dumps(sighting, sort_keys=True).encode()).hexdigest()


def record_occurrence(session, org_id, finding, project_version_id, tool,
                      source, *, kind, rule_id, path, line, detail, now) -> None:
    key = sighting_key(kind, rule_id, path, line, tool, source, project_version_id)
    # The query below cannot see rows added earlier in this transaction when the
    # session runs with autoflush=False, which is how ingest is wired: a SARIF
    # run with several results on the same rule+path then hit
    # uq_occurrence_sighting. Track what this transaction has queued.
    pending = session.info.setdefault("occurrence_sightings", set())
    marker = (finding.id, key)
    if marker in pending:
        return
    pending.add(marker)
    existing = (session.query(models.Occurrence)
                .filter_by(finding_id=finding.id, sighting_key=key).one_or_none())
    if existing is not None:
        return
    session.add(models.Occurrence(
        org_id=org_id, finding_id=finding.id,
        project_version_id=project_version_id,
        tool=tool, source=source, sighting_key=key,
        evidence=detail, seen_at=now, created_at=now))


def _approved_rules(session, org_id: str) -> list[models.SuppressionRule]:
    rules = (session.query(models.SuppressionRule)
             .filter_by(org_id=org_id, status="approved").all())
    now = models.utcnow()
    active = []
    for rule in rules:
        if rule.expires_at is not None:
            expires = _aware(rule.expires_at)
            if expires is not None and expires < now:
                rule.status = "expired"
                rule.updated_at = now
                continue
        active.append(rule)
    return active


def _aware(value):
    from datetime import timezone

    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def _matches(rule: models.SuppressionRule, finding: models.Finding) -> bool:
    if rule.project_id and rule.project_id != finding.project_id:
        return False
    if rule.kind and rule.kind != finding.kind:
        return False
    if rule.rule_id and rule.rule_id != (finding.rule_id or ""):
        return False
    if rule.path_pattern:
        if not finding.path or not fnmatch.fnmatch(finding.path, rule.path_pattern):
            return False
    return bool(rule.kind or rule.rule_id or rule.path_pattern)


def _apply_suppressions(session, finding: models.Finding,
                        rules: list[models.SuppressionRule]) -> int:
    applied = 0
    now = models.utcnow()
    for rule in rules:
        if not _matches(rule, finding):
            continue
        existing = (session.query(models.FindingSuppression)
                    .filter_by(finding_id=finding.id, rule_id=rule.id).one_or_none())
        if existing is not None:
            continue
        session.add(models.FindingSuppression(
            finding_id=finding.id, rule_id=rule.id, applied_at=now, applied_by=rule.approved_by))
        if finding.status == "open":
            finding.status = "suppressed"
            finding.status_reason = f"suppression rule {rule.id}: {rule.reason}"
            finding.status_changed_at = now
        applied += 1
    return applied


def approve_rule(session, rule: models.SuppressionRule, approver: str) -> int:
    """Approve (requester may not self-approve) then apply the rule to every
    open finding it matches. Returns the number of findings suppressed."""
    if rule.requested_by and rule.requested_by == approver:
        raise ValueError("a requester cannot approve their own suppression rule")
    if rule.status != "pending":
        raise ValueError(f"rule is {rule.status}, only pending rules can be approved")
    rule.status = "approved"
    rule.approved_by = approver
    rule.updated_at = models.utcnow()
    session.flush()
    matching = (session.query(models.Finding)
                .filter_by(org_id=rule.org_id, status="open").all())
    applied = 0
    for finding in matching:
        applied += _apply_suppressions(session, finding, [rule])
    return applied


def reject_rule(session, rule: models.SuppressionRule, approver: str,
                reason: str) -> None:
    if rule.requested_by and rule.requested_by == approver:
        raise ValueError("a requester cannot review their own suppression rule")
    if rule.status != "pending":
        raise ValueError(f"rule is {rule.status}, only pending rules can be rejected")
    rule.status = "rejected"
    rule.approved_by = approver
    rule.rejection_reason = reason
    rule.updated_at = models.utcnow()

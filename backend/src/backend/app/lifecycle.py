"""B1: finding lifecycle — priority classification, SLA deadlines, remediation.

Priority uses severity fall-backs plus org rules (first rule match wins,
ordered by position). Every classification carries its explanation, like the
reference platform's priority_reason. SLA deadlines come from the org's
default policy per-day buckets.
"""
import datetime

<<<<<<< Updated upstream
from backend.app import models, severity as severity_mod
=======
from backend.app import models
>>>>>>> Stashed changes

SEVERITY_FALLBACK = {
    "CRITICAL": "P0",
    "HIGH": "P1",
    "MEDIUM": "P2",
    "LOW": "P3",
    "UNKNOWN": "P3",
}
_PRIORITY_DAYS = {"P0": "p0_days", "P1": "p1_days", "P2": "p2_days", "P3": "p3_days"}


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def classify(session, org_id: str, finding: models.Finding) -> tuple[str, str]:
    """(priority, reason): first inclusive matching org rule wins, then the
    severity fallback table. Rule criteria may include intel membership
    (`match_intel='kev'`: the advisory's CVE is exploited in the wild) so KEV
    stays a configurable rule, not a hard global override."""
    rules = (session.query(models.PriorityRule)
             .filter_by(org_id=org_id)
             .order_by(models.PriorityRule.position).all())
    for rule in rules:
        if rule.match_kind and rule.match_kind != finding.kind:
            continue
        if rule.match_source and rule.match_source != (finding.source or ""):
            continue
        if rule.match_severities:
            wanted = {s.strip().upper() for s in rule.match_severities.split(",")}
<<<<<<< Updated upstream
            mine = severity_mod.canonical(finding.severity)
=======
            mine = (finding.severity or "UNKNOWN").upper()
>>>>>>> Stashed changes
            if mine not in wanted:
                continue
        if rule.match_intel:
            intel_hit = False
            if rule.match_intel == "kev" and finding.vulnerability_id:
                advisory = session.get(models.Vulnerability, finding.vulnerability_id)
                intel_hit = bool(
                    advisory and advisory.cve_id and
                    session.get(models.KevEntry, advisory.cve_id))
            if not intel_hit:
                continue
        has_criterion = bool(rule.match_kind or rule.match_source
                             or rule.match_severities or rule.match_intel)
        if has_criterion:
            return rule.priority, rule.reason
<<<<<<< Updated upstream
    fallback = SEVERITY_FALLBACK.get(severity_mod.canonical(finding.severity), "P3")
    return fallback, f"severity {severity_mod.canonical(finding.severity)} fallback"
=======
    fallback = SEVERITY_FALLBACK.get((finding.severity or "UNKNOWN").upper(), "P3")
    return fallback, f"severity {finding.severity or 'UNKNOWN'} fallback"
>>>>>>> Stashed changes


def default_policy(session, org_id: str):
    return (session.query(models.SlaPolicy)
            .filter_by(org_id=org_id, is_default=True).one_or_none())


def apply_lifecycle(session, org_id: str, finding: models.Finding) -> None:
    """Set priority (rule or fall-back) and refresh the SLA deadline computed
    from the org's default policy buckets."""
    priority, reason = classify(session, org_id, finding)
    changed = finding.priority != priority or finding.priority_reason != reason
    finding.priority = priority
    finding.priority_reason = reason
    policy = default_policy(session, org_id)
    if policy is not None:
        days = getattr(policy, _PRIORITY_DAYS[priority])
        base = finding.created_at or _now()
        base = _aware(base)
        finding.sla_deadline = (base + datetime.timedelta(days=days))
    if changed:
        finding.updated_at = _now()


def reclassify_org(session, org_id: str) -> int:
    """Re-run classification over the org's findings (rule edits trigger this
    from the router; their recylýania machinery kept as a backfill-only loop)."""
    rows = session.query(models.Finding).filter_by(org_id=org_id).all()
    changed = 0
    for finding in rows:
        before = (finding.priority, finding.priority_reason)
        apply_lifecycle(session, org_id, finding)
        if (finding.priority, finding.priority_reason) != before:
            changed += 1
    return changed


def _aware(value: datetime.datetime) -> datetime.datetime:
    from datetime import timezone

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value

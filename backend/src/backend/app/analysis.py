"""Closure of findings based on what an analysis actually evaluated.

Rule (v0): a finding becomes `resolved` because it was absent from a scan only
when that scan had **full coverage**, used the same tool, and evaluated the
finding's location. A diff or partial run can never close anything, and an
inconclusive run is not evidence of a fix.

The preview and the apply path share `plan_closure`, so the number a reader sees
is the number that changes.
"""
from backend.app import models

CLOSABLE_COVERAGES = {"full"}
OPEN_STATUSES = {"open", "acknowledged"}

REASON_NOT_FULL = (
    "coverage is {coverage}: a run that did not evaluate the whole target cannot "
    "show that a finding is fixed")
REASON_NO_VERSION = "the run is not bound to a project version, so it has no scope to close"


def _tool_matches(finding, run) -> bool:
    if not run.tool:
        return False
    if finding.tool:
        return finding.tool.lower() == run.tool.lower()
    # Advisories matched by the platform carry no tool; their source is the tool.
    return (finding.source or "").lower() == run.tool.lower()


def _scope_matches(finding, run, evaluated_paths: list[str]) -> bool:
    """A full run covers everything; an explicit path list narrows it.

    A finding with a path is only inside a narrowed run when its path was
    evaluated; a finding without a location is outside any narrowed run.
    """
    if not evaluated_paths:
        return True
    if not finding.path:
        return False
    return any(finding.path == path or finding.path.startswith(path.rstrip("/") + "/")
               for path in evaluated_paths)


def plan_closure(session, run: models.AnalysisRun) -> dict:
    if run.coverage not in CLOSABLE_COVERAGES:
        return {"eligible": False, "reason": REASON_NOT_FULL.format(coverage=run.coverage),
                "closable": [], "skipped": [], "counts": {"closable": 0, "skipped": 0}}
    if not run.project_version_id:
        return {"eligible": False, "reason": REASON_NO_VERSION,
                "closable": [], "skipped": [], "counts": {"closable": 0, "skipped": 0}}

    evaluated = run.evaluated or {}
    evaluated_paths = [path for path in (evaluated.get("paths") or []) if path]
    findings = (session.query(models.Finding)
                .filter(models.Finding.org_id == run.org_id,
                        models.Finding.project_id == run.project_id,
                        models.Finding.last_seen_version_id == run.project_version_id)
                .all())
    closable, skipped = [], []
    for finding in findings:
        if finding.status not in OPEN_STATUSES:
            skipped.append({"id": finding.id, "reason": f"status is {finding.status}"})
            continue
        if not _tool_matches(finding, run):
            skipped.append({"id": finding.id,
                            "reason": f"produced by {finding.tool or finding.source}, "
                                      f"not by {run.tool}"})
            continue
        if not _scope_matches(finding, run, evaluated_paths):
            skipped.append({"id": finding.id,
                            "reason": "location was outside this run's evaluated paths"})
            continue
        closable.append({"id": finding.id, "title": finding.title,
                         "severity": finding.severity, "path": finding.path,
                         "status": finding.status})
    return {"eligible": True, "reason": None, "closable": closable,
            "skipped": skipped,
            "counts": {"closable": len(closable), "skipped": len(skipped)}}


def apply_closure(session, run: models.AnalysisRun, actor: str) -> dict:
    """Close the findings the plan lists; returns what changed and what did not."""
    plan = plan_closure(session, run)
    if not plan["eligible"]:
        plan["changed"] = 0
        return plan
    from backend.app.routers.identity import _audit as _audit_log
    changed = []
    for item in plan["closable"]:
        finding = session.get(models.Finding, item["id"])
        if finding is None:
            continue
        finding.status = "resolved"
        tool_label = " ".join(part for part in (run.tool, run.tool_version) if part)
        finding.status_reason = (
            f"not observed by run {run.id} ({tool_label}, full coverage)")
        finding.status_changed_at = models.utcnow()
        finding.updated_at = finding.status_changed_at
        finding.last_evaluated_run_id = run.id
        _audit_log(session, run.org_id, actor, "finding.closed_by_analysis",
                   "finding", finding.id,
                   f"run {run.id} ({run.tool}, {run.coverage})")
        changed.append(finding.id)
    plan["changed"] = len(changed)
    plan["changed_ids"] = changed
    return plan

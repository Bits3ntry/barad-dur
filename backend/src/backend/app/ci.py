"""F3: CI run registration, findings attachment and gate verdicts."""
import datetime

from backend.app import models

DEFAULT_GATE_MAX_SEVERITY = "HIGH"  # fails on HIGH and CRITICAL
_SEVERITY_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
MAX_REASON_LINES = 5


def _now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


def register_run(session, org_id: str, *, provider: str, repository: str,
                 workflow_path: str | None, ref: str | None, commit_sha: str | None,
                 event: str | None, actor: str | None) -> models.CiRun:
    pipeline = _pipeline(session, org_id, provider, repository, workflow_path)
    now = _now()
    run = models.CiRun(org_id=org_id, pipeline_id=pipeline.id if pipeline else None,
                       ref=ref, commit_sha=commit_sha, event=event, actor=actor,
                       status="running", started_at=now,
                       created_at=now, updated_at=now)
    session.add(run)
    session.flush()
    return run


def _pipeline(session, org_id: str, provider: str, repository: str,
              workflow_path: str | None) -> models.CiPipeline | None:
    pipeline = (session.query(models.CiPipeline)
                .filter_by(org_id=org_id, provider=provider,
                           repository=repository, workflow_path=workflow_path)
                .one_or_none())
    if pipeline is None:
        pipeline = models.CiPipeline(org_id=org_id, provider=provider,
                                     repository=repository, workflow_path=workflow_path)
        session.add(pipeline)
        session.flush()
    return pipeline


def attach_finding(session, run: models.CiRun, finding: models.Finding) -> bool:
    """Attach a finding to a run; idempotent per (run, finding)."""
    existing = (session.query(models.CiRunFinding)
                .filter_by(run_id=run.id, finding_id=finding.id).one_or_none())
    if existing is not None:
        return False
    session.add(models.CiRunFinding(run_id=run.id, finding_id=finding.id,
                                    severity=finding.severity, created_at=_now()))
    session.flush()  # visible to the same-request verdict computation
    return True


def finish_run(session, run: models.CiRun, *, status: str) -> dict:
    """Close a run and compute the fail-closed gate verdict.

    Any UNKNOWN/scan failure also fails the run: an incomplete scan must never
    produce a passing verdict. Reason lines are capped for public CI logs.
    """
    if run.status != "running":
        raise ValueError(f"run is {run.status}, only running runs finish")
    if status not in ("succeeded", "failed"):
        raise ValueError("status must be succeeded or failed")
    now = _now()
    run.status = status
    run.finished_at = now
    run.updated_at = now

    rows = (session.query(models.CiRunFinding, models.Finding)
            .join(models.Finding, models.CiRunFinding.finding_id == models.Finding.id)
            .filter(models.CiRunFinding.run_id == run.id).all())
    run.findings_count = len(rows)
    reasons = []
    worst = "UNKNOWN"
    for _link, finding in rows:
        severity = (finding.severity or "UNKNOWN").upper()
        if _SEVERITY_ORDER.get(severity, 0) > _SEVERITY_ORDER.get(worst, 0):
            worst = severity
        if _SEVERITY_ORDER.get(severity, 0) >= _SEVERITY_ORDER[DEFAULT_GATE_MAX_SEVERITY]:
            if len(reasons) < MAX_REASON_LINES:
                reasons.append(f"{severity} {finding.kind} {finding.rule_id or '-'} "
                               f"{finding.path or ''}".strip())
    if status != "succeeded":
        run.verdict = "fail"
        run.verdict_detail = "CI run reported failure"
        return _summary(run, failed=True)

    exceeding = any(
        (link.severity or "UNKNOWN").upper() in ("HIGH", "CRITICAL")
        for link, _finding in rows)
    if exceeding:
        run.verdict = "fail"
        run.verdict_detail = ("gate: findings at or above "
                              + DEFAULT_GATE_MAX_SEVERITY
                              + "\n" + "\n".join(reasons)) if reasons else \
            "gate: findings at or above " + DEFAULT_GATE_MAX_SEVERITY
        return _summary(run, failed=True)

    run.verdict = "pass"
    run.verdict_detail = (f"gate: {len(rows)} finding(s), none at or above "
                          + DEFAULT_GATE_MAX_SEVERITY)
    return _summary(run, failed=False)


def _summary(run: models.CiRun, *, failed: bool) -> dict:
    return {"run_id": run.id, "verdict": run.verdict or "",
            "findings_count": run.findings_count, "failed": failed}

"""BL-110: dashboard aggregates over real data (no fabricated values)."""
import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from backend.app import auth, gates, licenses, models
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1", tags=["dashboard"])

NON_OPEN = {"resolved", "false_positive", "accepted_risk"}
SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def _aware(value):
    if value.tzinfo is None:
        return value.replace(tzinfo=datetime.timezone.utc)
    return value


@router.get("/dashboard/summary")
def summary(project: str | None = Query(default=None),
            version: str | None = Query(default=None),
            org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    now = models.utcnow()
    week_ago = now - datetime.timedelta(days=7)
    week_soon = now + datetime.timedelta(days=2)

    proj = None
    if project is not None:
        proj = (session.query(models.Project)
                .filter_by(org_id=org.id, slug=project).one_or_none())
    pv = None
    if proj is not None and version is not None:
        pv = (session.query(models.ProjectVersion)
              .filter_by(project_id=proj.id, version=version).one_or_none())

    findings_query = session.query(models.Finding).filter_by(org_id=org.id)
    if proj is not None:
        findings_query = findings_query.filter_by(project_id=proj.id)
    if pv is not None:
        findings_query = findings_query.filter_by(last_seen_version_id=pv.id)
    findings = findings_query.all()

    open_findings = [f for f in findings if f.status not in NON_OPEN]
    severity_counts = {sev: 0 for sev in SEVERITIES}
    for finding in open_findings:
        severity_counts[(finding.severity or "UNKNOWN").upper()
                        if (finding.severity or "").upper() in severity_counts
                        else "UNKNOWN"] += 1

    kev_open = 0
    for finding in open_findings:
        if finding.vulnerability_id:
            advisory = session.get(models.Vulnerability, finding.vulnerability_id)
            if advisory and advisory.cve_id and \
                    session.get(models.KevEntry, advisory.cve_id) is not None:
                kev_open += 1

    sla_breached = sum(
        1 for f in open_findings
        if f.sla_deadline and _aware(f.sla_deadline) < now)
    sla_soon = sum(
        1 for f in open_findings
        if f.sla_deadline and now <= _aware(f.sla_deadline) <= week_soon)

    new_findings_week = sum(
        1 for f in findings if f.first_seen_at and _aware(f.first_seen_at) >= week_ago)
    resolved_week = sum(
        1 for f in findings
        if f.status == "resolved" and f.status_changed_at
        and _aware(f.status_changed_at) >= week_ago)

    assets_query = session.query(models.Asset).filter_by(org_id=org.id)
    assets_total = assets_query.count()
    assets_week = sum(
        1 for asset in assets_query.all()
        if asset.discovered_at and _aware(asset.discovered_at) >= week_ago)

    ci_runs = (session.query(models.CiRun).filter_by(org_id=org.id)
               .order_by(models.CiRun.started_at.desc()).limit(50).all())
    verdicts = {"pass": 0, "fail": 0, "pending": 0}
    for run in ci_runs:
        verdicts[run.verdict if run.verdict in verdicts else "pending"] += 1

    tasks = session.query(models.RemediationTask).filter_by(org_id=org.id).all()
    remediation = {"open": 0, "in_progress": 0, "resolved": 0}
    for task in tasks:
        if task.status in remediation:
            remediation[task.status] += 1

    licenses_block = None
    if proj is not None and pv is not None:
        result = licenses.evaluate_project_version(session, org.id, proj, pv)
        licenses_block = result["counts"]

    gate_block = None
    if proj is not None:
        gate_result = gates.evaluate(session, org.id, proj, pv)
        gate_block = {"verdict": gate_result["verdict"],
                      "reasons": gate_result["reasons"]}

    occurrences_week = (session.query(models.Occurrence).filter_by(org_id=org.id)
                        .filter(models.Occurrence.seen_at >= week_ago).count())


    # Scanner execution health (management plane view of the Shauron workers).
    day_ago = now - datetime.timedelta(hours=24)
    workers = session.query(models.Worker).filter_by(org_id=org.id).all()
    worker_online = 0
    worker_stale = 0
    for worker in workers:
        stale = (now - _aware(worker.last_heartbeat)).total_seconds() > 120
        if stale:
            worker_stale += 1
        else:
            worker_online += 1
    jobs = session.query(models.ScanJob).filter_by(org_id=org.id).all()
    job_states = {"queued": 0, "leased": 0, "running": 0,
                  "succeeded": 0, "failed": 0, "cancelled": 0}
    recent_success = recent_failure = 0
    durations = []
    last_errors = []
    for job in jobs:
        if job.status in job_states:
            job_states[job.status] += 1
        if job.finished_at and _aware(job.finished_at) >= day_ago:
            if job.status == "succeeded":
                recent_success += 1
            elif job.status == "failed":
                recent_failure += 1
                if job.error:
                    last_errors.append({"scanner": job.scanner,
                                        "error": job.error[:160]})
        if job.started_at and job.finished_at and job.status == "succeeded":
            durations.append(
                (_aware(job.finished_at) - _aware(job.started_at)).total_seconds())
    orchestration = {
        "workers": {"total": len(workers), "online": worker_online,
                    "stale": worker_stale},
        "jobs": job_states,
        "last_24h": {"succeeded": recent_success, "failed": recent_failure},
        "avg_duration_s": round(sum(durations) / len(durations), 1) if durations else None,
        "recent_failures": last_errors[:5],
    }

    # Pentest posture.
    engagements = (session.query(models.PentestEngagement)
                   .filter_by(org_id=org.id).all())
    pentest_states = {"draft": 0, "active": 0, "completed": 0, "cancelled": 0}
    for engagement in engagements:
        if engagement.status in pentest_states:
            pentest_states[engagement.status] += 1
    pentest_findings = (session.query(models.PentestFinding)
                        .filter_by(org_id=org.id).all())
    pentest = {
        "engagements": pentest_states,
        "findings_open": sum(1 for row in pentest_findings
                             if row.status not in {"closed", "false_positive"}),
        "findings_total": len(pentest_findings),
    }

    return {"data": {
        "scope": {"project": proj.slug if proj else None,
                  "version": pv.version if pv else None},
        "findings": {
            "total": len(findings), "open": len(open_findings),
            "by_severity_open": severity_counts, "kev_open": kev_open,
            "new_last_7d": new_findings_week, "resolved_last_7d": resolved_week,
            "sla_breached": sla_breached, "sla_due_within_2d": sla_soon,
        },
        "supply_chain": licenses_block,
        "gate": gate_block,
        "assets": {"total": assets_total, "discovered_last_7d": assets_week},
        "ci": {"runs_considered": len(ci_runs), "verdicts": verdicts},
        "remediation": remediation,
        "orchestration": orchestration,
        "pentest": pentest,
        "occurrences_last_7d": occurrences_week,
        "generated_at": now.isoformat(),
    }}


@router.get("/dashboard/projects")
def projects_posture(org: models.Organization = Depends(auth.require_org),
                     session: Session = Depends(get_session)):
    """Per-project posture for the organization view."""
    rows = (session.query(models.Project).filter_by(org_id=org.id).all())
    data = []
    for project in rows:
        findings = (session.query(models.Finding)
                    .filter_by(org_id=org.id, project_id=project.id).all())
        open_rows = [f for f in findings if f.status not in NON_OPEN]
        critical = sum(1 for f in open_rows
                       if (f.severity or "").upper() == "CRITICAL")
        high = sum(1 for f in open_rows if (f.severity or "").upper() == "HIGH")
        data.append({"project": project.slug, "open": len(open_rows),
                     "critical": critical, "high": high,
                     "total": len(findings)})
    data.sort(key=lambda row: row["critical"] * 10 + row["high"],
              reverse=True)
    return {"data": data, "total": len(data)}

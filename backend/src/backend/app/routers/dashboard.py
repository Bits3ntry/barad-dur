"""BL-110: dashboard aggregates over real data (no fabricated values)."""
import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app.versions import pick_version
from backend.app import auth, gates, licenses, models, projects as projects_ref, severity as severity_mod
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1", tags=["dashboard"])

NON_OPEN = {"resolved", "false_positive", "accepted_risk"}
SEVERITIES = list(severity_mod.SEVERITIES)


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

    proj = projects_ref.by_ref(session, org.id, project)
    if project is not None and proj is None:
        # An unknown project must not answer with the whole organization.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    pv = None
    if proj is not None and version is not None:
        pv = (pick_version(session, proj.id, version))

    findings_query = session.query(models.Finding).filter_by(org_id=org.id)
    if proj is not None:
        findings_query = findings_query.filter_by(project_id=proj.id)
    if pv is not None:
        findings_query = findings_query.filter_by(last_seen_version_id=pv.id)
    findings = findings_query.all()

    open_findings = [f for f in findings if f.status not in NON_OPEN]
    severity_counts = {sev: 0 for sev in SEVERITIES}
    for finding in open_findings:
        severity_counts[severity_mod.canonical(finding.severity)] += 1

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


@router.get("/dashboard/findings/severity/time-series")
def findings_severity_time_series(
        window: int = Query(30, ge=1, le=90),
        org: models.Organization = Depends(auth.require_org),
        session: Session = Depends(get_session)):
    """New findings per day, split by severity, oldest bucket first."""
    now = models.utcnow()
    start = (now - datetime.timedelta(days=window - 1)).replace(
        hour=0, minute=0, second=0, microsecond=0)
    rows = (session.query(models.Finding)
            .filter(models.Finding.org_id == org.id,
                    models.Finding.first_seen_at >= start)
            .all())
    buckets: dict[str, dict[str, int]] = {}
    for day in range(window):
        key = (start + datetime.timedelta(days=day)).date().isoformat()
        buckets[key] = {sev: 0 for sev in SEVERITIES}
    for finding in rows:
        if not finding.first_seen_at:
            continue
        key = _aware(finding.first_seen_at).date().isoformat()
        bucket = buckets.get(key)
        if bucket is None:
            continue
        bucket[severity_mod.canonical(finding.severity)] += 1
    return {"data": [{"date": date, **counts} for date, counts in buckets.items()]}



@router.get("/dashboard/findings/occurrences/time-series")
def findings_occurrences_time_series(
        window: int = Query(30, ge=1, le=90),
        org: models.Organization = Depends(auth.require_org),
        session: Session = Depends(get_session)):
    """Occurrence counts over time (for line chart)."""
    now = models.utcnow()
    start = now - datetime.timedelta(days=window)
    rows = (session.query(models.Occurrence)
            .filter(models.Occurrence.seen_at >= start,
                    models.Occurrence.org_id == org.id)
            .all())
    counts = {}
    for o in rows:
        date = _aware(o.seen_at).replace(hour=0, minute=0, second=0, microsecond=0)
        counts[date.isoformat()] = counts.get(date.isoformat(), 0) + 1
    return {"data": [{"date": k, "count": v} for k, v in sorted(counts.items())]}





@router.get("/dashboard/findings/severity/pie")
def findings_severity_pie_chart(
        org: models.Organization = Depends(auth.require_org),
        session: Session = Depends(get_session)):
    """Severity distribution for pie/donut chart (real data)."""
    now = models.utcnow()
    rows = (session.query(models.Finding)
            .filter(models.Finding.org_id == org.id)
            .all())
    counts = {sev: 0 for sev in SEVERITIES}
    for f in rows:
        counts[severity_mod.canonical(f.severity)] += 1
    return {"data": counts}



@router.get("/dashboard/findings/occurrences/line")
def findings_occurrences_line_chart(
        window: int = Query(30, ge=1, le=90),
        org: models.Organization = Depends(auth.require_org),
        session: Session = Depends(get_session)):
    """Occurrence counts over time for line chart (real data)."""
    now = models.utcnow()
    start = now - datetime.timedelta(days=window)
    rows = (session.query(models.Occurrence)
            .filter(models.Occurrence.seen_at >= start,
                    models.Occurrence.org_id == org.id)
            .all())
    counts = {}
    for o in rows:
        date = _aware(o.seen_at).replace(hour=0, minute=0, second=0, microsecond=0)
        counts[date.isoformat()] = counts.get(date.isoformat(), 0) + 1
    return {"data": [{"date": k, "count": v} for k, v in sorted(counts.items())]}


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
                       if severity_mod.canonical(f.severity) == "CRITICAL")
        high = sum(1 for f in open_rows if severity_mod.canonical(f.severity) == "HIGH")
        data.append({"project": project.slug, "open": len(open_rows),
                     "critical": critical, "high": high,
                     "total": len(findings)})
    data.sort(key=lambda row: row["critical"] * 10 + row["high"],
              reverse=True)
    return {"data": data, "total": len(data)}


@router.get("/dashboard/exposure-flow")
def exposure_flow(window: int = Query(default=30, ge=1, le=365),
                  project: str | None = Query(default=None),
                  version: str | None = Query(default=None),
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    """Exposure flow: what came in, what is actionable, and where it stands.

    Every number is read from the findings table; nothing is estimated. Stages
    that have no data in this deployment (in progress, fixed, accepted) are
    returned as zero rather than omitted, so the diagram can render a complete
    outcome column and a reader can tell "none yet" from "not tracked".
    """
    now = models.utcnow()
    since = now - datetime.timedelta(days=window)

    proj = projects_ref.by_ref(session, org.id, project)
    if project is not None and proj is None:
        # An unknown scope must not silently answer with the whole org, but an
        # omitted scope is the organization's own portfolio.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    pv = None
    if proj is not None and version is not None:
        pv = (pick_version(session, proj.id, version))
        if pv is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")

    query = session.query(models.Finding).filter_by(org_id=org.id)
    if proj is not None:
        query = query.filter_by(project_id=proj.id)
    if pv is not None:
        query = query.filter_by(last_seen_version_id=pv.id)
    findings = query.all()

    received = [f for f in findings if f.first_seen_at and _aware(f.first_seen_at) >= since]
    open_now = [f for f in findings if f.status not in NON_OPEN and f.status != "suppressed"]

    sources: dict[tuple[str, str], int] = {}
    for finding in received:
        # The same engine arrives spelled OpenGrep / opengrep / Opengrep OSS;
        # one row per tool, or the flow lies about how many sources there are.
        tool = (finding.tool or finding.source or "import").strip().lower()
        if tool.startswith("opengrep"):
            tool = "opengrep"
        sources[(finding.kind, tool)] = sources.get((finding.kind, tool), 0) + 1
    source_rows = sorted(
        ({"kind": kind, "tool": tool, "count": count}
         for (kind, tool), count in sources.items()),
        key=lambda row: (-row["count"], row["kind"], row["tool"]))

    by_priority = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "unranked": 0}
    for finding in open_now:
        key = (finding.priority or "").upper()
        by_priority[key if key in by_priority else "unranked"] += 1

    past_sla = 0
    for finding in open_now:
        deadline = finding.sla_deadline
        if deadline is not None and _aware(deadline) < now:
            past_sla += 1

    suppressed = sum(1 for f in findings if f.status == "suppressed")
    in_progress = sum(1 for f in findings if f.status == "in_progress")
    resolved = sum(1 for f in findings if f.status in NON_OPEN)
    closed_in_window = sum(
        1 for f in findings
        if f.status in NON_OPEN and f.status_changed_at
        and _aware(f.status_changed_at) >= since)

    return {"data": {
        "window_days": window,
        "sources": source_rows,
        "received": len(received),
        "actionable": len(open_now),
        "by_priority": by_priority,
        "outcomes": {
            "open": len(open_now),
            "past_sla": past_sla,
            "in_progress": in_progress,
            "suppressed": suppressed,
            "resolved": resolved,
            "closed_in_window": closed_in_window,
        },
    }}


@router.get("/dashboard/v0")
def v0_overview(org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    """The v0 dashboard block: every number comes from a query, and each one
    declares where it links. Blocks that depend on coverage say so."""
    from backend.app import severity as severity_vocab
    from backend.app.routers.vulnerabilities import _groups

    now = models.utcnow()
    findings = (session.query(models.Finding)
                .filter_by(org_id=org.id)
                .filter(models.Finding.status != "suppressed").all())
    open_findings = [row for row in findings if row.status in {"open", "acknowledged"}]
    by_severity: dict[str, int] = {}
    by_priority: dict[str, int] = {}
    for row in open_findings:
        severity = severity_vocab.canonical(row.severity)
        by_severity[severity] = by_severity.get(severity, 0) + 1
        key = row.priority or "unclassified"
        by_priority[key] = by_priority.get(key, 0) + 1

    assets = (session.query(models.Asset)
              .filter_by(org_id=org.id)
              .filter(models.Asset.archived_at.is_(None)).count())
    projects = (session.query(models.Project).filter_by(org_id=org.id).count())
    problems = _groups(session, org, include_suppressed=False)
    cves = [row for row in problems if row["cve_id"]]
    cycles_active = (session.query(models.Cycle)
                     .filter_by(org_id=org.id, state="active").count())
    cycles_review = (session.query(models.Cycle)
                     .filter_by(org_id=org.id, state="review").count())
    open_exposures = (session.query(models.ExposureEvent)
                      .filter_by(org_id=org.id, state="open").count())
    needs_owner = (session.query(models.Asset)
                   .filter_by(org_id=org.id, owner=None)
                   .filter(models.Asset.archived_at.is_(None)).count())
    acceptances_soon = (session.query(models.WorkItem)
                        .filter_by(org_id=org.id, kind="acceptance")
                        .filter(models.WorkItem.status.notin_(["rejected", "withdrawn"]))
                        .all())
    expiring = 0
    for item in acceptances_soon:
        if item.valid_until is None:
            continue
        due = item.valid_until if item.valid_until.tzinfo else \
            item.valid_until.replace(tzinfo=datetime.timezone.utc)
        if due <= now + datetime.timedelta(days=30):
            expiring += 1

    from backend.app.routers.exposures import changes as changes_query
    recent = changes_query(days=7, category=None, asset=None, limit=1,
                           org=org, session=session)

    return {"data": {
        "generated_at": now.isoformat(),
        "assets": {"value": assets, "link": "assets",
                   "filters": {"include_archived": False}},
        "projects": {"value": projects, "link": "projects"},
        "findings": {"open": len(open_findings), "by_severity": by_severity,
                     "by_priority": by_priority, "link": "findings",
                     "filters": {"status": ["open", "acknowledged"],
                                 "include_suppressed": False}},
        "vulnerabilities": {"problems": len(problems),
                            "cves": len(cves),
                            "kev": sum(1 for row in cves
                                       if row["enrichment"]["kev"]["listed"]),
                            "findings_behind": sum(row["findings"] for row in problems),
                            "by_vector": {vector: sum(1 for row in problems
                                                      if row["vector"] == vector)
                                          for vector in ("dependency-cve", "credential",
                                                         "sast", "misconfig")},
                            "link": "vulnerabilities",
                            "filters": {"include_suppressed": False}},
        "recent_changes": {"last_7d": recent["total"],
                           "link": "attack-surface",
                           "filters": {"days": 7}},
        "exposures": {"open": open_exposures, "link": "exposures",
                      "filters": {"state": "open"}},
        "cycles": {"active": cycles_active, "in_review": cycles_review,
                   "link": "cycles", "filters": {"state": "active"}},
        "expiries": {"acceptances_next_30d": expiring, "link": "my-work",
                     "filters": {"kind": "acceptance", "window_days": 30}},
        "coverage": {
            "assets_without_owner": needs_owner,
            "assets_without_project": (session.query(models.Asset)
                                       .filter_by(org_id=org.id, project_id=None)
                                       .filter(models.Asset.archived_at.is_(None))
                                       .count()),
            "change_coverage_notes": len(recent["coverage_notes"]),
            "note": ("counters count what exists; a coverage gap means nothing was "
                     "observed or evaluated there, not that it is clean"),
        },
    }}

"""CTEM cycle overview: the five phases, each measured from real rows.

Continuous Threat Exposure Management is only useful if a phase can say whether
it is done. Each phase here reports the counts it is judged by, a status derived
from those counts, and the screen that acts on them — no phase is reported as
healthy because the table it needs is empty.
"""
import datetime

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from backend.app import auth, models
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1", tags=["ctem"])

from backend.app.status import NON_OPEN


def _phase(key, title, question, metrics, status, progress, links):
    # The English text stays for every non-UI client (CLI, MCP, tests); the
    # console renders from the keys, so a phase reads in the reader's language
    # without the API having to know which languages exist.
    return {"key": key, "title": title, "question": question,
            "title_key": f"ctem.phase.{key}.title",
            "question_key": f"ctem.phase.{key}.question",
            "metrics": metrics, "status": status, "progress": progress,
            "links": links}


def _status(done: bool, started: bool) -> tuple[str, int]:
    if done:
        return "done", 100
    if started:
        return "partial", 55
    return "empty", 0


def _metric(label, value, hint=None, key=None, hint_key=None, hint_params=None):
    return {"label": label, "value": value, "hint": hint,
            "label_key": f"ctem.metric.{key}" if key else None,
            "hint_key": hint_key, "hint_params": hint_params}


@router.get("/ctem/overview")
def ctem_overview(org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    now = models.utcnow()
    since = now - datetime.timedelta(days=30)

    projects = session.query(models.Project).filter_by(org_id=org.id).all()
    project_ids = {project.id for project in projects}
    versions = (session.query(models.ProjectVersion)
                .filter(models.ProjectVersion.project_id.in_(project_ids)).all()
                if project_ids else [])
    version_ids = {version.id for version in versions}
    projects_with_version = len({version.project_id for version in versions})

    assets = session.query(models.Asset).filter_by(org_id=org.id).all()
    scope_targets = session.query(models.ScopeTarget).filter_by(org_id=org.id).all()
    exclusions = session.query(models.ScopeExclusion).filter_by(org_id=org.id).all()

    components = session.query(models.Component).filter_by(org_id=org.id).count()
    imports = (session.query(models.SbomImport)
               .filter(models.SbomImport.project_version_id.in_(version_ids)).all()
               if version_ids else [])
    recent_imports = [row for row in imports if row.created_at and row.created_at >= since]

    findings = session.query(models.Finding).filter_by(org_id=org.id).all()
    open_findings = [row for row in findings if row.status not in NON_OPEN]
    # F3 (D29): only rows a human has triaged and that are not bare guesses count
    # toward the estate's posture. An agent's forty hypotheses are real work and stay
    # in the queue; they are not forty findings, and a rejected row cannot hide a
    # build that was never scanned because the build count is measured elsewhere.
    counted_findings = [row for row in open_findings
                        if row.triage_status in models.COUNTED_TRIAGE
                        and row.evidence_level != "hypothesis"]
    awaiting_triage = sum(1 for row in open_findings
                          if row.triage_status == "new")
    hypotheses = sum(1 for row in findings
                     if row.evidence_level == "hypothesis")
    ranked = [row for row in counted_findings if row.priority]
    kev_cves = {row.cve_id for row in session.query(models.KevEntry).all()}
    vulnerable_ids = {row.vulnerability_id for row in counted_findings
                      if row.vulnerability_id}
    advisory_cves = {}
    if vulnerable_ids:
        for advisory in (session.query(models.Vulnerability)
                         .filter(models.Vulnerability.id.in_(vulnerable_ids)).all()):
            advisory_cves[advisory.id] = advisory.cve_id
    kev_open = sum(1 for row in counted_findings
                   if advisory_cves.get(row.vulnerability_id) in kev_cves)

    past_sla = sum(1 for row in counted_findings
                   if row.sla_deadline is not None and row.sla_deadline < now)

    engagements = session.query(models.PentestEngagement).filter_by(org_id=org.id).all()
    regression_tests = session.query(models.RegressionTest).filter_by(org_id=org.id).all()
    pull_requests = session.query(models.PullRequest).filter_by(org_id=org.id).count()
    tickets = session.query(models.JiraLink).filter_by(org_id=org.id).count()
    resolved = [row for row in findings if row.status in {"resolved", "accepted_risk"}]

    # Scoping — do we know what is ours?
    scope_status, scope_progress = _status(
        bool(projects) and projects_with_version == len(projects) and bool(scope_targets),
        bool(projects) or bool(assets) or bool(scope_targets))
    scoping = _phase(
        "scoping", "Scoping", "Do we know what is ours?",
        [_metric("projects", len(projects),
                 f"{projects_with_version} with a scanned version",
                 key="projects", hint_key="ctem.hint.withScanned",
                 hint_params={"n": projects_with_version}),
         _metric("assets observed", len(assets), key="assetsObserved"),
         _metric("scope targets", len(scope_targets), f"{len(exclusions)} exclusions",
                 key="scopeTargets", hint_key="ctem.hint.exclusions",
                 hint_params={"n": len(exclusions)})],
        scope_status, scope_progress, [{"label": "Projects", "screen": "projects"},
                                       {"label": "Attack surface", "screen": "assets"}])

    # Discovery — do we know what it is made of?
    discovery_status, discovery_progress = _status(
        bool(components) and bool(recent_imports), bool(components))
    discovery = _phase(
        "discovery", "Discovery", "Do we know what it is made of?",
        [_metric("components", components, key="components"),
         _metric("imports 30d", len(recent_imports), f"{len(imports)} total",
                 key="imports30d", hint_key="ctem.hint.total",
                 hint_params={"n": len(imports)}),
         _metric("assets", len(assets), key="assets")],
        discovery_status, discovery_progress,
        [{"label": "Components", "screen": "components"},
         {"label": "Attack surface", "screen": "assets"}])

    # Prioritization — do we know what matters?
    # The denominator is `counted_findings`, not every open row: an agent's
    # hypotheses would otherwise make the estate look permanently un-prioritized.
    prioritization_status, prioritization_progress = _status(
        bool(ranked) and len(ranked) == len(counted_findings), bool(counted_findings))
    prioritization = _phase(
        "prioritization", "Prioritization", "Do we know what matters?",
        [_metric("open findings", len(counted_findings),
                 f"{len(open_findings)} open, {awaiting_triage} awaiting triage",
                 key="openFindings", hint_key="ctem.hint.openAwaiting",
                 hint_params={"open": len(open_findings), "awaiting": awaiting_triage}),
         _metric("ranked", len(ranked),
                 f"{len(counted_findings) - len(ranked)} without priority",
                 key="ranked", hint_key="ctem.hint.withoutPriority",
                 hint_params={"n": len(counted_findings) - len(ranked)}),
         _metric("known exploited", kev_open, key="knownExploited"),
         _metric("hypotheses", hypotheses, "not counted until triaged",
                 key="hypotheses", hint_key="ctem.hint.notCounted")],
        prioritization_status, prioritization_progress,
        [{"label": "Findings", "screen": "findings"},
         {"label": "Quality gates", "screen": "gates"}])

    # Validation — is the exposure real?
    validation_status, validation_progress = _status(
        bool(engagements), bool(engagements) or bool(regression_tests))
    validation = _phase(
        "validation", "Validation", "Is the exposure real?",
        [_metric("pentest engagements", len(engagements), key="pentests"),
         _metric("regression tests", len(regression_tests), key="regressionTests"),
         _metric("pull requests reviewed", pull_requests, key="pullRequests")],
        validation_status, validation_progress,
        [{"label": "Pentests", "screen": "pentest"},
         {"label": "Regression", "screen": "regression"},
         {"label": "Pull requests", "screen": "code"}])

    # Mobilization — is it being closed?
    mobilization_status, mobilization_progress = _status(
        bool(resolved) or bool(tickets), bool(open_findings) and (past_sla == 0))
    mobilization = _phase(
        "mobilization", "Mobilization", "Is it being closed?",
        [_metric("open", len(open_findings), f"{past_sla} past SLA",
                 key="open", hint_key="ctem.hint.pastSla",
                 hint_params={"n": past_sla}),
         _metric("resolved", len(resolved), key="resolved"),
         _metric("tickets", tickets, key="tickets")],
        mobilization_status, mobilization_progress,
        [{"label": "Remediation", "screen": "remediation"},
         {"label": "Jira", "screen": "jira"}])

    phases = [scoping, discovery, prioritization, validation, mobilization]
    return {"data": {"organization": {"name": org.name, "slug": org.slug},
                     "phases": phases,
                     "done": sum(1 for phase in phases if phase["status"] == "done"),
                     "generated_at": now.isoformat()}}

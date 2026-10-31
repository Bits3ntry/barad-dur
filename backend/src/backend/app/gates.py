"""BL-055: deterministic quality-gate evaluation.

Verdict rules are explicit and testable; every rule reports pass/fail with
the concrete offending rows. Policy precedence: project policy outranks org
policy; newest active policy wins within a scope.
"""
from backend.app import licenses, models

SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
NON_OPEN = {"resolved", "false_positive", "accepted_risk"}
POLICY_VERSION = 1


def policy_for(session, org_id: str, project_id: str | None = None):
    if project_id is not None:
        row = (session.query(models.GatePolicy)
               .filter_by(org_id=org_id, scope_type="project",
                          scope_id=project_id, status="active")
               .order_by(models.GatePolicy.created_at.desc()).first())
        if row is not None:
            return row
    return (session.query(models.GatePolicy)
            .filter_by(org_id=org_id, scope_type="org", status="active")
            .order_by(models.GatePolicy.created_at.desc()).first())


def _suppressed_ids(session, org_id: str) -> set[str]:
    rows = (session.query(models.FindingSuppression)
            .join(models.Finding, models.FindingSuppression.finding_id == models.Finding.id)
            .filter(models.Finding.org_id == org_id).all())
    return {row.finding_id for row in rows}


def evaluate(session, org_id: str, project, version=None) -> dict:
    policy = policy_for(session, org_id, project.id)
    threshold = (policy.max_severity if policy else "HIGH").upper()
    threshold_rank = SEVERITY_RANK.get(threshold, 3)

    query = (session.query(models.Finding)
             .filter_by(org_id=org_id, project_id=project.id))
    if version is not None:
        query = query.filter_by(last_seen_version_id=version.id)
    findings = query.all()

    suppressed = set() if policy and policy.include_suppressed else _suppressed_ids(session, org_id)
    open_findings = [f for f in findings
                     if f.status not in NON_OPEN and f.id not in suppressed]

    rules = []

    # Rule 1: severity threshold
    offenders = [f for f in open_findings
                 if SEVERITY_RANK.get((f.severity or "UNKNOWN").upper(), 0) >= threshold_rank]
    rules.append({
        "rule": "severity_threshold", "threshold": threshold,
        "status": "fail" if offenders else "pass",
        "detail": (f"{len(offenders)} open finding(s) at or above {threshold}"
                   if offenders else f"no open findings at or above {threshold}"),
        "findings": [{"id": f.id, "severity": f.severity, "title": f.title}
                     for f in offenders[:50]],
    })

    # Rule 2 (optional): KEV exposure
    if policy is not None and policy.block_kev:
        kev_hits = []
        for finding in open_findings:
            advisory = (session.get(models.Vulnerability, finding.vulnerability_id)
                        if finding.vulnerability_id else None)
            if advisory and advisory.cve_id and \
                    session.get(models.KevEntry, advisory.cve_id) is not None:
                kev_hits.append(finding)
        rules.append({
            "rule": "kev_exposure", "status": "fail" if kev_hits else "pass",
            "detail": (f"{len(kev_hits)} open finding(s) on the CISA KEV list"
                       if kev_hits else "no open finding is known-exploited"),
            "findings": [{"id": f.id, "title": f.title} for f in kev_hits[:50]],
        })

    # Rule 3 (optional): license denials for the evaluated version
    if policy is not None and policy.block_license_denied and version is not None:
        license_result = licenses.evaluate_project_version(
            session, org_id, project, version)
        denied = license_result["counts"]["denied"]
        rules.append({
            "rule": "license_compliance", "status": "fail" if denied else "pass",
            "detail": (f"{denied} denied license(s) in this version"
                       if denied else "no denied licenses in this version"),
            "findings": [{"component": row["component"], "license": row["license"]}
                         for row in license_result["results"]
                         if row["verdict"] == "denied"][:50],
        })

    failed = [rule for rule in rules if rule["status"] == "fail"]
    return {
        "verdict": "fail" if failed else "pass",
        "policy": ({"id": policy.id, "name": policy.name,
                    "scope": policy.scope_type,
                    "max_severity": threshold,
                    "block_kev": policy.block_kev,
                    "block_license_denied": policy.block_license_denied}
                   if policy else None),
        "policy_version": POLICY_VERSION,
        "project": project.slug,
        "version": version.version if version else None,
        "rules": rules,
        "reasons": [rule["detail"] for rule in failed],
    }

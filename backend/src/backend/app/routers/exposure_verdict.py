"""Exposure verdict: the interpretation of the chain, against one vulnerability.

`deployment.chain` says what we have. This endpoint says what that *means* for a
specific CVE, and the dependency runs one way only (D78): the verdict consumes the
chain, the chain never consumes a CVE.

Three stages (D80), and it can stop early honestly:

    match          deterministic — which builds hold an affected component
    applicability  deterministic rules — narrow or refute, never invent a match
    residual       an analyst over the code path and platform conditions (F2)

A verdict that stopped at `rules` says so in `depth` and names what would settle it
in `missing`. `unknown` is a complete answer: the whole point of D3 is that "no
finding" is not "not affected", and this endpoint is where that would otherwise
become a lie.
"""
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from backend.app import auth, models
from backend.app.db import get_session
from backend.app.routers import deployment_chain as chain_api

router = APIRouter(prefix="/api/v1", tags=["exposure-verdict"])

DEPTHS = ("match", "rules", "full")

# A finding in one of these states proves nothing about the estate any more.
REFUTING_STATUSES = {"resolved", "false_positive", "suppressed"}

# Environments where a deployment is someone's laptop or a rehearsal.
NON_PRODUCTION = {"dev", "development", "test", "testing", "qa", "local",
                  "sandbox", "pre", "preview", "staging"}

STALE_CHECK_DAYS = 30


def _finding_rows(session: Session, org_id: str, vuln_ids: list[str]):
    return (session.query(models.Finding)
            .filter_by(org_id=org_id)
            .filter(models.Finding.vulnerability_id.in_(vuln_ids or [""]))
            .all())


def _advisory(session: Session, ref: str):
    return (session.query(models.Vulnerability)
            .filter((models.Vulnerability.cve_id == ref)
                    | (models.Vulnerability.source_id == ref))
            .all())


def _chain_for(session: Session, org: models.Organization, component: models.Component):
    """One chain per component. The verdict never invents an edge of its own."""
    try:
        return chain_api.deployment_chain(
            purl=component.purl, component=None if component.purl else component.name,
            project=None, asset=None, org=org, session=session)
    except HTTPException:
        return None


def _applicability(finding: models.Finding, deployment: dict, ages: dict) -> dict:
    """Rules over chain edges. They narrow and refute; they never add a match."""
    reasons: list[str] = []
    state = "applicable"

    if deployment["status"] != "active":
        return {"state": "refuted",
                "reasons": [f"deployment is {deployment['status']}, "
                            "so nothing runs there"]}

    if deployment["matched_by"] == "label":
        state = "unknown"
        reasons.append("the version is declared on the deployment but no build "
                       "confirms it")

    if deployment["environment"].lower() in NON_PRODUCTION:
        reasons.append(f"environment {deployment['environment']} is not production")

    if deployment["exposure"] == "unknown":
        reasons.append("exposure is unknown (never observed)")
    elif deployment["exposure"] in {"public", "internet"}:
        reasons.append("interface is internet-facing")
    elif deployment["exposure"] in {"internal", "private"}:
        reasons.append("interface is internal only")

    if not deployment["requires_auth"]:
        reasons.append("deployment declares no authentication in front")

    check_age = ages.get("deployment_check")
    if check_age is None:
        reasons.append("deployment was never verified against a probe")
    elif check_age > STALE_CHECK_DAYS:
        reasons.append(f"deployment was last verified {check_age} days ago")

    return {"state": state, "reasons": reasons}


@router.get("/exposure/verdict")
def exposure_verdict(
    cve: str = Query(min_length=3, max_length=64),
    purl: str | None = Query(default=None, max_length=1024),
    depth: str = Query(default="rules"),
    org: models.Organization = Depends(auth.require_org),
    session: Session = Depends(get_session),
):
    """`affected | not_affected | unknown`, with the deployments that decided it."""
    if depth not in DEPTHS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"depth must be one of {list(DEPTHS)}")

    advisories = _advisory(session, cve)
    findings = _finding_rows(session, org.id, [row.id for row in advisories])
    if purl:
        components = (session.query(models.Component)
                      .filter_by(org_id=org.id)
                      .filter((models.Component.purl == purl)
                              | (models.Component.purl.like(purl + "@%")))
                      .all())
        allowed = {row.id for row in components}
        findings = [row for row in findings if row.component_id in allowed]

    if not advisories and not findings:
        return {
            "query": {"cve": cve, "purl": purl, "depth_requested": depth},
            "depth": "match",
            "verdict": "unknown",
            "deployments": [],
            "why": [f"no advisory or finding for {cve} in this organization"],
            "missing": [f"ingest an SBOM or run a scan that covers {cve}"],
            "freshness": {"as_of": None, "ages_days": {}},
            "stopped_because": "no_match",
        }

    rows: list[dict] = []
    missing: list[str] = []
    refuted = 0
    unknown_count = 0
    applicable = 0

    seen_components: set[str] = set()
    for finding in findings:
        component = (session.get(models.Component, finding.component_id)
                     if finding.component_id else None)
        if component is None or component.id in seen_components:
            continue
        seen_components.add(component.id)
        chain = _chain_for(session, org, component)
        if chain is None:
            missing.append(f"no build links {component.name or component.purl} "
                           "to a version")
            rows.append({"project": None, "component": component.name,
                         "purl": component.purl, "version": component.version,
                         "deployment": None, "environment": None,
                         "exposure": None, "state": "unknown",
                         "reasons": ["the component is not attached to any build"],
                         "matched_by": None, "freshness": {}})
            unknown_count += 1
            continue

        ages = chain["ages_days"]
        deployments = chain["edges"]["deployments"]
        if not deployments:
            rows.append({"project": (chain["edges"]["builds"][0]["project"]
                                     if chain["edges"]["builds"] else None),
                         "component": component.name, "purl": component.purl,
                         "version": component.version, "deployment": None,
                         "environment": None, "exposure": None,
                         "state": "not_deployed",
                         "reasons": ["the build contains it, no deployment runs "
                                     "that version"],
                         "matched_by": None, "freshness": ages})
            unknown_count += 1
            missing.append("a deployment row for this version, or confirmation "
                           "that it is not running anywhere")
            continue

        for deployment in deployments:
            if depth == "match":
                # The caller asked for matches only; the rules did not run.
                rows.append({**_row(component, deployment, ages),
                             "state": "not_evaluated",
                             "reasons": ["rules were not run"]})
                continue
            if finding.status in REFUTING_STATUSES:
                rows.append({**_row(component, deployment, ages),
                             "state": "refuted",
                             "reasons": [f"finding is {finding.status}"]})
                refuted += 1
                continue
            verdict = _applicability(finding, deployment, ages)
            state = verdict["state"]
            if state == "applicable":
                applicable += 1
            elif state == "refuted":
                refuted += 1
            elif state == "unknown":
                unknown_count += 1
            reasons = list(verdict["reasons"])
            if finding.status == "accepted_risk":
                reasons.append("the risk is accepted, so it is still present")
            rows.append({**_row(component, deployment, ages),
                         "state": state, "reasons": reasons})

    if depth == "match":
        overall = "unknown"
        stopped = "depth_match"
    elif applicable:
        overall = "affected"
        stopped = None
    elif unknown_count:
        overall = "unknown"
        stopped = "unknown_edges"
    else:
        overall = "not_affected"
        stopped = None

    if depth == "full":
        # The residual analyst is F2. Saying "rules" is the honest answer.
        stopped = "analyst_not_implemented"

    why = []
    if overall == "affected":
        why.append(f"{applicable} deployment(s) run an affected version")
    elif overall == "not_affected":
        why.append("every match was refuted by a rule")
    else:
        why.append("the evidence does not settle it")
    if refuted:
        why.append(f"{refuted} match(es) refuted")
    if unknown_count:
        why.append(f"{unknown_count} match(es) unknown")
    if not findings:
        why.append("no finding references this advisory in this organization")
        missing.append(f"a build analysed against {cve}")

    first = rows[0]["freshness"] if rows else {}
    return {
        "query": {"cve": cve, "purl": purl, "depth_requested": depth},
        "depth": "rules" if depth in ("rules", "full") else "match",
        "verdict": overall,
        "deployments": rows,
        "why": why,
        "missing": missing,
        "freshness": {"as_of": (rows[0]["freshness"] or {}).get("as_of")
                      if rows else None,
                      "ages_days": first},
        "stopped_because": stopped,
    }


def _row(component: models.Component, deployment: dict, ages: dict) -> dict:
    return {
        "project": deployment["project"],
        "component": component.name,
        "purl": component.purl,
        "version": component.version,
        "deployment": deployment["name"],
        "environment": deployment["environment"],
        "exposure": deployment["exposure"],
        "requires_auth": deployment["requires_auth"],
        "matched_by": deployment["matched_by"],
        "last_checked_at": deployment["last_checked_at"],
        "freshness": {"ages_days": ages,
                      "as_of": deployment["last_checked_at"]},
    }

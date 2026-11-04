"""BL-040b (part 1): SARIF 2.1.0 ingestion and version baseline diff.

SARIF findings land in the same findings pipeline (kind code-weakness) with
their rule/path/line identity, so the console, gates, suppressions and
occurrences work unchanged. The diff endpoint compares two versions and
labels absences honestly ("absent_from_current_scan", never "fixed").
"""
import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.versions import pick_version
from backend.app import auth, incidents, models
from backend.app.db import get_session

router = APIRouter(prefix="/api/v1", tags=["sarif"])

SEVERITY_BY_LEVEL = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW", "none": "LOW"}


def _severity_of(result: dict, rules_index: dict) -> str:
    """Prefer GitHub's security-severity numeric tag; fall back to the level."""
    rule_id = result.get("ruleId")
    rule = rules_index.get(rule_id) or {}
    security = ((rule.get("properties") or {}).get("security-severity")
                or (result.get("properties") or {}).get("security-severity"))
    try:
        value = float(security)
        if value >= 9.0:
            return "CRITICAL"
        if value >= 7.0:
            return "HIGH"
        if value >= 4.0:
            return "MEDIUM"
        return "LOW"
    except (TypeError, ValueError):
        return SEVERITY_BY_LEVEL.get((result.get("level") or "warning").lower(),
                                     "MEDIUM")


def _location(result: dict):
    locations = result.get("locations") or []
    if not locations:
        return None, None
    physical = ((locations[0] or {}).get("physicalLocation") or {})
    uri = ((physical.get("artifactLocation") or {}).get("uri"))
    line = ((physical.get("region") or {}).get("startLine"))
    return uri, line


class SarifIngestIn(BaseModel):
    run: dict = Field(description="one SARIF run object")
    actor: str | None = None


def ingest_run(session, org_id: str, proj, pv, run: dict, *,
               source: str = "api", tool_hint: str | None = None,
               actor: str | None = None, commit: bool = True,
               analysis_run_id: str | None = None) -> dict:
    """Ingest ONE SARIF run into the findings pipeline (idempotent by recipe).

    Extracted from the route so the scan-flow evidence sink uses the same code:
    two parsers for one format is how the same finding starts having two
    identities.
    """
    run = run or {}
    tool_name = tool_hint or (
        ((run.get("tool") or {}).get("driver") or {}).get("name") or "sarif")
    rules_index = {}
    for rule in ((run.get("tool") or {}).get("driver") or {}).get("rules") or []:
        if isinstance(rule, dict) and rule.get("id"):
            rules_index[rule["id"]] = rule

    counters = {"received": 0, "created": 0, "existing": 0, "skipped": 0}
    now = models.utcnow()
    for result in run.get("results") or []:
        if not isinstance(result, dict):
            counters["skipped"] += 1
            continue
        rule_id = result.get("ruleId")
        path, line = _location(result)
        if not rule_id or not path:
            counters["skipped"] += 1
            continue
        counters["received"] += 1
        severity = _severity_of(result, rules_index)
        message = ((result.get("message") or {}).get("text")
                   or (rules_index.get(rule_id, {}).get("shortDescription") or {}).get("text")
                   or rule_id)
        fingerprint = incidents.recipe_fingerprint(
            "code-weakness", org_id, proj.id, rule_id, path)
        finding = (session.query(models.Finding)
                   .filter_by(org_id=org_id, fingerprint=fingerprint).one_or_none())
        if finding is None:
            finding = models.Finding(
                org_id=org_id, project_id=proj.id, kind="code-weakness",
                fingerprint=fingerprint, source=source,
                title=message[:512], severity=severity, url=None,
                detail=f"SARIF {tool_name} {rule_id}", tool=tool_name,
                rule_id=rule_id, path=path, line=line,
                last_seen_version_id=pv.id,
                last_evaluated_run_id=analysis_run_id,
                first_seen_at=now, last_seen_at=now, updated_at=now)
            session.add(finding)
            session.flush()
            counters["created"] += 1
        else:
            finding.last_seen_at = now
            finding.last_seen_version_id = pv.id
            # A run that just ingested this finding is the run that evaluated it.
            # Without this the flow cannot answer "what did I produce".
            if analysis_run_id:
                finding.last_evaluated_run_id = analysis_run_id
            finding.severity = severity
            finding.line = line
            finding.updated_at = now
            counters["existing"] += 1
        incidents.record_occurrence(
            session, org_id, finding, pv.id, tool_name, source,
            kind="code-weakness", rule_id=rule_id, path=path, line=line,
            detail=(result.get("message") or {}).get("text"), now=now)
    if commit:
        session.commit()
    return {"status": "ingested", "tool": tool_name, "counts": counters}


@router.post("/sarif")
def ingest_sarif(payload: SarifIngestIn = None,
                 project: str = Query(...),
                 version: str = Query(...),
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """Ingest one SARIF run into the findings pipeline (idempotent by recipe)."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    proj = (session.query(models.Project)
            .filter_by(org_id=org.id, slug=project).one_or_none())
    if proj is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    pv = (pick_version(session, proj.id, version))
    if pv is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")
    return ingest_run(session, org.id, proj, pv, payload.run or {},
                      source="api", actor=payload.actor)


@router.get("/sarif/diff")
def diff_versions(project: str = Query(...), version: str = Query(...),
                  baseline: str = Query(...),
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    """New-vs-baseline comparison by finding identity.

    `absent_from_current_scan` is NOT a fixed claim: absence can mean fixed,
    moved, excluded or simply not re-observed by this run.
    """
    proj = (session.query(models.Project)
            .filter_by(org_id=org.id, slug=project).one_or_none())
    if proj is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    versions = {}
    for name in (version, baseline):
        row = (pick_version(session, proj.id, name))
        if row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND,
                                f"version {name} not found")
        versions[name] = row

    def _rows(version_row):
        """Findings seen in that version, via occurrence history (the
        last_seen pointer mutates; occurrences are the stable record)."""
        return (session.query(models.Finding)
                .join(models.Occurrence,
                      models.Occurrence.finding_id == models.Finding.id)
                .filter(models.Finding.org_id == org.id,
                        models.Finding.project_id == proj.id,
                        models.Occurrence.project_version_id == version_row.id)
                .distinct().all())

    current = {f.fingerprint: f for f in _rows(versions[version])}
    base = {f.fingerprint: f for f in _rows(versions[baseline])}
    new = [current[key] for key in current.keys() - base.keys()]
    absent = [base[key] for key in base.keys() - current.keys()]
    common = [current[key] for key in current.keys() & base.keys()]

    def row_data(f):
        return {"id": f.id, "rule_id": f.rule_id, "path": f.path, "line": f.line,
                "severity": f.severity, "title": f.title, "status": f.status}

    return {"data": {
        "project": proj.slug, "version": version, "baseline": baseline,
        "new": [row_data(f) for f in new],
        "absent_from_current_scan": [row_data(f) for f in absent],
        "common": len(common),
        "note": "absence from the current scan is informational; it does not "
                "assert remediation",
    }}

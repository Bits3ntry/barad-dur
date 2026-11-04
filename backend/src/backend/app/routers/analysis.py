"""Analysis runs: what a tool actually looked at, and what that entitles it to close.

A run is recorded on import or CI receipt. Closing findings is an explicit step
with a preview, because "absent from a scan" only means "fixed" when the scan
covered the whole target.
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app.versions import pick_version
from backend.app import analysis, auth, models, projects as projects_ref
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log

router = APIRouter(prefix="/api/v1/analysis", tags=["analysis"])

COVERAGES = models.ANALYSIS_COVERAGES
SOURCES = {"import", "ci", "api", "cli"}


class RunIn(BaseModel):
    project: str = Field(min_length=1, max_length=128)
    version: str | None = Field(default=None, max_length=255)
    tool: str = Field(min_length=1, max_length=64)
    tool_version: str | None = Field(default=None, max_length=64)
    coverage: str = "unknown"
    source: str = "import"
    revision: str | None = Field(default=None, max_length=128)
    branch: str | None = Field(default=None, max_length=255)
    repository_id: str | None = Field(default=None, max_length=36)
    pull_request: str | None = Field(default=None, max_length=64)
    base_revision: str | None = Field(default=None, max_length=128)
    evaluated: dict = Field(default_factory=dict)
    receipt: dict = Field(default_factory=dict)
    findings_seen: int = Field(default=0, ge=0)
    started_at: str | None = None
    finished_at: str | None = None
    actor: str = Field(default="system", max_length=255)


class ClosureIn(BaseModel):
    actor: str = Field(default="system", max_length=255)
    dry_run: bool = True


def _parse_ts(value: str | None, name: str) -> datetime | None:
    if value in (None, ""):
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"{name} must be ISO-8601") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _repository_data(session: Session, repository_id: str | None) -> dict | None:
    if not repository_id:
        return None
    row = session.get(models.Repository, repository_id)
    if row is None:
        return None
    return {"id": row.id, "name": row.name, "provider": row.provider,
            "remote_url": row.remote_url}


def _resolve_repository(session: Session, org_id: str, ref: str | None) -> str | None:
    """Accept a repository id or its remote URL; anything else is a 404."""
    if not ref:
        return None
    row = session.get(models.Repository, ref)
    if row is None:
        row = (session.query(models.Repository)
               .filter_by(org_id=org_id, remote_url=ref).one_or_none())
    if row is None or row.org_id != org_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "repository not found in this organization")
    return row.id


def _data(session: Session, run: models.AnalysisRun) -> dict:
    project = session.get(models.Project, run.project_id)
    version = (session.get(models.ProjectVersion, run.project_version_id)
               if run.project_version_id else None)
    return {
        "id": run.id, "project": project.slug if project else None,
        "version": version.version if version else None,
        "tool": run.tool, "tool_version": run.tool_version,
        "coverage": run.coverage, "closure_eligible": run.coverage in analysis.CLOSABLE_COVERAGES,
        "source": run.source, "revision": run.revision, "branch": run.branch,
        "repository": _repository_data(session, run.repository_id),
        "pull_request": run.pull_request,
        "base_revision": run.base_revision,
        "evaluated": run.evaluated or {}, "receipt": run.receipt or {},
        "base_run_id": run.base_run_id, "report_format": run.report_format,
        "uninterpreted": run.uninterpreted or {},
        "findings_seen": run.findings_seen, "actor": run.actor,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "created_at": run.created_at.isoformat(),
    }


@router.get("/runs")
def list_runs(project: str | None = Query(default=None),
              version: str | None = Query(default=None),
              coverage: str | None = Query(default=None),
              limit: int = Query(default=50, ge=1, le=200),
              offset: int = Query(default=0, ge=0),
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    query = session.query(models.AnalysisRun).filter_by(org_id=org.id)
    if project:
        project_row = projects_ref.by_ref(session, org.id, project)
        if project_row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
        query = query.filter(models.AnalysisRun.project_id == project_row.id)
    if coverage:
        query = query.filter(models.AnalysisRun.coverage == coverage)
    total = query.count()
    rows = (query.order_by(models.AnalysisRun.created_at.desc())
            .offset(offset).limit(limit).all())
    data = [_data(session, row) for row in rows]
    if version:
        data = [row for row in data if row["version"] == version]
    return {"data": data, "total": total, "limit": limit, "offset": offset}


@router.post("/runs", status_code=status.HTTP_201_CREATED)
def record_run(payload: RunIn = None,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """Record what a tool evaluated. Recording never changes a finding."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.coverage not in COVERAGES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"coverage must be one of {sorted(COVERAGES)}")
    if payload.source not in SOURCES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"source must be one of {sorted(SOURCES)}")
    project_row = projects_ref.by_ref(session, org.id, payload.project)
    if project_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    repository_id = _resolve_repository(session, org.id, payload.repository_id)
    version_row = None
    if payload.version:
        version_row = (pick_version(session, project_row.id, payload.version))
        if version_row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")
    run = models.AnalysisRun(
        org_id=org.id, project_id=project_row.id,
        project_version_id=version_row.id if version_row else None,
        tool=payload.tool, tool_version=payload.tool_version,
        coverage=payload.coverage, source=payload.source,
        revision=payload.revision, branch=payload.branch,
        repository_id=repository_id, pull_request=payload.pull_request,
        base_revision=payload.base_revision,
        evaluated=payload.evaluated or {}, receipt=payload.receipt or {},
        findings_seen=payload.findings_seen, actor=payload.actor,
        started_at=_parse_ts(payload.started_at, "started_at"),
        finished_at=_parse_ts(payload.finished_at, "finished_at"))
    session.add(run)
    session.flush()
    _audit_log(session, org.id, payload.actor, "analysis.run_recorded",
               "analysis_run", run.id,
               f"{payload.tool} {payload.coverage} on {project_row.slug}"
               + (f"@{payload.version}" if payload.version else ""))
    session.commit()
    return {"data": _data(session, run)}


@router.get("/runs/{run_id}")
def get_run(run_id: str,
            org: models.Organization = Depends(auth.require_org),
            session: Session = Depends(get_session)):
    run = session.get(models.AnalysisRun, run_id)
    if run is None or run.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "analysis run not found")
    plan = analysis.plan_closure(session, run)
    return {"data": {**_data(session, run),
                     "closure": {"eligible": plan["eligible"],
                                 "reason": plan["reason"],
                                 "counts": plan["counts"]}}}


@router.post("/runs/{run_id}/close-unseen")
def close_unseen(run_id: str, payload: ClosureIn = None,
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    """Preview (default) or apply closure. Diff/partial runs answer 409."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    run = session.get(models.AnalysisRun, run_id)
    if run is None or run.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "analysis run not found")
    if payload.dry_run:
        plan = analysis.plan_closure(session, run)
        if not plan["eligible"]:
            raise HTTPException(status.HTTP_409_CONFLICT, plan["reason"])
        return {"data": {"dry_run": True, **plan}}
    plan = analysis.apply_closure(session, run, payload.actor)
    if not plan["eligible"]:
        session.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, plan["reason"])
    session.commit()
    return {"data": {"dry_run": False, **plan}}


# ─────────────── report intake + viewer ───────────────

import hashlib  # noqa: E402

from backend.app import incidents, sast  # noqa: E402


class FileIn(BaseModel):
    path: str = Field(min_length=1, max_length=1024)
    content: str | None = Field(default=None, max_length=sast.MAX_FILE_CHARS)
    kind: str = "analyzed"


class ImportIn(BaseModel):
    project: str = Field(min_length=1, max_length=128)
    version: str | None = Field(default=None, max_length=255)
    format: str = Field(default="sarif", description="sarif | opengrep")
    report: dict
    files: list[FileIn] = Field(default_factory=list, max_length=sast.MAX_FILES)
    diff: str | None = Field(default=None, max_length=4_000_000)
    coverage: str = "full"
    tool: str | None = Field(default=None, max_length=64)
    tool_version: str | None = Field(default=None, max_length=64)
    revision: str | None = Field(default=None, max_length=128)
    branch: str | None = Field(default=None, max_length=255)
    repository_id: str | None = Field(default=None, max_length=36)
    pull_request: str | None = Field(default=None, max_length=64)
    base_revision: str | None = Field(default=None, max_length=128)
    base_run_id: str | None = Field(default=None, max_length=36)
    source: str = "import"
    actor: str = Field(default="system", max_length=255)


def _af_data(row: models.AnalysisFinding, session: Session) -> dict:
    finding = session.get(models.Finding, row.finding_id)
    return {"id": row.id, "finding_id": row.finding_id, "path": row.path,
            "line": row.line, "end_line": row.end_line, "rule_id": row.rule_id,
            "severity": row.severity, "cwe": row.cwe, "message": row.message,
            "snippet": row.snippet, "classification": row.classification,
            "on_modified_line": bool(row.on_modified_line),
            "introduced_by_pr": bool(row.introduced_by_pr),
            "source_sink": row.source_sink or {},
            "finding_status": finding.status if finding else None}


@router.post("/import", status_code=status.HTTP_201_CREATED)
def import_report(payload: ImportIn = None,
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    """Import one analysis: report + optional code snapshots + optional diff.

    Findings land in the normal findings pipeline (same fingerprint recipe as the
    SARIF route), so identity is preserved across imports and screens. The run
    keeps the report format, the rules, what could not be interpreted and the
    diff text; classification is `no_reference` unless a comparable base run is
    supplied.
    """
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.coverage not in COVERAGES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"coverage must be one of {sorted(COVERAGES)}")
    try:
        parsed = sast.parse_report(payload.format, payload.report or {})
    except ValueError as error:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(error)) from None
    project_row = projects_ref.by_ref(session, org.id, payload.project)
    if project_row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
    version_row = None
    if payload.version:
        version_row = (pick_version(session, project_row.id, payload.version))
        if version_row is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project version not found")

    tool = payload.tool or parsed["tool"]
    base = None
    if payload.base_run_id:
        base = session.get(models.AnalysisRun, payload.base_run_id)
        if base is None or base.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "base run not found")
        if base.tool.lower() != tool.lower():
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                f"base run used {base.tool}; comparing across tools would invent findings")
        if base.project_version_id != (version_row.id if version_row else None):
            raise HTTPException(status.HTTP_409_CONFLICT,
                                "base run belongs to another project version")

    base_keys: dict[tuple, models.AnalysisFinding] = {}
    comparable = base is not None and base.coverage in analysis.CLOSABLE_COVERAGES
    if comparable:
        for row in (session.query(models.AnalysisFinding)
                    .filter_by(run_id=base.id).all()):
            base_keys[(row.rule_id, row.path)] = row

    repository_id = _resolve_repository(session, org.id, payload.repository_id)
    diff = sast.parse_diff(payload.diff) if payload.diff else {"files": {}}
    run = models.AnalysisRun(
        org_id=org.id, project_id=project_row.id,
        project_version_id=version_row.id if version_row else None,
        tool=tool, tool_version=payload.tool_version or parsed["tool_version"],
        coverage=payload.coverage, source=payload.source,
        revision=payload.revision, branch=payload.branch,
        repository_id=repository_id, pull_request=payload.pull_request,
        base_revision=payload.base_revision,
        base_run_id=base.id if base else None,
        report_format=parsed["format"], rules=parsed["rules"],
        uninterpreted={"results": parsed["uninterpreted"][:200],
                       "count": len(parsed["uninterpreted"])},
        diff_text=payload.diff,
        evaluated={"paths": sorted({item["path"] for item in parsed["results"]})},
        findings_seen=len(parsed["results"]), actor=payload.actor)
    session.add(run)
    session.flush()

    seen_paths = set()
    for item in payload.files:
        if item.path in seen_paths or len(seen_paths) >= sast.MAX_FILES:
            continue
        seen_paths.add(item.path)
        content = item.content
        session.add(models.AnalysisFile(
            org_id=org.id, run_id=run.id, path=item.path, content=content,
            content_hash=(hashlib.sha256(content.encode()).hexdigest() if content else None),
            line_count=(content.count("\n") + 1 if content else 0),
            kind=item.kind if item.kind in {"analyzed", "context"} else "analyzed"))

    now = models.utcnow()
    counters = {"results": 0, "created": 0, "existing": 0, "skipped": 0,
                "new": 0, "persistent": 0, "resolved": 0, "no_reference": 0,
                "on_modified_line": 0}
    current_keys = set()
    for item in parsed["results"]:
        counters["results"] += 1
        key = (item["rule_id"], item["path"])
        current_keys.add(key)
        finding = (session.query(models.Finding)
                   .filter_by(org_id=org.id,
                              fingerprint=incidents.recipe_fingerprint(
                                  "code-weakness", org.id, project_row.id,
                                  item["rule_id"], item["path"])).one_or_none())
        if finding is None:
            finding = models.Finding(
                org_id=org.id, project_id=project_row.id, kind="code-weakness",
                fingerprint=incidents.recipe_fingerprint(
                    "code-weakness", org.id, project_row.id,
                    item["rule_id"], item["path"]),
                source="api", title=(item["message"] or item["rule_id"])[:512],
                severity=item["severity"], detail=f"{tool} {item['rule_id']}",
                tool=tool, rule_id=item["rule_id"], path=item["path"],
                line=item.get("line"), cwe=item.get("cwe"),
                last_seen_version_id=version_row.id if version_row else None,
                first_seen_at=now, last_seen_at=now, updated_at=now)
            session.add(finding)
            session.flush()
            counters["created"] += 1
        else:
            finding.last_seen_at = now
            finding.severity = item["severity"]
            finding.line = item.get("line")
            finding.cwe = item.get("cwe") or finding.cwe
            if version_row is not None:
                finding.last_seen_version_id = version_row.id
            counters["existing"] += 1
        if version_row is not None:
            incidents.record_occurrence(
                session, org.id, finding, version_row.id, tool, "api",
                kind="code-weakness", rule_id=item["rule_id"], path=item["path"],
                line=item.get("line"), detail=item.get("message"), now=now)
        if comparable:
            classification = "persistent" if key in base_keys else "new"
        else:
            classification = "no_reference"
        on_modified = bool(item.get("line")) and any(
            item["path"] == path and item["line"] in info["added"]
            for path, info in diff["files"].items())
        session.add(models.AnalysisFinding(
            org_id=org.id, run_id=run.id, finding_id=finding.id,
            path=item["path"], line=item.get("line"), end_line=item.get("end_line"),
            rule_id=item["rule_id"], severity=item["severity"], cwe=item.get("cwe"),
            message=item.get("message"), snippet=item.get("snippet"),
            classification=classification, on_modified_line=on_modified,
            introduced_by_pr=bool(comparable and classification == "new" and on_modified),
            source_sink=item.get("source_sink") or {}))
        # "Last evaluated by" is what lets a reviewer jump from the finding back
        # to this run; it is stamped even when the finding already existed.
        finding.last_evaluated_run_id = run.id
        counters[classification] += 1
        if on_modified:
            counters["on_modified_line"] += 1

    if comparable:
        for key, base_row in base_keys.items():
            if key in current_keys or base_row.classification == "resolved":
                continue
            # Absent from a full run of the same tool/version: "resolved" is a
            # claim about coverage, so it needs both runs to be full.
            session.add(models.AnalysisFinding(
                org_id=org.id, run_id=run.id, finding_id=base_row.finding_id,
                path=base_row.path, line=base_row.line, end_line=base_row.end_line,
                rule_id=base_row.rule_id, severity=base_row.severity,
                cwe=base_row.cwe, message=base_row.message,
                snippet=base_row.snippet, classification="resolved",
                on_modified_line=False, introduced_by_pr=False,
                source_sink=base_row.source_sink or {}))
            counters["resolved"] += 1

    _audit_log(session, org.id, payload.actor, "analysis.imported", "analysis_run",
               run.id, f"{tool} {payload.format} {payload.coverage}: "
                       f"{counters['created']} new findings, "
                       f"{counters['new']} new in diff terms")
    session.commit()
    return {"data": {**_data(session, run),
                     "counters": counters,
                     "baseline": ("comparable" if comparable else
                                  "no reference: nothing is classified new or resolved"),
                     "uninterpreted": run.uninterpreted}}


@router.get("/runs/{run_id}/files")
def run_files(run_id: str,
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    run = session.get(models.AnalysisRun, run_id)
    if run is None or run.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "analysis run not found")
    counts: dict[str, int] = {}
    for row in (session.query(models.AnalysisFinding).filter_by(run_id=run.id).all()):
        counts[row.path] = counts.get(row.path, 0) + 1
    files = (session.query(models.AnalysisFile).filter_by(run_id=run.id)
             .order_by(models.AnalysisFile.path).all())
    data = [{"path": row.path, "kind": row.kind, "line_count": row.line_count,
             "available": row.content is not None,
             "findings": counts.get(row.path, 0)} for row in files]
    known = {row["path"] for row in data}
    for path, count in sorted(counts.items()):
        if path not in known:
            data.append({"path": path, "kind": "reported-only", "line_count": 0,
                         "available": False, "findings": count})
    return {"data": data, "total": len(data),
            "content_available": any(row["available"] for row in data)}


@router.get("/runs/{run_id}/file")
def run_file(run_id: str, path: str = Query(...),
             org: models.Organization = Depends(auth.require_org),
             session: Session = Depends(get_session)):
    run = session.get(models.AnalysisRun, run_id)
    if run is None or run.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "analysis run not found")
    row = (session.query(models.AnalysisFile)
           .filter_by(run_id=run.id, path=path).one_or_none())
    findings = [_af_data(item, session) for item in
                session.query(models.AnalysisFinding)
                .filter_by(run_id=run.id, path=path)
                .order_by(models.AnalysisFinding.line).all()]
    return {"data": {"path": path,
                     "content": row.content if row else None,
                     "available": bool(row and row.content is not None),
                     "line_count": row.line_count if row else 0,
                     "reason": None if row and row.content is not None else
                               "the report referenced this file but no code snapshot "
                               "was supplied for it",
                     "findings": findings}}


@router.get("/runs/{run_id}/diff")
def run_diff(run_id: str,
             org: models.Organization = Depends(auth.require_org),
             session: Session = Depends(get_session)):
    run = session.get(models.AnalysisRun, run_id)
    if run is None or run.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "analysis run not found")
    parsed = sast.parse_diff(run.diff_text or "")
    findings = (session.query(models.AnalysisFinding).filter_by(run_id=run.id).all())
    positions: dict[str, list] = {}
    for row in findings:
        positions.setdefault(row.path, []).append(_af_data(row, session))
    files = []
    for path, info in parsed["files"].items():
        files.append({"path": path,
                      "added": sorted(info["added"]),
                      "removed": sorted(info["removed"]),
                      "hunks": info["hunks"],
                      "findings": positions.get(path, [])})
    return {"data": {"available": bool(run.diff_text),
                     "reason": None if run.diff_text else
                               "no diff was supplied for this analysis",
                     "touched_lines": {"added": parsed["added_total"],
                                       "removed": parsed["removed_total"]},
                     "files": files, "total": len(files),
                     "note": ("a finding on a modified line is not thereby "
                              "introduced by the change")}}


@router.get("/runs/{run_id}/findings")
def run_findings(run_id: str,
                 classification: str | None = Query(default=None),
                 org: models.Organization = Depends(auth.require_org),
                 session: Session = Depends(get_session)):
    run = session.get(models.AnalysisRun, run_id)
    if run is None or run.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "analysis run not found")
    query = session.query(models.AnalysisFinding).filter_by(run_id=run.id)
    if classification:
        query = query.filter(models.AnalysisFinding.classification == classification)
    rows = query.order_by(models.AnalysisFinding.path,
                          models.AnalysisFinding.line).all()
    counts: dict[str, int] = {}
    for row in session.query(models.AnalysisFinding).filter_by(run_id=run.id).all():
        counts[row.classification] = counts.get(row.classification, 0) + 1
    return {"data": [_af_data(row, session) for row in rows],
            "total": len(rows), "counts": counts}

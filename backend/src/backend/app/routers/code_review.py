"""BL-040b part 2: code review — source snapshots, PR classification, context.

Design decisions:
  - Source is PUSHED by CI per ref; the platform never reaches into a
    repository on its own (authorization stays with the CI identity).
  - Every served line passes through shared redaction, and the viewer refuses
    content that looks like a secret dump line-for-line instead of trusting
    the scanner.
  - PR classification is honest: `new` means the fingerprint did not exist in
    this org before this PR scan; `existing` means it did. Nothing is called
    "fixed" from absence — that stays `absent_from_current_scan` in the diff
    endpoint.
"""
import hashlib
import json

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from backend.app import auth, gates, incidents, models, redaction
from backend.app.db import get_session
from backend.app.routers.identity import _audit as _audit_log
from backend.app.routers.sarif import _location, _severity_of

router = APIRouter(prefix="/api/v1/code", tags=["code-review"])

MAX_FILE_BYTES = 400_000
CONTEXT_RADIUS = 5


def _file_data(row: models.CodeFile, include_content: bool = False) -> dict:
    data = {"id": row.id, "repository_id": row.repository_id, "ref": row.ref,
            "path": row.path, "content_hash": row.content_hash,
            "bytes": len(row.content or ""),
            "created_at": row.created_at.isoformat()}
    if include_content:
        data["content"] = redaction.redact_text(row.content)
        data["lines"] = len((row.content or "").splitlines())
    return data


def _latest_file(session, org_id: str, repository_id: str | None,
                 path: str, ref: str | None = None):
    query = (session.query(models.CodeFile)
             .filter_by(org_id=org_id, path=path))
    if repository_id:
        query = query.filter_by(repository_id=repository_id)
    if ref:
        query = query.filter_by(ref=ref)
    return query.order_by(models.CodeFile.created_at.desc()).first()


class FileIn(BaseModel):
    repository_id: str
    ref: str = Field(min_length=1, max_length=128)
    path: str = Field(min_length=1, max_length=1024)
    content: str
    actor: str = Field(min_length=2, max_length=255)


@router.post("/files")
def push_file(payload: FileIn = None,
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    repo = session.get(models.Repository, payload.repository_id)
    if repo is None or repo.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "repository not found")
    raw = payload.content.encode()
    if len(raw) > MAX_FILE_BYTES:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            f"file exceeds {MAX_FILE_BYTES} bytes")
    if b"\x00" in raw:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "binary content is not accepted")
    digest = hashlib.sha256(raw).hexdigest()
    existing = (session.query(models.CodeFile)
                .filter_by(org_id=org.id, repository_id=repo.id,
                           ref=payload.ref, path=payload.path,
                           content_hash=digest).one_or_none())
    if existing is not None:
        return {"data": _file_data(existing), "created": False}
    row = models.CodeFile(
        org_id=org.id, repository_id=repo.id, ref=payload.ref,
        path=payload.path, content=payload.content, content_hash=digest,
        created_at=models.utcnow())
    session.add(row)
    session.flush()
    _audit_log(session, org.id, payload.actor, "code.file_pushed",
               "code_file", row.id, payload.path[:200])
    session.commit()
    return {"data": _file_data(row), "created": True}


@router.get("/files")
def list_files(repository_id: str = Query(...), ref: str | None = None,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    query = (session.query(models.CodeFile)
             .filter_by(org_id=org.id, repository_id=repository_id))
    if ref:
        query = query.filter_by(ref=ref)
    latest = {}
    for row in query.order_by(models.CodeFile.created_at).all():
        ref_key = row.ref if not ref else ""
        current = latest.get((ref_key, row.path))
        if current is None or row.created_at >= current.created_at:
            latest[(ref_key, row.path)] = row
    rows = sorted(latest.values(), key=lambda r: r.path)
    return {"data": [_file_data(r) for r in rows], "total": len(rows)}


@router.get("/file")
def read_file(repository_id: str = Query(...), path: str = Query(...),
              ref: str | None = None,
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    row = _latest_file(session, org.id, repository_id, path, ref)
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "file not in the index")
    return {"data": _file_data(row, include_content=True)}


@router.get("/findings/{finding_id}/context")
def finding_context(finding_id: str, radius: int = Query(default=CONTEXT_RADIUS, ge=0, le=50),
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    """Lines around a finding's location, redacted, from the latest snapshot."""
    finding = session.get(models.Finding, finding_id)
    if finding is None or finding.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    if not finding.path:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "finding has no source location")
    repo_ids = [link.repository_id for link in
                (session.query(models.ProjectRepository)
                 .filter_by(project_id=finding.project_id).all())] \
        if hasattr(models, "ProjectRepository") else []
    row = None
    for repo_id in repo_ids or [None]:
        row = _latest_file(session, org.id, repo_id, finding.path)
        if row is not None:
            break
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND,
                            "no code snapshot indexed for that path")
    lines = (row.content or "").splitlines()
    target = (finding.line or 1) - 1
    start = max(0, target - radius)
    end = min(len(lines), target + radius + 1)
    numbered = [{"number": index + 1,
                 "text": redaction.redact_text(lines[index])}
                for index in range(start, end)]
    return {"data": {"finding_id": finding.id, "path": finding.path,
                     "ref": row.ref, "content_hash": row.content_hash,
                     "line": finding.line, "radius": radius,
                     "lines": numbered,
                     "truncated": len(lines) > (end - start)}}


class PullRequestIn(BaseModel):
    repository_id: str | None = None
    number: int = Field(ge=1)
    title: str | None = None
    branch: str | None = None
    base_branch: str | None = None
    head_sha: str | None = None
    project: str | None = None
    version: str | None = None
    actor: str = Field(min_length=2, max_length=255)


def _pr_data(session, row: models.PullRequest) -> dict:
    links = (session.query(models.PrFinding).filter_by(pr_id=row.id).all())
    counts = {}
    for link in links:
        counts[link.classification] = counts.get(link.classification, 0) + 1
    return {"id": row.id, "number": row.number, "title": row.title,
            "branch": row.branch, "base_branch": row.base_branch,
            "head_sha": row.head_sha, "status": row.status,
            "gate_verdict": row.gate_verdict, "gate_reason": row.gate_reason,
            "comment": row.comment, "counts": counts,
            "repository_id": row.repository_id,
            "created_at": row.created_at.isoformat()}


@router.post("/pull-requests")
def create_pull_request(payload: PullRequestIn = None,
                        org: models.Organization = Depends(auth.require_org),
                        session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    project_id = pv_id = None
    if payload.project:
        project = (session.query(models.Project)
                   .filter_by(org_id=org.id, slug=payload.project).one_or_none())
        if project is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "project not found")
        project_id = project.id
        if payload.version:
            pv = (session.query(models.ProjectVersion)
                  .filter_by(project_id=project.id, version=payload.version)
                  .one_or_none())
            if pv is None:
                raise HTTPException(status.HTTP_404_NOT_FOUND, "version not found")
            pv_id = pv.id
    if payload.repository_id:
        repo = session.get(models.Repository, payload.repository_id)
        if repo is None or repo.org_id != org.id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "repository not found")
    existing = (session.query(models.PullRequest)
                .filter_by(org_id=org.id, repository_id=payload.repository_id,
                           number=payload.number).one_or_none())
    if existing is not None:
        for field in ("title", "branch", "base_branch", "head_sha"):
            value = getattr(payload, field)
            if value:
                setattr(existing, field, value)
        existing.updated_at = models.utcnow()
        session.commit()
        return {"data": _pr_data(session, existing), "created": False}
    now = models.utcnow()
    row = models.PullRequest(
        org_id=org.id, project_id=project_id, project_version_id=pv_id,
        repository_id=payload.repository_id, number=payload.number,
        title=payload.title, branch=payload.branch,
        base_branch=payload.base_branch, head_sha=payload.head_sha,
        status="open", created_at=now, updated_at=now)
    session.add(row)
    session.flush()
    _audit_log(session, org.id, payload.actor, "code.pr_registered",
               "pull_request", row.id, f"#{payload.number}")
    session.commit()
    return {"data": _pr_data(session, row), "created": True}


@router.get("/pull-requests")
def list_pull_requests(org: models.Organization = Depends(auth.require_org),
                       session: Session = Depends(get_session)):
    rows = (session.query(models.PullRequest).filter_by(org_id=org.id)
            .order_by(models.PullRequest.created_at.desc()).all())
    return {"data": [_pr_data(session, r) for r in rows], "total": len(rows)}


class PrSarifIn(BaseModel):
    run: dict
    actor: str = Field(min_length=2, max_length=255)


def _render_comment(pr: models.PullRequest, items: list[dict]) -> str:
    lines = [f"## Barad-dûr security review — PR #{pr.number}"]
    lines.append("")
    if pr.gate_verdict:
        lines.append(f"**Quality gate:** {pr.gate_verdict.upper()} — {pr.gate_reason or ''}".strip())
        lines.append("")
    if not items:
        lines.append("No security findings were reported for this change.")
        return "\n".join(lines)
    new_items = [i for i in items if i["classification"] == "new"]
    lines.append(f"{len(new_items)} new · {len(items) - len(new_items)} pre-existing")
    lines.append("")
    for item in items:
        marker = "NEW" if item["classification"] == "new" else "existing"
        lines.append(f"- **{item['severity']}** `{item['rule_id']}` at "
                     f"`{item['path']}:{item['line']}` ({marker}) — {item['title']}")
    lines.append("")
    lines.append("A finding missing from this scan is reported as "
                 "`absent_from_current_scan`, never as fixed.")
    return "\n".join(lines)


@router.post("/pull-requests/{pr_id}/sarif")
def ingest_pr_sarif(pr_id: str, payload: PrSarifIn = None,
                    org: models.Organization = Depends(auth.require_org),
                    session: Session = Depends(get_session)):
    """Ingest one SARIF run for the PR, classify findings, evaluate the gate."""
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    pr = session.get(models.PullRequest, pr_id)
    if pr is None or pr.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "pull request not found")
    if pr.project_id is None:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "pull request has no project scope")
    project = session.get(models.Project, pr.project_id)
    run = payload.run or {}
    tool_name = (((run.get("tool") or {}).get("driver") or {}).get("name")
                 or "sarif")
    rules_index = {}
    for rule in ((run.get("tool") or {}).get("driver") or {}).get("rules") or []:
        if isinstance(rule, dict) and rule.get("id"):
            rules_index[rule["id"]] = rule
    now = models.utcnow()
    counters = {"received": 0, "new": 0, "existing": 0, "skipped": 0}
    items = []
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
        fingerprint = incidents.recipe_fingerprint(
            "code-weakness", org.id, project.id, rule_id, path)
        finding = (session.query(models.Finding)
                   .filter_by(org_id=org.id, fingerprint=fingerprint).one_or_none())
        is_new = finding is None
        if finding is None:
            finding = models.Finding(
                org_id=org.id, project_id=project.id, kind="code-weakness",
                fingerprint=fingerprint, source="code-review",
                title=((result.get("message") or {}).get("text") or rule_id)[:512],
                severity=_severity_of(result, rules_index),
                detail=f"SARIF {tool_name} {rule_id} (PR #{pr.number})",
                tool=tool_name, rule_id=rule_id, path=path, line=line,
                last_seen_version_id=pr.project_version_id,
                first_seen_at=now, last_seen_at=now, updated_at=now)
            session.add(finding)
            session.flush()
        else:
            finding.last_seen_at = now
        classification = "new" if is_new else "existing"
        counters[classification] += 1
        link = (session.query(models.PrFinding)
                .filter_by(pr_id=pr.id, finding_id=finding.id).one_or_none())
        if link is None:
            link = models.PrFinding(
                org_id=org.id, pr_id=pr.id, finding_id=finding.id,
                classification=classification, file_path=path, line=line,
                created_at=now)
            session.add(link)
        items.append({"finding_id": finding.id, "severity": finding.severity,
                      "rule_id": rule_id, "path": path, "line": line,
                      "title": finding.title,
                      "classification": classification})
    session.flush()

    verdict = gates.evaluate(session, org.id, project,
                             session.get(models.ProjectVersion,
                                         pr.project_version_id)
                             if pr.project_version_id else None)
    pr.gate_verdict = verdict["verdict"]
    pr.gate_reason = verdict.get("reason") or json.dumps(
        verdict.get("rules", []))[:400]
    pr.comment = _render_comment(pr, items)
    pr.updated_at = models.utcnow()
    _audit_log(session, org.id, payload.actor, "code.pr_scanned",
               "pull_request", pr.id,
               f"{counters['new']} new / {counters['existing']} existing / "
               f"gate {pr.gate_verdict}")
    session.commit()
    return {"data": _pr_data(session, pr), "counters": counters,
            "gate": verdict, "comment": pr.comment}


@router.get("/pull-requests/{pr_id}/findings")
def pr_findings(pr_id: str, org: models.Organization = Depends(auth.require_org),
                session: Session = Depends(get_session)):
    pr = session.get(models.PullRequest, pr_id)
    if pr is None or pr.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "pull request not found")
    links = (session.query(models.PrFinding).filter_by(pr_id=pr.id).all())
    by_path: dict[str, list] = {}
    for link in links:
        finding = session.get(models.Finding, link.finding_id)
        entry = {"finding_id": link.finding_id, "classification": link.classification,
                 "path": link.file_path, "line": link.line,
                 "severity": finding.severity if finding else None,
                 "rule_id": finding.rule_id if finding else None,
                 "title": finding.title if finding else None,
                 "status": finding.status if finding else None}
        by_path.setdefault(link.file_path or "-", []).append(entry)
    return {"data": {"pull_request": _pr_data(session, pr),
                     "files": [{"path": path,
                                "findings": sorted(items,
                                                   key=lambda i: i["line"] or 0)}
                               for path, items in sorted(by_path.items())]},
            "total": len(links)}


class PrStatusIn(BaseModel):
    status: str
    actor: str = Field(min_length=2, max_length=255)


@router.post("/pull-requests/{pr_id}/status")
def set_pr_status(pr_id: str, payload: PrStatusIn = None,
                  org: models.Organization = Depends(auth.require_org),
                  session: Session = Depends(get_session)):
    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    if payload.status not in {"open", "merged", "closed"}:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            "status must be open | merged | closed")
    pr = session.get(models.PullRequest, pr_id)
    if pr is None or pr.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "pull request not found")
    pr.status = payload.status
    pr.updated_at = models.utcnow()
    _audit_log(session, org.id, payload.actor, "code.pr_status",
               "pull_request", pr.id, payload.status)
    session.commit()
    return {"data": _pr_data(session, pr)}


def _diff_lines(base_text: str, head_text: str, path: str,
                context: int = 3) -> list[dict]:
    """Unified diff as structured rows; every kept line is redacted."""
    import difflib

    base_lines = (base_text or "").splitlines()
    head_lines = (head_text or "").splitlines()
    rows = []
    for line in difflib.unified_diff(base_lines, head_lines,
                                     fromfile=f"a/{path}", tofile=f"b/{path}",
                                     n=context, lineterm=""):
        if line.startswith(("---", "+++")):
            continue
        if line.startswith("@@"):
            rows.append({"type": "hunk", "text": line})
        elif line.startswith("+"):
            rows.append({"type": "added", "text": redaction.redact_text(line[1:])})
        elif line.startswith("-"):
            rows.append({"type": "removed", "text": redaction.redact_text(line[1:])})
        else:
            rows.append({"type": "context", "text": redaction.redact_text(line[1:])})
    return rows


@router.get("/diff")
def file_diff(repository_id: str = Query(...),
              from_ref: str = Query(...), to_ref: str = Query(...),
              path: str = Query(...),
              org: models.Organization = Depends(auth.require_org),
              session: Session = Depends(get_session)):
    base = _latest_file(session, org.id, repository_id, path, from_ref)
    head = _latest_file(session, org.id, repository_id, path, to_ref)
    if base is None or head is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "diff impossible: "
            + ("base snapshot missing" if base is None else "")
            + ("; " if base is None and head is None else "")
            + ("head snapshot missing" if head is None else ""))
    rows = _diff_lines(base.content, head.content, path)
    return {"data": {"path": path, "from_ref": from_ref, "to_ref": to_ref,
                     "changed": bool(rows),
                     "added": sum(1 for row in rows if row["type"] == "added"),
                     "removed": sum(1 for row in rows if row["type"] == "removed"),
                     "rows": rows}}


@router.get("/pull-requests/{pr_id}/diff")
def pull_request_diff(pr_id: str,
                      org: models.Organization = Depends(auth.require_org),
                      session: Session = Depends(get_session)):
    """Diff base↔head for every file that carries findings in this PR.

    A missing base snapshot is reported as `missing_base` — never presented
    as "no changes", because absence of a baseline is not evidence of safety.
    """
    pr = session.get(models.PullRequest, pr_id)
    if pr is None or pr.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "pull request not found")
    links = session.query(models.PrFinding).filter_by(pr_id=pr.id).all()
    paths = sorted({link.file_path for link in links if link.file_path})
    files = []
    for path in paths:
        entry = {"path": path}
        if not (pr.repository_id and pr.base_branch and (pr.branch or pr.head_sha)):
            entry.update({"status": "missing_refs",
                          "detail": "repository, base branch and head ref are required"})
            files.append(entry)
            continue
        base = _latest_file(session, org.id, pr.repository_id, path, pr.base_branch)
        head = _latest_file(session, org.id, pr.repository_id, path,
                            pr.branch or pr.head_sha)
        if base is None or head is None:
            entry.update({"status": "missing_base" if base is None else "missing_head",
                          "detail": "no source snapshot indexed for that ref"})
        else:
            rows = _diff_lines(base.content, head.content, path)
            entry.update({"status": "diff", "changed": bool(rows),
                          "added": sum(1 for row in rows if row["type"] == "added"),
                          "removed": sum(1 for row in rows if row["type"] == "removed"),
                          "rows": rows})
        files.append(entry)
    return {"data": {"pull_request": _pr_data(session, pr), "files": files}}


class PublishIn(BaseModel):
    actor: str = Field(min_length=2, max_length=255)
    target_url: str | None = None


@router.post("/pull-requests/{pr_id}/publish")
def publish_pr(pr_id: str, payload: PublishIn = None,
               org: models.Organization = Depends(auth.require_org),
               session: Session = Depends(get_session)):
    """Publish the gate verdict as a commit status + one idempotent PR comment."""
    from backend.app import scm_client

    if payload is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "payload required")
    pr = session.get(models.PullRequest, pr_id)
    if pr is None or pr.org_id != org.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "pull request not found")
    if not pr.gate_verdict:
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "run a PR scan before publishing (no gate verdict yet)")
    if not (pr.repository_id and pr.head_sha):
        raise HTTPException(status.HTTP_409_CONFLICT,
                            "publishing needs a repository and the head commit SHA")
    if not scm_client.configured():
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "scm_not_configured: set GITHUB_TOKEN")
    repo = session.get(models.Repository, pr.repository_id)
    if repo is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "repository not found")
    try:
        slug = scm_client.repo_slug(repo.remote_url)
        state = "success" if pr.gate_verdict == "pass" else "failure"
        description = (f"Barad-dûr gate {pr.gate_verdict}: "
                       f"{pr.gate_reason or 'see console'}")[:140]
        status_response = scm_client.post_commit_status(
            slug, pr.head_sha, state, description,
            target_url=payload.target_url)
        body = f"{scm_client.COMMENT_MARKER}\n{pr.comment or 'No findings.'}"
        comment = scm_client.upsert_pr_comment(slug, pr.number, body)
    except scm_client.ScmError as exc:
        _audit_log(session, org.id, payload.actor, "code.pr_publish_failed",
                   "pull_request", pr.id, str(exc)[:300])
        session.commit()
        raise HTTPException(exc.status_code or status.HTTP_502_BAD_GATEWAY,
                            str(exc)) from None
    _audit_log(session, org.id, payload.actor, "code.pr_published",
               "pull_request", pr.id,
               f"{slug}#{pr.number} {state}")
    session.commit()
    return {"data": {"repository": slug, "sha": pr.head_sha, "state": state,
                     "status_id": status_response.get("id"),
                     "comment_id": comment.get("id")}}

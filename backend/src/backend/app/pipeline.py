"""The delivery plane: what an Action run did, in one row.

An **action** is what a pipeline asks for (`code`, `supply-chain`,
`web-surface`); a **scanner run** is the same machinery started by hand from the
CLI or the console. Both are `scan_jobs`; only `origin=ci` is a pipeline row,
because only a pipeline is a thing an operator reads as a run list. Everything a
person started belongs to orchestration, where it can be cancelled and re-run.

The verdict is the CI gate, computed the same way `ci.finish_run` computes it for
a registered run: fail-closed. A flow that did not finish, or that finished
without delivering every task, cannot certify anything — and a finding at or
above HIGH blocks. There is no "passing with a caveat": a pipeline that blocks
only sometimes teaches people to ignore it.
"""
from __future__ import annotations

import json
from urllib.parse import urlparse

from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.app import models, scan_actions, scan_flow
from backend.app.gates import NON_OPEN

GATE_SEVERITY = {"HIGH", "CRITICAL"}
# `suppressed` is enforced by the suppression rules (incidents.py) rather than by
# the finding's status vocabulary, so it is added here: a finding somebody
# deliberately silenced must not keep a build red forever.
NON_BLOCKING = NON_OPEN | {"suppressed"}
SEVERITY_RANK = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
# The three answers a run can give, and the only ones a commit row may inherit.
GROUP_VERDICTS = ("pass", "running", "fail")


def tasks_of(job: models.ScanJob) -> list[dict]:
    try:
        return json.loads(job.tasks or "[]")
    except (TypeError, ValueError):
        return []


def action_of(job: models.ScanJob) -> str | None:
    return scan_actions.action_for_tasks([task.get("task") for task in tasks_of(job)])


def event_of(subject: dict) -> str | None:
    """Which workflow event announced this run.

    Shauron's ticket carries the ref, the commit and the pull request, not the
    event name — so a pull request is `pull_request` and a bare branch is `push`.
    An explicit `event` on the subject wins the day the CLI sends one, and a
    ticket with neither stays unknown instead of being guessed.
    """
    if subject.get("event"):
        return subject["event"]
    if subject.get("pull_request"):
        return "pull_request"
    if subject.get("branch"):
        return "push"
    return None


def web_base(remote: str | None) -> str | None:
    """The browser URL of a repository, from whatever shape the CI sent.

    A remote arrives as `https://host/owner/repo.git`, `git@host:owner/repo` or
    `ssh://git@host/owner/repo`. The web UI is the same repository without the
    transport suffix, and stripping it is safer than guessing: a link that opens
    the wrong page is worse than no link.
    """
    if not remote:
        return None
    value = remote.strip()
    if value.startswith("git@") and ":" in value:
        host, _, path = value[4:].partition(":")
        value = f"https://{host}/{path}"
    elif value.startswith("ssh://"):
        rest = value[len("ssh://"):]
        authority, _, path = rest.partition("/")
        value = f"https://{authority.rsplit('@', 1)[-1]}/{path}"
    if not value.startswith(("http://", "https://")):
        return None
    value = value.rstrip("/")
    if value.endswith(".git"):
        value = value[:-4]
    return value


def commit_url(remote: str | None, sha: str | None) -> str | None:
    """Where to read this commit in the forge's own UI.

    GitHub, Gitea and Forgejo answer on `/commit/<sha>`; GitLab needs the `-/`
    segment and Bitbucket pluralises it. The host name is the only signal a
    remote carries, so an unknown forge takes the GitHub shape — the common one.
    """
    base = web_base(remote)
    if not base or not sha:
        return None
    host = urlparse(base).netloc.lower()
    if "gitlab" in host:
        return f"{base}/-/commit/{sha}"
    if "bitbucket" in host:
        return f"{base}/commits/{sha}"
    return f"{base}/commit/{sha}"


def summaries(session: Session, job_ids: list[str]) -> dict[str, dict]:
    """Findings per flow, in one query, keyed by flow id.

    A flow owns its analysis runs and a finding records the run that last
    evaluated it, so this is an identity join — never a timestamp window.

    `total` counts OPEN findings only, because that is the number the gate
    enforces: a resolved, accepted-risk, false-positive or suppressed finding
    must not keep a build red forever, or the gate gets switched off. `closed`
    is reported alongside so the console can account for every row it lists
    instead of silently dropping the others.
    """
    if not job_ids:
        return {}
    rows = (session.query(models.AnalysisRun.scan_job_id,
                          models.Finding.severity,
                          models.Finding.status,
                          func.count(models.Finding.id))
            .join(models.Finding,
                  models.Finding.last_evaluated_run_id == models.AnalysisRun.id)
            .filter(models.AnalysisRun.scan_job_id.in_(job_ids))
            .group_by(models.AnalysisRun.scan_job_id, models.Finding.severity,
                      models.Finding.status)
            .all())
    out: dict[str, dict] = {}
    for job_id, severity, status, count in rows:
        entry = out.setdefault(job_id, {"total": 0, "closed": 0,
                                        "by_severity": {}, "worst": None})
        if status in NON_BLOCKING:
            entry["closed"] += count
            continue
        key = (severity or "UNKNOWN").upper()
        entry["by_severity"][key] = entry["by_severity"].get(key, 0) + count
        entry["total"] += count
        if SEVERITY_RANK.get(key, 0) > SEVERITY_RANK.get(entry["worst"] or "UNKNOWN", 0):
            entry["worst"] = key
    return out


def reported(session: Session, job_ids: list[str]) -> dict[str, int]:
    """How many findings each flow reported when it finished.

    The live join above hands a finding to the run that *last* evaluated it, so a
    newer run of the same commit takes ownership of it and an older row would
    read "0 findings, pass" while it actually reported two. The finished event
    carries the executor's own counters and never moves; it is what keeps a
    historical row honest.
    """
    if not job_ids:
        return {}
    rows = (session.query(models.ScanEvent.job_id, models.ScanEvent.detail)
            .filter(models.ScanEvent.job_id.in_(job_ids),
                    models.ScanEvent.kind == "finished").all())
    out: dict[str, int] = {}
    for job_id, detail in rows:
        try:
            counts = (json.loads(detail or "{}").get("counts") or {})
        except (TypeError, ValueError):
            continue
        found = counts.get("findings")
        if isinstance(found, int):
            out[job_id] = found
    return out


def verdict(job: models.ScanJob, summary: dict | None) -> dict:
    summary = summary or {}
    total, worst = summary.get("total", 0), summary.get("worst")
    if job.status not in scan_flow.TERMINAL:
        return {"verdict": "running", "reason": f"flow is {job.status}"}
    if job.status != "finished":
        return {"verdict": "fail", "reason": f"the flow was {job.status}, so it certified nothing"}
    if job.evidence_state != "complete":
        return {"verdict": "fail",
                "reason": f"evidence is {job.evidence_state}: not every task came back"}
    if worst in GATE_SEVERITY:
        return {"verdict": "fail",
                "reason": f"{total} finding(s), worst {worst}: HIGH and above block the gate"}
    return {"verdict": "pass", "reason": f"{total} finding(s), none at or above HIGH"}


def row(job: models.ScanJob, summary: dict | None, reported_findings: int | None = None) -> dict:
    subject = json.loads(job.subject or "{}")
    outcome = verdict(job, summary)
    summary = summary or {"total": 0, "closed": 0, "by_severity": {}, "worst": None}
    remote = subject.get("repository")
    commit = subject.get("commit")
    # A finished run whose findings were re-evaluated elsewhere cannot be judged
    # by today's join: say so instead of showing a pass it did not earn. A run
    # that still owns closed findings is not superseded — it is a pass whose
    # findings somebody disposed of.
    superseded = (job.status == "finished" and summary["total"] == 0
                  and summary.get("closed", 0) == 0 and bool(reported_findings))
    return {
        "id": job.id,
        "started_at": _iso(scan_flow.aware(job.started_at) or scan_flow.aware(job.created_at)),
        "finished_at": _iso(scan_flow.aware(job.finished_at)),
        "ref": subject.get("branch"),
        "pull_request": subject.get("pull_request"),
        "pull_request_author": subject.get("pull_request_author"),
        "commit": commit,
        "commit_url": commit_url(remote, commit),
        "event": event_of(subject),
        "actor": job.created_by or job.principal,
        "action": action_of(job),
        "repository": subject.get("repository_name") or subject.get("repository"),
        "repository_url": web_base(remote),
        "project": subject.get("project"),
        "component": subject.get("component"),
        "version": subject.get("version"),
        "coverage": scan_flow.coverage(job),
        "status": job.status,
        "evidence": job.evidence_state,
        "verdict": outcome["verdict"],
        "verdict_reason": outcome["reason"],
        "superseded": superseded,
        "findings": {
            "total": summary["total"],
            "closed": summary.get("closed", 0),
            "reported": reported_findings,
            "by_severity": summary["by_severity"],
            "worst": summary["worst"],
        },
    }


def _iso(value) -> str | None:
    return value.isoformat() if value else None


def group_key(item: dict) -> tuple[str, str]:
    """The identity of a commit row: repository plus sha.

    Two repositories can hold the same sha, and one commit lives on exactly one
    of them. A run the CI did not stamp with a commit cannot be grouped with
    anything — it keeps its own id as key, so two unknown commits never merge
    into a row that claims they are one build.
    """
    commit = item.get("commit")
    if not commit:
        return ("", item["id"])
    return (item.get("repository_url") or item.get("repository") or "", commit)


def grouped(rows: list[dict]) -> list[dict]:
    """Fold action runs into one row per commit, newest commit first.

    A retried, cancelled or re-run workflow leaves several rows on the same sha,
    and the operator's question is about the commit, not about the attempt. The
    group speaks with its NEWEST run — that is the run that owns the findings
    today — and keeps the older attempts beside it with their own verdicts, so a
    green retry cannot bury a red attempt: `earlier_failed` says how many of
    them failed and the drawer still opens each one.
    """
    groups: list[dict] = []
    index: dict[tuple[str, str], dict] = {}
    for item in rows:
        key = group_key(item)
        group = index.get(key)
        if group is None:
            group = index[key] = {
                "key": f"{key[0] or '-'}::{key[1]}",
                "commit": item["commit"], "commit_url": item["commit_url"],
                "ref": item["ref"], "pull_request": item["pull_request"],
                "pull_request_author": item["pull_request_author"],
                "event": item["event"], "actor": item["actor"],
                "repository": item["repository"],
                "repository_url": item["repository_url"],
                "project": item["project"], "component": item["component"],
                "version": item["version"],
                "runs": [],
                "counts": {"total": 0, "pass": 0, "fail": 0,
                           "running": 0, "superseded": 0},
            }
            groups.append(group)
        group["runs"].append(item)
        counts = group["counts"]
        counts["total"] += 1
        if item["superseded"]:
            counts["superseded"] += 1
        elif item["verdict"] in GROUP_VERDICTS:
            counts[item["verdict"]] += 1
    for group in groups:
        head = group["runs"][0]
        group["id"] = head["id"]
        group["started_at"] = head["started_at"]
        group["finished_at"] = head["finished_at"]
        group["verdict"] = head["verdict"]
        group["verdict_reason"] = head["verdict_reason"]
        group["superseded"] = head["superseded"]
        group["findings"] = head["findings"]
        earlier = group["runs"][1:]
        group["earlier_failed"] = sum(1 for run in earlier if run["verdict"] == "fail")
        group["earlier_running"] = sum(1 for run in earlier if run["verdict"] == "running")
    return groups

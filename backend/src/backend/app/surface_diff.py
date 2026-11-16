"""What changed since the last time we looked at the same targets.

A run that reports "5 observations" is a receipt. The sentence an operator needs is
"the certificate now expires in 12 days instead of 43, and a new endpoint answered".
That is a diff against the previous run of the same profile on the same targets —
same tool, same questions, so the difference is about the target and not about
what we asked.

Scoping is by time window, because an observation is stored per asset (that is the
model the Assets screen reads) and carries no run id. The window is the run's own
start and finish, widened by a minute on each side for clock skew, and the result
says so — an honest boundary is better than a silent one.
"""
from __future__ import annotations

import datetime
import json

from sqlalchemy.orm import Session

from backend.app import models


def _aware(value: datetime.datetime | None) -> datetime.datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=datetime.timezone.utc)


def previous_run(session: Session, job: models.ScanJob) -> models.ScanJob | None:
    """The last finished run of the same profile that touched the same targets."""
    current = json.loads(job.profile or "{}").get("name")
    if not current:
        return None
    try:
        wanted = {json.dumps(target, sort_keys=True)
                  for target in json.loads(job.targets or "[]")}
    except (TypeError, ValueError):
        return None
    rows = (session.query(models.ScanJob)
            .filter_by(org_id=job.org_id, scanner="shauron-surface",
                       status="finished")
            .filter(models.ScanJob.id != job.id)
            .filter(models.ScanJob.created_at < job.created_at)
            .order_by(models.ScanJob.created_at.desc()).limit(40).all())
    for row in rows:
        if json.loads(row.profile or "{}").get("name") != current:
            continue
        try:
            theirs = {json.dumps(target, sort_keys=True)
                      for target in json.loads(row.targets or "[]")}
        except (TypeError, ValueError):
            continue
        if theirs == wanted:
            return row
    return None


def observations_between(session: Session, org_id: str, start, end) -> dict:
    """Keyed by kind|subject|port so two runs are comparable field by field."""
    start, end = _aware(start), _aware(end)
    if start is None or end is None:
        return {}
    rows = (session.query(models.Observation)
            .filter(models.Observation.org_id == org_id)
            .filter(models.Observation.observed_at >= start - datetime.timedelta(minutes=1))
            .filter(models.Observation.observed_at <= end + datetime.timedelta(minutes=1))
            .order_by(models.Observation.observed_at).all())
    out: dict[str, dict] = {}
    for row in rows:
        key = f"{row.kind}|{row.subject}|{row.port or ''}"
        # The last observation of a run wins: a step may re-read the same fact.
        out[key] = {"kind": row.kind, "subject": row.subject, "port": row.port,
                    "value": row.value if isinstance(row.value, dict) else {},
                    "observed_at": row.observed_at.isoformat() if row.observed_at else None}
    return out


def _render(value):
    """A value a human can read in a diff line.

    `web_paths` is a list of 14 dictionaries. Printing it raw is `[object Object]`
    fourteen times, which is worse than printing nothing: it looks like a change
    and says less than the count would.
    """
    if isinstance(value, list):
        if all(isinstance(item, dict) for item in value):
            keys = ("path", "url", "name", "value", "product")
            picked = []
            for item in value:
                for key in keys:
                    if key in item and item[key] not in (None, ""):
                        picked.append(str(item[key]))
                        break
            return picked or [json.dumps(item, sort_keys=True) for item in value]
        return [str(item) if not isinstance(item, (dict, list)) else json.dumps(item, sort_keys=True)
                for item in value]
    if isinstance(value, dict):
        return [f"{key}={value[key]}" for key in sorted(value)]
    return value


def _same(before, after) -> bool:
    """Lists of scalars compare as sets: DNS returns its MX records in any order,
    and reporting that as a change every single run teaches the reader to ignore
    the diff — the worst thing a change feed can do."""
    if isinstance(before, list) and isinstance(after, list):
        # A list is a bag of facts, not a sequence: DNS returns its MX records in
        # any order and ffuf reports paths in whatever order it finished them.
        # Comparing positionally reported a change on every single run.
        return sorted(_render(before)) == sorted(_render(after))
    if isinstance(before, dict) and isinstance(after, dict):
        return sorted(_render(before)) == sorted(_render(after))
    if isinstance(before, (dict, list)) or isinstance(after, (dict, list)):
        return json.dumps(before, sort_keys=True) == json.dumps(after, sort_keys=True)
    return before == after


def build(session: Session, job: models.ScanJob) -> dict:
    """The diff block for a run, or a reason there is nothing to compare against."""
    if job.status != "finished":
        return {"available": False, "reason": "the run has not finished",
                "reason_key": "surfaceRun.diff.notFinished"}
    previous = previous_run(session, job)
    if previous is None:
        return {"available": False,
                "reason": "this is the first finished run of this profile on these targets",
                "reason_key": "surfaceRun.diff.firstRun"}
    before = observations_between(session, job.org_id, previous.started_at or previous.created_at,
                                 previous.finished_at)
    after = observations_between(session, job.org_id, job.started_at or job.created_at,
                                 job.finished_at)
    new = [row for key, row in after.items() if key not in before]
    gone = [row for key, row in before.items() if key not in after]
    changed = []
    for key, row in after.items():
        old = before.get(key)
        if old is None:
            continue
        for field, value in row["value"].items():
            old_value = old["value"].get(field)
            if not _same(old_value, value):
                changed.append({"kind": row["kind"], "subject": row["subject"],
                                "port": row["port"], "field": field,
                                "before": _render(old_value),
                                "after": _render(value)})

    if not (new or gone or changed):
        headline = ("nothing changed since the previous run of this profile"
                    f" ({_age(previous)})")
    else:
        parts = []
        if new:
            parts.append(f"{len(new)} new")
        if changed:
            parts.append(f"{len(changed)} changed")
        if gone:
            parts.append(f"{len(gone)} gone")
        headline = f"{', '.join(parts)} since the previous run ({_age(previous)})"
    return {"available": True, "previous_run_id": previous.id,
            "previous_at": previous.created_at.isoformat() if previous.created_at else None,
            "new": new[:50], "gone": gone[:50], "changed": changed[:50],
            "counts": {"new": len(new), "gone": len(gone), "changed": len(changed)},
            "headline": headline}


def _age(job: models.ScanJob) -> str:
    stamp = _aware(job.finished_at or job.created_at)
    if stamp is None:
        return "earlier"
    delta = datetime.datetime.now(datetime.timezone.utc) - stamp
    minutes = int(delta.total_seconds() // 60)
    if minutes < 60:
        return f"{minutes}m ago"
    hours = minutes // 60
    if hours < 48:
        return f"{hours}h ago"
    return f"{hours // 24}d ago"

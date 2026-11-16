"""Every finding is work.

A finding nobody owns is a row in a list. The console's day starts in *My work*,
which reads the `work_items` trays — so a finding that never becomes a task is a
finding nobody is asked to fix, however well it is prioritised.

This module keeps that promise in one place: an ORM hook that writes the task the
moment a finding is inserted, whichever path created it (SBOM ingest, a scanner, a
SARIF import, a pentest report, an autonomous candidate promoted by a person), plus
a backfill for the findings that predate the rule.

The task is not a copy of the finding: it points at it, carries the SLA deadline as
its due date, and names the person who will be asked — the finding's assignee, else
the project's owner, else the organisation's owner.
"""

from __future__ import annotations

import re

from sqlalchemy import event, select
from sqlalchemy.orm import Session, object_session

from backend.app import models


def _owner_of(session: Session, finding: models.Finding) -> str | None:
    """Who is asked to do this: the assignee, the project's owner, the org's owner."""
    if finding.assignee:
        return finding.assignee
    owner = _owner_from(lambda statement: session.execute(statement).first(), finding)
    return owner


def _owner_from(run, finding: models.Finding) -> str | None:
    """The same rule, over a connection or a session: callers flush differently."""
    if finding.assignee:
        return finding.assignee
    if finding.project_id:
        row = run(select(models.Project.owner).where(models.Project.id == finding.project_id))
        if row and row[0]:
            return row[0]
    row = run(select(models.User.email)
              .where(models.User.org_id == finding.org_id, models.User.role == "owner")
              .order_by(models.User.created_at))
    return row[0] if row else None


def task_title(finding: models.Finding) -> str:
    """What the task says, in one line.

    An advisory's `title` is its whole description — the first page of a CVE is not a
    task name, and a queue of six hundred paragraphs is unreadable. The first sentence
    plus where it hurts is what somebody needs to pick the row up.
    """
    text = " ".join((finding.title or "finding").split())
    # Advisory titles arrive as markdown: "### Summary\nIn affected versions…". A task
    # named "### Summary In affected versions" tells nobody what to fix.
    text = re.sub(r"^[#*`\s]+", "", text)
    text = re.sub(r"^(summary|description|impact|overview|details|resumen|descripción|"
                  r"impacto)\b[\s:—-]*", "", text, flags=re.I)
    sentence = re.split(r"(?<=[.!?])\s", text)[0] or text
    if len(sentence) > 120:
        sentence = sentence[:117].rstrip() + "…"
    location = finding.endpoint or finding.path or ""
    return (f"Fix: {sentence}" + (f" · {location}" if location else ""))[:200]


def ensure_task(session: Session, finding: models.Finding) -> models.WorkItem | None:
    """Create the finding's task when it has none open. Idempotent."""
    existing = (session.query(models.WorkItem)
                .filter_by(org_id=finding.org_id, finding_id=finding.id)
                .filter(models.WorkItem.status.notin_(("done", "rejected", "withdrawn")))
                .first())
    if existing is not None:
        return existing
    item = models.WorkItem(
        org_id=finding.org_id, kind="task", title=task_title(finding),
        description=f"Finding {finding.id}: {finding.severity or 'unrated'} · "
                    f"{finding.status}",
        status="open", assignee=_owner_of(session, finding),
        requested_by="platform", due_at=finding.sla_deadline,
        cycle_id=None, finding_id=finding.id)
    session.add(item)
    return item


@event.listens_for(models.Finding, "after_insert")
def _finding_becomes_work(mapper, connection, target: models.Finding) -> None:
    """Hook: every finding is inserted as work, in the same transaction.

    Written through the connection, not the session: `session.add()` during the
    flush stage is unsupported (SQLAlchemy warns and the row never lands), and this
    hook has to work for every creation path, including bulk ingest.
    """
    existing = connection.execute(
        select(models.WorkItem.id)
        .where(models.WorkItem.org_id == target.org_id,
               models.WorkItem.finding_id == target.id,
               models.WorkItem.status.notin_(("done", "rejected", "withdrawn")))
    ).first()
    if existing:
        return
    now = models.utcnow()
    connection.execute(models.WorkItem.__table__.insert().values(
        id=models.uuid_hex(), org_id=target.org_id, kind="task",
        title=task_title(target),
        description=f"Finding {target.id}: {target.severity or 'unrated'} · {target.status}",
        status="open", assignee=_owner_from(
            lambda statement: connection.execute(statement).first(), target),
        requested_by="platform", due_at=target.sla_deadline,
        finding_id=target.id, created_at=now, updated_at=now))


def backfill(session: Session) -> int:
    """Give a task to every open finding that never got one. Returns how many."""
    created = 0
    rows = (session.query(models.Finding)
            .filter(models.Finding.status.in_(("open", "acknowledged")))
            .all())
    for finding in rows:
        before = (session.query(models.WorkItem)
                  .filter_by(org_id=finding.org_id, finding_id=finding.id).count())
        if before:
            continue
        if ensure_task(session, finding) is not None:
            created += 1
    session.commit()
    return created

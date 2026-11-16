"""One append point for the thread.

The thread is a projection: every writer goes through `append`, which allocates the next
`seq` for that thread. `run_ref` groups a family, `reply_to` draws the edge — together
they are what lets the UI render nested work instead of a flat log.
"""

from __future__ import annotations

import json

from sqlalchemy.orm import Session

from backend.app import models


def append(session: Session, *, org_id: str, thread: str, kind: str,
           body: str | None = None, author_spec: str | None = None,
           actor: str | None = None, refs: list[str] | None = None,
           run_ref: str | None = None, reply_to: str | None = None) -> models.AgentEvent:
    last = (session.query(models.AgentEvent)
            .filter_by(org_id=org_id, thread=thread)
            .order_by(models.AgentEvent.seq.desc()).first())
    row = models.AgentEvent(
        org_id=org_id, thread=thread, seq=(last.seq + 1) if last else 1,
        author_spec=author_spec, actor=actor, kind=kind, body=body,
        refs=json.dumps(refs or []), run_ref=run_ref, reply_to=reply_to)
    session.add(row)
    session.flush()
    return row

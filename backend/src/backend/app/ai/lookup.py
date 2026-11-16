"""What is this id?

The estate hands out 32-hex ids for findings, missions, tasks, runs, cycles, assets and
components, and nothing in the tool catalogue could answer "which of them is this?" — so
a chat that was handed a finding id searched it as *text*, got zero rows, and concluded
the finding did not exist. It existed; it was the finding that same agent had produced an
hour earlier.

This resolves a ref against every table that uses that shape and says what it is. A miss
is a fact too: `kind: None` means the estate does not hold it, which is different from a
tool that does not look.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from backend.app import models

#: Ordered by how often a person pastes one of these into a chat.
KINDS = (
    ("finding", models.Finding, ("id", "title", "severity", "status", "source",
                                "asset_id", "project_id", "agent_mission_id")),
    ("mission", models.AgentMission, ("id", "goal", "status", "capability", "profile",
                                      "run_id")),
    ("task", models.AgentTask, ("id", "kind", "status", "mission_id")),
    ("run", models.AiRun, ("id", "status", "question", "steps", "tokens_in",
                           "tokens_out")),
    ("cycle", models.Cycle, ("id", "name", "kind", "state")),
    ("asset", models.Asset, ("id", "value", "type", "last_seen_at")),
    ("component", models.Component, ("id", "name", "version", "purl")),
)


def lookup(ref: str, *, org: models.Organization, session: Session) -> dict:
    """`{"ref", "kind", "row"}` — the row when it exists, `kind: None` when it does not."""
    wanted = (ref or "").strip()
    if not wanted:
        return {"ref": ref, "kind": None, "row": None,
                "note": "empty ref"}
    for kind, model, fields in KINDS:
        row = session.get(model, wanted)
        if row is None:
            continue
        # Every table here carries `org_id` except an org-scoped child of one that does:
        # checking when the attribute exists keeps a cross-tenant id from answering.
        owner = getattr(row, "org_id", None)
        if owner is not None and owner != org.id:
            continue
        data = {}
        for field in fields:
            value = getattr(row, field, None)
            if value is not None:
                data[field] = value.isoformat() if hasattr(value, "isoformat") else value
        return {"ref": wanted, "kind": kind, "row": data}
    return {"ref": wanted, "kind": None, "row": None,
            "note": ("no finding, mission, task, run, cycle, asset or component in this "
                     "estate has that id — this is an absence, not a failed lookup")}

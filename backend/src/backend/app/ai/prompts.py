"""Prompts as versions (A8): the code string is the floor, a row only overrides.

Three properties this module exists for, and each one is a way prompt editing could
destroy the ledger:

* **One active version per key.** A step records `intel.cve@3`, so "which instructions
  produced this answer" is a fact and not a guess — the reason D24 refused editable
  prompts in the first place.
* **Frozen per run.** `freeze()` is called once, at the start of `execute()`; activating
  a version while a loop is running cannot change step 5 of that loop.
* **No row, no problem.** `specialists.py` keeps its strings and answers whenever the
  table is empty, so a fresh database, the test suite and a rollback all behave.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from backend.app import models
from backend.app.ai import specialists

#: The field loop's system prompt lives in Shauron today; this key is how the console
#: overrides it through `/llm/complete` without a registry inside the worker.
FIELD_KEY = "field.generic"


#: A catalogue agent's prompt is a key too (`agent.<slug>`), so the same screen that
#: versions `intel.cve` versions an agent — and the code string stays the floor.
AGENT_PREFIX = "agent."


def code_default(key: str, session: Session | None = None) -> str | None:
    """The floor for a key: the string shipped in code, or None for the field loop.

    `session` is only needed for agent keys: their floor is composed from the spec row,
    because an agent's identity *is* the row and a prompt that ignored it would describe
    an agent that no longer exists.
    """
    spec = specialists.get(key)
    if spec is not None:
        return spec.get("prompt") or ""
    if key == FIELD_KEY:
        return ""            # empty = "leave the worker's own prompt alone"
    if key.startswith(AGENT_PREFIX):
        if session is None:
            return None
        from backend.app.ai import agents as agent_catalogue
        row = (session.query(models.AgentSpec)
               .filter_by(slug=key[len(AGENT_PREFIX):]).one_or_none())
        if row is None:
            return None
        return agent_catalogue.as_specialist(row)["prompt"]
    return None


def keys(session: Session | None = None) -> list[str]:
    """Every key that can exist: specialists, the field loop, and the agents.

    Without a session the agent half is simply absent — the registry still answers, it
    just cannot enumerate a table it was not given.
    """
    base = list(specialists.names()) + [FIELD_KEY]
    if session is not None:
        slugs = (session.query(models.AgentSpec.slug)
                 .filter_by(status="active").order_by(models.AgentSpec.slug).all())
        base += [f"{AGENT_PREFIX}{slug}" for (slug,) in slugs]
    return sorted(base)


def active_row(session: Session, key: str) -> models.AiPrompt | None:
    return (session.query(models.AiPrompt)
            .filter_by(key=key, status="active")
            .order_by(models.AiPrompt.version.desc()).first())


def resolve(session: Session, key: str) -> tuple[str, str]:
    """`(body, label)` for a key. The label goes on every step of the run."""
    row = active_row(session, key)
    if row is not None:
        return row.body, f"{key}@{row.version}"
    return (code_default(key, session) or ""), f"{key}@code"


def freeze(session: Session) -> dict[str, tuple[str, str]]:
    """The whole active set, resolved once. Pass this down; never re-read mid-run."""
    rows = (session.query(models.AiPrompt).filter_by(status="active").all())
    by_key = {row.key: row for row in rows}
    frozen: dict[str, tuple[str, str]] = {}
    for key in keys(session):
        row = by_key.get(key)
        if row is not None:
            frozen[key] = (row.body, f"{key}@{row.version}")
        else:
            frozen[key] = (code_default(key, session) or "", f"{key}@code")
    return frozen


def next_version(session: Session, key: str) -> int:
    last = (session.query(models.AiPrompt).filter_by(key=key)
            .order_by(models.AiPrompt.version.desc()).first())
    return (last.version if last else 0) + 1


def draft(session: Session, key: str, body: str, *, notes: str | None = None,
          author: str | None = None) -> models.AiPrompt:
    """A new draft version. Never active: a model or a person may write it, a person
    promotes it."""
    row = models.AiPrompt(key=key, version=next_version(session, key), body=body,
                          status="draft", notes=notes, created_by=author)
    session.add(row)
    session.flush()
    return row


def activate(session: Session, row: models.AiPrompt, *, actor: str) -> models.AiPrompt:
    """Promote one version and archive the previous one, in that order."""
    for other in (session.query(models.AiPrompt)
                  .filter_by(key=row.key, status="active").all()):
        if other.id != row.id:
            other.status = "archived"
    row.status = "active"
    row.activated_by = actor
    row.activated_at = models.utcnow()
    session.flush()
    return row


def receipts(session: Session) -> dict[str, dict]:
    """What each version actually did, read from the ledger — no new telemetry.

    `ai_steps.prompt_version` already carries the label, so the editor can show runs,
    tokens and invalid handoffs per version instead of asking the operator to trust a
    change.
    """
    import json

    out: dict[str, dict] = {}
    rows = (session.query(models.AiStep)
            .filter(models.AiStep.prompt_version.isnot(None)).all())
    for step in rows:
        label = step.prompt_version or ""
        bucket = out.setdefault(label, {"steps": 0, "runs": set(), "tokens": 0,
                                        "invalid_refs": 0})
        bucket["steps"] += 1
        bucket["runs"].add(step.run_id)
        bucket["tokens"] += (step.tokens_in or 0) + (step.tokens_out or 0)
        try:
            handoff = json.loads(step.handoff or "null")
        except ValueError:
            handoff = None
        if isinstance(handoff, dict):
            bucket["invalid_refs"] += int(handoff.get("invalid_refs") or 0)
    return {label: {**values, "runs": len(values["runs"])}
            for label, values in out.items()}


def describe(session: Session) -> list[dict]:
    """The whole registry, one entry per key: active, drafts and their receipts."""
    counts = receipts(session)
    out: list[dict] = []
    for key in keys(session):
        rows = (session.query(models.AiPrompt).filter_by(key=key)
                .order_by(models.AiPrompt.version.desc()).all())
        active = next((row for row in rows if row.status == "active"), None)
        out.append({
            "key": key,
            "active": _row_data(active, counts) if active else None,
            "code_default": code_default(key, session) or "",
            "versions": [_row_data(row, counts) for row in rows],
        })
    return out


def row_data(session: Session, row: models.AiPrompt) -> dict:
    """One version as the API renders it, receipts included."""
    return _row_data(row, receipts(session))


def _row_data(row: models.AiPrompt, counts: dict) -> dict:
    label = f"{row.key}@{row.version}"
    return {"id": row.id, "key": row.key, "version": row.version,
            "label": label, "status": row.status, "body": row.body,
            "notes": row.notes, "created_by": row.created_by,
            "activated_by": row.activated_by,
            "activated_at": row.activated_at.isoformat() if row.activated_at else None,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "receipts": counts.get(label, {"steps": 0, "runs": 0, "tokens": 0,
                                           "invalid_refs": 0})}

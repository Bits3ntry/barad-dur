"""Lifecycle of an agent execution.

A run is created `queued`, moves to `running`, and ends in exactly one terminal state.
`budget_exhausted` and `blocked` are ends, not errors: both keep what was produced and
both carry a reason the operator can read.
"""

from __future__ import annotations

import json

from sqlalchemy.orm import Session

from backend.app import models
from backend.app.harness import budgets, events


OPEN_STATES = {"queued", "running", "waiting_approval"}


MAX_CHILDREN = 8
MAX_OPEN_PER_MISSION = 12


def _check_fanout(session: Session, *, mission_id: str | None,
                  parent_run_id: str | None) -> None:
    """One mission must not take every lane, and one parent must not fork a crowd."""
    if parent_run_id:
        children = (session.query(models.AgentRun)
                    .filter_by(parent_run_id=parent_run_id).count())
        if children >= MAX_CHILDREN:
            raise ValueError(f"fan-out cap reached: {children} children "
                             f"(max {MAX_CHILDREN})")
    if mission_id:
        open_runs = (session.query(models.AgentRun)
                     .filter_by(mission_id=mission_id)
                     .filter(models.AgentRun.status.in_(["queued", "running",
                                                         "waiting_approval"]))
                     .count())
        if open_runs >= MAX_OPEN_PER_MISSION:
            raise ValueError(f"mission cap reached: {open_runs} open runs "
                             f"(max {MAX_OPEN_PER_MISSION})")


def create(session: Session, *, org_id: str, spec_slug: str, goal: str,
           mission_id: str | None = None, parent_run_id: str | None = None,
           thread: str | None = None, max_turns: int | None = None,
           cost_ceiling_usd: float | None = None) -> models.AgentRun:
    _check_fanout(session, mission_id=mission_id, parent_run_id=parent_run_id)
    run = models.AgentRun(
        org_id=org_id, mission_id=mission_id, parent_run_id=parent_run_id,
        spec_slug=spec_slug, thread=thread, status="queued", goal=goal,
        max_turns=max_turns, cost_ceiling_usd=cost_ceiling_usd)
    session.add(run)
    session.flush()
    if thread:
        events.append(session, org_id=org_id, thread=thread, kind="run",
                      body=goal, author_spec=spec_slug, actor="console",
                      refs=[run.id], run_ref=run.id)
        if parent_run_id:
            session.add(models.AgentMessage(
                org_id=org_id, mission_id=mission_id, from_run=parent_run_id,
                to_run=run.id, kind="delegate", body=goal))
    return run


def start(session: Session, run: models.AgentRun) -> models.AgentRun:
    run.status = "running"
    run.started_at = models.utcnow()
    session.flush()
    return run


def finish(session: Session, run: models.AgentRun, status: str,
           *, reason: str | None = None) -> models.AgentRun:
    if status not in {"done", "failed", "blocked", "budget_exhausted", "cancelled"}:
        raise ValueError(f"not a terminal state: {status}")
    run.status = status
    run.blocked_reason = reason
    run.ended_at = models.utcnow()
    if run.thread:
        events.append(session, org_id=run.org_id, thread=run.thread,
                      kind="status", body=reason or status, author_spec=run.spec_slug,
                      actor="system", refs=[run.id], run_ref=run.id)
    session.flush()
    return run


def record_step(session: Session, run: models.AgentRun, step: models.AiStep) -> None:
    """Attribute an existing `AiStep` to this run and fold its usage."""
    step.parent_run_id = run.id
    budgets.register_step(session, run, tokens_in=step.tokens_in,
                          tokens_out=step.tokens_out,
                          cost_usd=None if step.price_known is False else step.cost_usd)


def data(session: Session, run: models.AgentRun, *, depth: int = 0) -> dict:
    children = (session.query(models.AgentRun)
                .filter_by(parent_run_id=run.id)
                .order_by(models.AgentRun.created_at).all()) if depth < 4 else []
    return {
        "id": run.id, "spec": run.spec_slug, "status": run.status,
        "thread": run.thread, "mission_id": run.mission_id,
        "parent_run_id": run.parent_run_id, "goal": run.goal,
        "blocked_reason": run.blocked_reason,
        "budget": budgets.summary(session, run),
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "ended_at": run.ended_at.isoformat() if run.ended_at else None,
        "children": [data(session, child, depth=depth + 1) for child in children],
    }

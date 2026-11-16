"""Money and turns, checked before they are spent.

A ceiling checked after the call is an invoice. Every entry point here answers one
question — "may this run spend one more cent/turn?" — and the answer is a refusal with a
reason, never a silent overspend.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from backend.app import models


class BudgetExceeded(RuntimeError):
    """The run cannot spend more. Carries the reason the operator will read."""

    def __init__(self, reason: str, *, kind: str = "budget_exhausted") -> None:
        super().__init__(reason)
        self.reason = reason
        self.kind = kind


def own_cost(run: models.AgentRun) -> float:
    return float(run.cost_usd or 0.0)


def family_cost(session: Session, run: models.AgentRun) -> float:
    """Total for this run and every descendant — the number the ceiling binds."""
    total = own_cost(run)
    children = (session.query(models.AgentRun)
                .filter(models.AgentRun.parent_run_id == run.id).all())
    for child in children:
        total += family_cost(session, child)
    return total


def remaining_usd(session: Session, run: models.AgentRun) -> float | None:
    if run.cost_ceiling_usd is None:
        return None
    return float(run.cost_ceiling_usd) - family_cost(session, run)


def enforce(session: Session, run: models.AgentRun, *, projected_usd: float = 0.0) -> None:
    """Refuse before the call, naming which limit was hit."""
    if run.status in {"done", "failed", "blocked", "budget_exhausted"}:
        raise BudgetExceeded(f"run is {run.status}", kind="run_closed")
    if run.max_turns is not None and run.turn_count >= run.max_turns:
        raise BudgetExceeded(
            f"turn budget reached ({run.turn_count}/{run.max_turns})")
    left = remaining_usd(session, run)
    if left is not None and projected_usd >= left:
        raise BudgetExceeded(
            f"cost ceiling reached (${family_cost(session, run):.4f} of "
            f"${float(run.cost_ceiling_usd):.4f})")


def register_step(session: Session, run: models.AgentRun, *, tokens_in: int,
                  tokens_out: int, cost_usd: float | None) -> None:
    """Fold one paid call into the run. `cost_usd is None` means unpriced usage."""
    run.turn_count += 1
    run.tokens_in += int(tokens_in or 0)
    run.tokens_out += int(tokens_out or 0)
    if cost_usd is not None:
        run.cost_usd = float(run.cost_usd or 0) + float(cost_usd)
    session.flush()


def summary(session: Session, run: models.AgentRun) -> dict:
    left = remaining_usd(session, run)
    return {
        "run_id": run.id,
        "turns": run.turn_count,
        "max_turns": run.max_turns,
        "cost_usd": round(family_cost(session, run), 6),
        "ceiling_usd": None if run.cost_ceiling_usd is None else float(run.cost_ceiling_usd),
        "remaining_usd": None if left is None else round(left, 6),
        "exhausted": left is not None and left <= 0,
    }

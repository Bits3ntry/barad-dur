"""Session context: what a prompt sees, and how it stops growing (D67–D69).

The rule the whole module exists for: **compression is prompt assembly, never
deletion.** `chat_turns` keeps every message; the prompt gets `brief + pins + last K
turns`. A divider turn records that a compaction happened, so the reader can see the
seam and open the raw turns behind it.
"""
from __future__ import annotations

import json

from sqlalchemy.orm import Session

from backend.app import models
from backend.app.ai import engine

K_TURNS = 6
TOKEN_BUDGET = 8000
BRIEF_CHARS = 2400          # ~600 tokens
COMPACT_AFTER_TURNS = 12

BRIEF_PROMPT = """You are compacting a security-operations conversation into a brief.

Preserve, in this order, and nothing else:
1. decisions already taken;
2. refusals and their reason (missing grant, unknown data, budget, out of scope);
3. open threads that still need an answer;
4. identifiers already cited (findings, assets, components, CVEs) — verbatim;
5. the operator's constraints ("only DEV", "no production", "read-only").

Drop: pleasantries, restated questions, reasoning that led nowhere, and any prose
that does not change what happens next. Answer with the brief only, at most 300 words."""


def estimate_tokens(text: str) -> int:
    """Cheap and honest: four characters per token, rounded up, never zero."""
    return max(1, (len(text or "") + 3) // 4)


def turns_for(session_db: Session, session: models.ChatSession,
              after_seq: int = 0) -> list[models.ChatTurn]:
    return (session_db.query(models.ChatTurn)
            .filter_by(session_id=session.id)
            .filter(models.ChatTurn.seq > after_seq)
            .order_by(models.ChatTurn.seq).all())


def pinned_ids(session_db: Session, session: models.ChatSession) -> set[str]:
    rows = (session_db.query(models.ChatPin).filter_by(session_id=session.id).all())
    return {row.turn_id for row in rows if row.turn_id}


def subject_digest(session_db: Session, session: models.ChatSession) -> str:
    """One line naming what this conversation is about, or `''`.

    `subject_kind/subject_id` has been stored since the first session and never read:
    the model re-derived the subject from the previous turns, which means a compaction
    could drop it and the operator had to restate it. The digest is a fact read from a
    row, so it survives compression and costs one line.
    """
    if not session.subject_kind or not session.subject_id:
        return ""
    kind, ref = session.subject_kind, session.subject_id
    try:
        if kind == "project":
            row = (session_db.get(models.Project, ref)
                   or session_db.query(models.Project).filter_by(slug=ref).one_or_none())
            if row is not None:
                group = getattr(row, "group_name", None)
                return (f"project · {row.name} (slug {row.slug}"
                        + (f", group {group}" if group else "") + ")")
        elif kind == "asset":
            row = session_db.get(models.Asset, ref)
            if row is not None:
                return (f"asset · {row.value} ({row.type}, "
                        f"{row.classification or 'unclassified'})")
        elif kind == "finding":
            row = session_db.get(models.Finding, ref)
            if row is not None:
                return (f"finding · {ref} — {row.title} "
                        f"({row.severity}, {row.status})")
        elif kind == "cycle":
            row = session_db.get(models.Cycle, ref)
            if row is not None:
                return f"cycle · {row.name} ({row.state})"
    except Exception:          # a digest is a convenience, never a reason to fail a turn
        return ""
    return f"{kind} · {ref} (not found in this estate)"


def assemble(session_db: Session, session: models.ChatSession, *,
             question: str, k: int = K_TURNS) -> list[dict]:
    """The messages sent to the model: subject, brief, pins, last K turns, question."""
    turns = turns_for(session_db, session)
    pinned = pinned_ids(session_db, session)
    messages: list[dict] = []

    subject = subject_digest(session_db, session)
    if subject:
        messages.append({"role": "system", "content": f"Subject: {subject}"})

    if session.brief:
        messages.append({"role": "system",
                         "content": f"Session brief (compressed history):\n{session.brief}"})

    pinned_text = [row.content for row in turns
                   if row.id in pinned and row.role in {"user", "orchestrator",
                                                        "specialist"}]
    if pinned_text:
        messages.append({"role": "system",
                         "content": "Pinned context (always relevant):\n"
                                    + "\n---\n".join(pinned_text)})

    window = [row for row in turns if row.role != "compaction"][-k:]
    for row in window:
        role = "user" if row.role == "user" else "assistant"
        messages.append({"role": role, "content": row.content})

    messages.append({"role": "user", "content": question})
    return messages


def context_tokens(messages: list[dict]) -> int:
    return sum(estimate_tokens(message.get("content") or "") for message in messages)


def needs_compaction(session_db: Session, session: models.ChatSession,
                     messages: list[dict]) -> bool:
    plain = [row for row in turns_for(session_db, session) if row.role != "compaction"]
    return (len(plain) > COMPACT_AFTER_TURNS
            or context_tokens(messages) > TOKEN_BUDGET)


def pending_for_compaction(session_db: Session, session: models.ChatSession,
                           k: int = K_TURNS) -> list[models.ChatTurn]:
    """The turns that would leave the verbatim window."""
    plain = [row for row in turns_for(session_db, session) if row.role != "compaction"]
    return plain[:-k] if len(plain) > k else []


def compact(session_db: Session, session: models.ChatSession, *, provider,
            api_key: str, transport=None) -> dict:
    """Rewrite the brief from (previous brief + the turns leaving the window).

    Recorded as an `AiRun(mode="compact")` with one step: compaction spends money, so
    it belongs in the same ledger as the answers it makes cheaper.
    """
    fold = pending_for_compaction(session_db, session)
    if not fold:
        return {"compacted": False, "reason": "nothing left the window yet",
                "brief_version": session.brief_version}

    settings = engine.settings_row(session_db)
    body = "\n".join(f"[{row.role}] {row.content}" for row in fold)
    prompt = (BRIEF_PROMPT
              + "\n\nPrevious brief:\n" + (session.brief or "(none)")
              + "\n\nTurns to fold:\n" + body[:20000])

    run = models.AiRun(org_id=session.org_id, actor=session.created_by,
                       actor_role="analyst", mode="compact",
                       question=f"compact session {session.id}", provider_id=provider.id,
                       model=provider.model)
    session_db.add(run)
    session_db.commit()

    try:
        engine.budget_check(session_db, settings,
                            estimate_tokens(prompt) + BRIEF_CHARS // 4)
        result = engine.complete(provider, api_key,
                                 [{"role": "user", "content": prompt}], [],
                                 transport=transport, session_id=run.id)
    except (engine.BudgetExceeded, engine.ProviderError) as error:
        run.status = ("stopped_budget" if isinstance(error, engine.BudgetExceeded)
                      else "failed")
        run.error = str(error)
        run.stop_reason = getattr(error, "reason", None)
        run.finished_at = models.utcnow()
        session_db.commit()
        return {"compacted": False, "reason": str(error),
                "brief_version": session.brief_version}

    brief = (result["content"] or "").strip()[:BRIEF_CHARS]
    cost, known = engine.price(provider, result["tokens_in"], result["tokens_out"])
    run.tokens_in = result["tokens_in"]
    run.tokens_out = result["tokens_out"]
    run.cost_usd = cost
    run.price_known = known
    run.steps = 1
    run.status = "answered"
    run.finished_at = models.utcnow()
    session_db.add(models.AiStep(
        org_id=session.org_id, run_id=run.id, seq=1, role="session.brief",
        prompt_version=engine.PROMPT_VERSION, tool_calls="[]",
        tokens_in=result["tokens_in"], tokens_out=result["tokens_out"],
        cost_usd=cost, cached_tokens=result.get("cached_tokens", 0),
        usage_json=_usage_json(result)))

    previous = json.dumps({"folded": len(fold), "tokens": session.brief_tokens})
    session.brief = brief
    session.brief_version += 1
    session.brief_tokens = estimate_tokens(brief)
    session_db.add(models.ChatTurn(
        org_id=session.org_id, session_id=session.id,
        seq=_next_seq(session_db, session), role="compaction",
        author="session.brief",
        content=(f"context compacted · {len(fold)} turns → brief v{session.brief_version}"
                 f" · −{max(0, context_tokens([{'content': body}]) - session.brief_tokens)}"
                 f" tokens · {previous}"),
        citations="[]"))
    session_db.commit()
    return {"compacted": True, "folded": len(fold),
            "brief_version": session.brief_version,
            "brief_tokens": session.brief_tokens, "cost_usd": cost}


def _usage_json(result: dict) -> str | None:
    """What the provider reported beyond the counters, verbatim (see A9)."""
    usage = {key: value for key, value in (result.get("usage_raw") or {}).items()
             if key not in ("prompt_tokens", "completion_tokens", "total_tokens")}
    return json.dumps(usage) if usage else None


def _next_seq(session_db: Session, session: models.ChatSession) -> int:
    last = (session_db.query(models.ChatTurn)
            .filter_by(session_id=session.id)
            .order_by(models.ChatTurn.seq.desc()).first())
    return (last.seq + 1) if last else 1


def next_seq(session_db: Session, session: models.ChatSession) -> int:
    return _next_seq(session_db, session)

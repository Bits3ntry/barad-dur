"""From "analizá esto" to a plan a person can approve.

The proposal used to be a template: `validate <title> on <host>`. That is a goal, not a
plan — the operator still had to know what to send. This runs a read-only pass over what
the estate already holds, and asks for one thing: a technique, the steps, and the signal
that would settle it.

What it will not do: invent a technique. If nothing in the catalogue documents how the
flaw is exercised, the plan says so and proposes a *falsification* — a probe that would
show the flaw is not there — instead of a payload that came from nowhere. That is the
difference between a PoC and a paragraph.
"""
from __future__ import annotations

import json
import re

from sqlalchemy.orm import Session

from backend.app import models
from backend.app.ai import engine, orchestrator

#: Read-only, and only what a plan needs: the finding, what it touches, where it runs,
#: what the world says about it, and what the estate authorises.
PLANNER_TOOLS = ["finding_detail", "findings_search", "components_impact",
                 "deployment_chain", "vulnerabilities_search", "advisory_resolve",
                 "intel_kev", "intel_epss", "assets_search", "authorized_targets",
                 "projects_list", "project_inventory"]

PROMPT = """You are validation.plan. You do not execute anything: you read this estate and
write the plan somebody else will approve.

Gather, with your tools and only with them: what the finding is about (component, version
as recorded, purl), which asset and deployment carry it, whether the advisory documents a
technique, and whether the host is inside an authorised scope.

Then, at the end of your answer, emit the plan inside a fenced json block — one line of
verdict before it, nothing after it:

```json

{
  "technique": {"known": true|false,
                "summary": "how the flaw is exercised, in one sentence",
                "sources": ["ids returned by your tools"]},
  "hypothesis": "one sentence: what would be true if this is exploitable",
  "steps": [{"n": 1, "method": "GET|POST|...", "path": "/exact/endpoint",
             "payload": "the body or query, or null",
             "expect": "the observable that decides this step"}],
  "success_signal": "the single observable that makes the verdict VULNERABLE",
  "safety": "read_only" if every step only reads, else "active",
  "needs_grant": true|false,
  "open_questions": ["what you could not establish, and the data that would settle it"]
}
```

Rules that make the plan usable:
- `path` is relative to the target's origin. Never include the host.
- Every step must be decidable: `expect` names a status, a header or a field, not a mood.
- If `technique.known` is false, `steps` still must exist: the probe that would falsify
  the hypothesis. Say in `open_questions` that no documented technique was found.
- No more than 5 steps. A plan that needs ten is a plan for a human, not a mission.
- If a version or host is unknown, that goes in `open_questions` — never a guessed value.
"""

#: The plan arrives as the last fenced block: prose first is what the answer path already
#: does, and forcing JSON on the only step is what left the run with no answer at all.
FENCE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)
LOOSE = re.compile(r"\{.*\}", re.DOTALL)


def spec() -> dict:
    """The orchestrator's shape for this agent. Not a catalogue row: a plan is not an
    agent anybody addresses, it is a step of a proposal."""
    return {
        "slug": "validation.plan",
        "name": "Validation planner",
        "prompt": PROMPT,
        "prompt_label": "validation.plan@code",
        "prompt_key": "validation.plan",
        "tools": PLANNER_TOOLS,
        "wants": ["a plan with steps, an expected signal and what is unknown"],
        "sees": [],
        "executor": "analyst",
        "must_return": ["technique", "hypothesis", "steps", "success_signal", "safety"],
    }


def parse(answer: str) -> dict | None:
    """The plan out of the model's answer, or None when it did not produce one.

    A planner that answers in prose is not a failure the operator should see as text: the
    proposal falls back to the honest template, which is worse but never wrong.
    """
    if not answer:
        return None
    for match in reversed(list(FENCE.finditer(answer))):
        try:
            payload = json.loads(match.group(1))
        except ValueError:
            continue
        if isinstance(payload, dict) and payload.get("steps"):
            return payload
    # A plan with no fence still counts if it is the whole answer: a model that ignores
    # the formatting is not a reason to throw away the analysis.
    loose = LOOSE.search(answer)
    if loose is not None:
        try:
            payload = json.loads(loose.group(0))
        except ValueError:
            return None
        if isinstance(payload, dict) and payload.get("steps"):
            return payload
    return None


def plan(session: Session, org: models.Organization, *, actor: str,
         question: str) -> dict | None:
    """Run the planner once and return its plan. Its own run, in the same ledger."""
    provider = engine.default_provider(session)
    if provider is None:
        return None
    run = models.AiRun(org_id=org.id, actor=actor, actor_role="analyst",
                       question=question, mode="ask",
                       provider_id=provider.id, model=provider.model)
    session.add(run)
    session.flush()
    try:
        orchestrator.execute(session, run, agent=spec())
    except Exception:          # a planner that dies must not take the proposal with it
        return None
    return parse(run.answer or "")


def describe(plan_row: dict, limit: int = 5) -> str:
    """The plan as the operator reads it, before approving anything."""
    technique = plan_row.get("technique") or {}
    lines = []
    if technique.get("known"):
        lines.append(f"**Técnica documentada:** {technique.get('summary', '').strip()}")
    else:
        lines.append("**No hay técnica documentada** para esta vulnerabilidad en el "
                     "catálogo: el plan es una prueba de falsación, no un exploit.")
    lines.append(f"**Hipótesis:** {plan_row.get('hypothesis', '').strip()}")
    steps = plan_row.get("steps") or []
    for step in steps[:limit]:
        payload = step.get("payload")
        body = f" · `{payload}`" if payload else ""
        lines.append(f"{step.get('n', '·')}. `{step.get('method', 'GET')} "
                     f"{step.get('path', '')}`{body} → {step.get('expect', '')}")
    signal = plan_row.get("success_signal")
    if signal:
        lines.append(f"**Señal de éxito:** {signal}")
    if plan_row.get("safety") == "active":
        lines.append("**Clase:** activa — modifica o autentica contra el target.")
    open_questions = plan_row.get("open_questions") or []
    if open_questions:
        lines.append("**Sin cerrar:** " + "; ".join(str(q) for q in open_questions[:3]))
    return "\n".join(lines)

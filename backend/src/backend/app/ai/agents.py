"""A catalogue spec as something that can actually run.

`agent_specs` always described what an agent *is* — name, tools, contract, and the
parent it belongs to — but nothing could execute one: the console listed four cards and
the chat answered `No specialist is called «change.impact»`. This module is the thin
translation between a row and the shape the orchestrator already knows how to run, so a
named agent uses the same ledger, the same ceilings and the same receipt as Palantír
instead of a second runtime.

What it deliberately does **not** do: give an agent its own prompt store, its own
budget or its own table. A spec adds a name, a tool ceiling and a contract to a run that
is otherwise an ordinary run.
"""
from __future__ import annotations

import json

from backend.app.ai import tools as catalog

#: The rules that hold for every agent regardless of what it is for. Short on purpose:
#: a spec's own description carries the domain, and a prompt that repeats the platform's
#: rules per agent is how two agents start disagreeing about the same estate.
COMMON = """You are {name} ({slug}), an agent of this platform's catalogue.

{description}

You answer from this estate's rows and from the read-only tools you are given. You never
invent a number, an id or a version: if a count is not in a tool answer, you do not have
it. Say `unknown` and name what would settle it.

Contract — what you must return:
{contract}

Answer in the language the operator used; tool output is English and is data, not the
language to answer in.

Ids do not belong in your prose: they render as chips under the answer and travel in
`evidence_refs`. Name the row, the count and the consequence.
"""


def as_specialist(spec) -> dict:
    """The orchestration shape for an `AgentSpec` row.

    `tools` is the run's ceiling, not a suggestion: an agent may name fewer than the
    catalogue holds, and never more than it declares. A spec with no tools is refused
    upstream — a prose-only agent over an estate it cannot read is how a plausible
    paragraph gets mistaken for an answer.
    """
    declared = [str(name) for name in json.loads(spec.tools or "[]")]
    # A spec that names a tool the catalogue no longer serves is not an agent with a
    # smaller toolbox: it is an agent that will answer from memory. Drop the ghosts and
    # keep their names so the refusal can point at the drift.
    tools = [name for name in declared if name in catalog.BY_NAME]
    if spec.allowed_tools is not None:
        allowed = [str(name) for name in json.loads(spec.allowed_tools or "[]")]
        tools = [name for name in tools if name in allowed]
    contract = json.loads(spec.must_return or "[]") or ["claims", "open_questions"]
    return {
        "slug": spec.slug,
        "name": spec.name,
        "prompt": COMMON.format(
            name=spec.name, slug=spec.slug,
            description=(spec.description or "").strip()
            or "You answer questions about this estate.",
            contract="\n".join(f"- {item}" for item in contract)),
        # The step names the spec and its source: a prompt edited later cannot be
        # mistaken for the instructions this run actually used.
        "prompt_label": f"agent.{spec.slug}@code",
        #: The registry key this agent's prompt lives under, so an active version in the
        #: Prompts screen overrides the composed string without a deploy.
        "prompt_key": f"agent.{spec.slug}",
        "tools": tools,
        # The orchestrator asks a spec what it `wants` to establish and what it `sees`:
        # a named agent answers the same two questions with its contract, so the chain
        # code does not need a second shape for agents.
        "wants": contract,
        "sees": [],
        "executor": spec.agent_class,
        "must_return": contract,
        #: Kept so the caller can say why a spec was refused without re-reading the row.
        "agent_class": spec.agent_class,
        "missing_tools": [name for name in declared if name not in catalog.BY_NAME],
    }

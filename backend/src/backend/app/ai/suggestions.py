"""The buttons under an answer: the agent may offer only what the platform can do.

An assistant that invents affordances is worse than one that offers none — a button that
404s teaches the operator to stop clicking. So the model does not propose free-form
actions: it picks from a closed vocabulary, and every pick is validated here against the
estate before it reaches the screen. A suggestion that does not survive validation is
dropped silently, and a dropped button is not an error the reader has to triage.

The vocabulary is deliberately small. `create_cycle` is **not** in it: there is no tool
that creates a cycle, so a button offering one would be a promise the platform cannot
keep. When that tool exists, it becomes one more entry here.
"""
from __future__ import annotations

import json
import re

from sqlalchemy.orm import Session

from backend.app import models

#: What an answer is allowed to offer. `label` is what the operator reads, never the
#: action name: the screen says "Validar en campo", not `validate_finding`.
ACTIONS = {
    "ask": "una pregunta de seguimiento que este mismo chat puede responder",
    "open_screen": "abrir una pantalla con lo que la respuesta acaba de nombrar",
    "validate_finding": "pedir una misión de validación para un hallazgo",
    "open_run": "abrir el recibo de una corrida",
}

SCREENS = {"projects", "assets", "findings", "missions", "prompts", "ai-runs",
           "inventory", "settings"}

FENCE = re.compile(r"```json\s*(\{.*?\})\s*```", re.DOTALL)
MAX_SUGGESTIONS = 3


def extract(session: Session, org: models.Organization,
            answer: str) -> tuple[str, list[dict]]:
    """Split the answer from the block that carries its buttons.

    Returns the prose with the block removed and the suggestions that survived. A block
    that is malformed, or that names an action outside the vocabulary, costs the answer
    its buttons and nothing else.
    """
    if not answer:
        return answer, []
    blocks = list(FENCE.finditer(answer))
    for match in reversed(blocks):
        try:
            payload = json.loads(match.group(1))
        except ValueError:
            continue
        if not isinstance(payload, dict) or "suggestions" not in payload:
            continue
        prose = (answer[:match.start()] + answer[match.end():]).rstrip()
        return prose, validate(session, org, payload.get("suggestions"))
    return answer, []


def validate(session: Session, org: models.Organization, raw) -> list[dict]:
    """Keep what the estate can honour. At most three, in the order the model put them."""
    if not isinstance(raw, list):
        return []
    out: list[dict] = []
    for item in raw:
        if len(out) >= MAX_SUGGESTIONS:
            break
        if not isinstance(item, dict):
            continue
        action = str(item.get("action") or "").strip()
        label = str(item.get("label") or "").strip()[:80]
        if action not in ACTIONS or not label:
            continue
        if action == "ask":
            prompt = str(item.get("prompt") or "").strip()[:600]
            if prompt:
                out.append({"action": action, "label": label, "prompt": prompt})
        elif action == "open_screen":
            screen = str(item.get("screen") or "").strip()
            if screen in SCREENS:
                suggestion = {"action": action, "label": label, "screen": screen,
                              "href": f"#{screen}"}
                if item.get("q"):
                    suggestion["q"] = str(item["q"])[:120]
                    suggestion["href"] = f"#{screen}::{suggestion['q']}"
                out.append(suggestion)
        elif action == "validate_finding":
            finding_id = str(item.get("finding_id") or "").strip()
            row = session.get(models.Finding, finding_id) if finding_id else None
            if row is not None and row.org_id == org.id:
                # The button sends the same sentence a person would type: the proposal
                # path is the only door, and it still stops at the human gate.
                out.append({"action": action, "label": label, "finding_id": finding_id,
                            "prompt": f"@angmar validá el impacto de {finding_id}"})
        elif action == "open_run":
            run_id = str(item.get("run_id") or "").strip()
            row = session.get(models.AiRun, run_id) if run_id else None
            if row is not None and row.org_id == org.id:
                out.append({"action": action, "label": label, "run_id": run_id,
                            "href": f"#ai-runs::{run_id}"})
    return out


#: What the report is told about its own buttons. Short on purpose: the model already
#: has the vocabulary, it does not need an essay about it.
INSTRUCTION = """After your answer, and only when it earns it, emit one fenced json block:

```json
{"suggestions": [{"action": "open_screen", "label": "...", "screen": "findings"}]}
```

Allowed `action` values, nothing else:
- `ask` — {"action":"ask","label":"...","prompt":"the next question"}
- `open_screen` — {"action":"open_screen","label":"...","screen":"projects|assets|findings|missions|prompts|ai-runs|inventory|settings","q":"optional search"}
- `validate_finding` — {"action":"validate_finding","label":"...","finding_id":"<32 hex from a tool answer>"}
- `open_run` — {"action":"open_run","label":"...","run_id":"<run id from this conversation>"}

At most three. Every id must come from a tool answer in this run; a button that points
at something you did not read is dropped by the platform. If nothing useful applies,
emit no block at all — an empty list of buttons is better than a guess.
"""

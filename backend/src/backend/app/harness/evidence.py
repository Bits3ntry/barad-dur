"""Evidence has a stance, and an assumption cannot close a claim.

`observation` means we saw it and can point at where. `assumption` means we inferred it.
A candidate may be stored either way; only an observation with a locator is proof.
"""

from __future__ import annotations

import json
from dataclasses import dataclass


STANCES = {"observation", "assumption"}


@dataclass(frozen=True)
class Evidence:
    stance: str
    statement: str
    locator: str | None = None


def normalize(raw) -> list[Evidence]:
    """Accept a dict, a list of dicts, a JSON string, or `None`."""
    if raw is None:
        return []
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return [Evidence("assumption", raw.strip())] if raw.strip() else []
    # A candidate may store the bare list or an envelope `{"evidence": [...],
    # "expect": "..."}`; both mean the same thing here.
    if isinstance(raw, dict) and "evidence" in raw:
        raw = raw.get("evidence")
        if raw is None:
            return []
    items = raw if isinstance(raw, list) else [raw]
    out: list[Evidence] = []
    for item in items:
        if isinstance(item, str):
            if item.strip():
                out.append(Evidence("assumption", item.strip()))
            continue
        if not isinstance(item, dict):
            continue
        stance = str(item.get("stance") or "assumption").lower()
        if stance not in STANCES:
            stance = "assumption"
        statement = str(item.get("statement") or "").strip()
        if not statement:
            continue
        locator = item.get("locator")
        out.append(Evidence(stance, statement,
                            str(locator).strip() if locator else None))
    return out


def confirmable(items: list[Evidence]) -> bool:
    """A claim can reach a terminal state only with one observation that names where."""
    return any(item.stance == "observation" and item.locator for item in items)


def as_json(items: list[Evidence]) -> str:
    return json.dumps([{"stance": i.stance, "statement": i.statement,
                        "locator": i.locator} for i in items], ensure_ascii=False)

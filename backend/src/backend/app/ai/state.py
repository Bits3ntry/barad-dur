"""The run's typed state (D19): facts, claims, open questions, what we visited.

The state is not a transcript. A transcript asks the model to remember; a typed state
lets code decide. Three consequences, and they are the reason this file exists:

* **Facts are append-only and keyed by tool.** `deployment_chain` called twice is one
  fact with one digest, so a loop cannot spin by re-reading the same rows.
* **Claims carry refs, and refs are checkable.** A claim whose `evidence_refs` do not
  appear in what the tools returned is not evidence, whatever the model says (D21).
* **Absence has a name.** An empty fact list is `not_installed`/`unknown`, never
  "clean"; the router reads `open_questions` to decide whether another specialist is
  worth a token.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field

#: Keys whose values are citable identifiers. Anything a tool returns with one of
#: these names can be pointed at from a claim.
ID_KEYS = {
    "id", "purl", "cve", "cve_id", "finding_id", "component_id", "version_id",
    "build_id", "deployment_id", "asset_id", "project_id", "repository_id",
    "observation_id", "ref", "commit", "slug",
}

MAX_REFS = 400
MAX_SUMMARY_CHARS = 3000


def _digest_key(value) -> str:
    """A deterministic JSON-object key for a non-JSON mapping key."""
    return f"{type(value).__module__}.{type(value).__qualname__}:{value!r}"


def _digestable(value):
    """Normalize exceptional mapping keys without changing ordinary payload hashes."""
    if isinstance(value, dict):
        return {_digest_key(key): _digestable(item)
                for key, item in sorted(value.items(), key=lambda pair: _digest_key(pair[0]))}
    if isinstance(value, list):
        return [_digestable(item) for item in value]
    if isinstance(value, tuple):
        return [_digestable(item) for item in value]
    return value


def digest(payload) -> str:
    try:
        blob = json.dumps(payload, sort_keys=True, default=str).encode()
    except TypeError:
        # Python sorts the original key objects before applying `default=str`; an
        # external tool payload containing both `null` and string keys otherwise
        # kills the run while we are only trying to write its receipt.
        blob = json.dumps(_digestable(payload), sort_keys=True, default=str).encode()
    return hashlib.sha256(blob).hexdigest()[:16]


#: What one tool result may cost the prompt. The console payloads are shaped for
#: screens — one findings page is 200 rows — and the field that answers a counting
#: question (`total`) sits *after* the rows, so dumping the dict and slicing the string
#: cut the number off: the model read "truncated, no total" and answered that it could
#: not give a figure over a table it had just queried successfully.
MAX_TOOL_CHARS = 4000  # a tool result is a pointer, not the record
#: Rows that carry a title and a severity are the ones an operator reads as a list. They
#: travel slim — id, title, severity, status — because the fat fields (`evidence`,
#: `detail`) are what pushed eleven rows past the budget and left the answer with
#: references instead of names. Eleven findings must fit; a finding is not a document
#: until somebody opens one.
ROW_FIELDS = ("id", "title", "severity", "status", "source", "vector", "asset_id",
              "asset_value", "component_name", "component_version", "cve_id",
              "cvss_score", "priority", "triage_status", "exploit_state", "first_seen_at",
              "last_seen_at", "kind", "name", "total", "url", "endpoint")


def _slim(row):
    if not isinstance(row, dict):
        return row
    if not ("severity" in row or "title" in row):
        return row
    return {key: value for key, value in row.items()
            if key in ROW_FIELDS and value is not None}
_SAMPLE_ROWS = (12, 6, 3, 1, 0)


def _shrink(value, rows: int):
    if isinstance(value, dict):
        return {key: _shrink(item, rows) for key, item in value.items()}
    if isinstance(value, list):
        head = [_shrink(item, rows) for item in value[:rows]]
        if len(value) > rows:
            head.append({"_rows_hidden": len(value) - rows,
                         "_hint": "call again with limit/offset if you need the rest"})
        return head
    return value


def _slim_list(value: list) -> list:
    return [_slim(item) for item in value]


def projection(payload) -> str:
    """A bounded, agent-shaped view of one tool result: the numbers first, then samples.

    Scalars (`total`, `limit`, `offset`, `coverage`, `counters`) come before any list,
    rows are sampled rather than sliced mid-JSON, and the hidden count is stated, so a
    model never has to infer an empty set from a truncated one.
    """
    if not isinstance(payload, dict):
        payload = {"data": payload}
    ordered = {key: value for key, value in payload.items()
               if not isinstance(value, (list, dict))}
    ordered.update({key: _slim_list(value) if isinstance(value, list) else value
                    for key, value in payload.items()
                    if isinstance(value, (list, dict))})
    text = json.dumps(ordered, default=str, ensure_ascii=False)
    for rows in _SAMPLE_ROWS:
        candidate = json.dumps(_shrink(ordered, rows), default=str, ensure_ascii=False)
        text = candidate
        if len(candidate) <= MAX_TOOL_CHARS:
            return candidate
    return text[:MAX_TOOL_CHARS] + "…[truncated]"


def refs_from(payload, into: set[str] | None = None) -> set[str]:
    """Every identifier a tool payload exposes, at any depth."""
    found = into if into is not None else set()
    if len(found) >= MAX_REFS:
        return found
    if isinstance(payload, dict):
        for key, value in payload.items():
            if key in ID_KEYS and isinstance(value, (str, int)) and str(value).strip():
                found.add(str(value))
            else:
                refs_from(value, found)
    elif isinstance(payload, list):
        for item in payload[:200]:
            refs_from(item, found)
    return found


@dataclass
class Fact:
    specialist: str
    tool: str
    args: dict
    payload: dict
    refs: set[str] = field(default_factory=set)
    fingerprint: str = ""

    def __post_init__(self) -> None:
        if not self.refs:
            self.refs = refs_from(self.payload)
        if not self.fingerprint:
            self.fingerprint = digest({"tool": self.tool, "args": self.args,
                                       "payload": self.payload})

    @property
    def key(self) -> str:
        """`tool:args` — the cache key D19 asks for."""
        return f"{self.tool}:{json.dumps(self.args, sort_keys=True, default=str)}"


@dataclass
class Claim:
    text: str
    level: str = "hypothesis"          # hypothesis | observed | validated
    evidence_refs: list[str] = field(default_factory=list)
    specialist: str = ""
    invalid: bool = False

    def as_dict(self) -> dict:
        return {"text": self.text, "level": self.level,
                "evidence_refs": self.evidence_refs, "specialist": self.specialist,
                "invalid": self.invalid}


@dataclass
class AgentState:
    question: str
    label: str = "posture"
    profile: str = "palantir"
    facts: list[Fact] = field(default_factory=list)
    claims: list[Claim] = field(default_factory=list)
    open_questions: list[str] = field(default_factory=list)
    #: Specialists the budget refused to run. Kept apart from `open_questions` because
    #: a question is something the data cannot answer and this is something the *plan*
    #: was not allowed to ask — and the ledger has to show both.
    skipped: list[str] = field(default_factory=list)
    visited: set[str] = field(default_factory=set)
    steps: int = 0
    empty_steps: int = 0

    # ── facts ──────────────────────────────────────────────────────────────
    def has_fact(self, tool: str, args: dict | None = None) -> bool:
        key = f"{tool}:{json.dumps(args or {}, sort_keys=True, default=str)}"
        return any(fact.key == key for fact in self.facts)

    def add_fact(self, fact: Fact) -> bool:
        """Append unless the same tool+args was already read. True when new."""
        if any(existing.key == fact.key for existing in self.facts):
            return False
        self.facts.append(fact)
        return True

    def facts_from(self, specialist: str) -> list[Fact]:
        return [fact for fact in self.facts if fact.specialist == specialist]

    def refs(self) -> set[str]:
        found: set[str] = set()
        for fact in self.facts:
            found |= fact.refs
        return found

    def purls(self) -> list[str]:
        out = []
        for fact in self.facts:
            for ref in fact.refs:
                if ref.startswith("pkg:") and ref not in out:
                    out.append(ref)
        return out[:20]

    # ── claims ─────────────────────────────────────────────────────────────
    def add_claim(self, claim: Claim) -> None:
        for existing in self.claims:
            if existing.text.strip() == claim.text.strip():
                return
        self.claims.append(claim)

    def claims_mentioning(self, needle: str) -> list[Claim]:
        needle = needle.lower()
        return [claim for claim in self.claims if needle in claim.text.lower()]

    def affected(self) -> bool:
        return any("affected" in claim.text.lower() and "not_affected" not in
                   claim.text.lower() for claim in self.claims)

    def validate_refs(self, known: set[str] | None = None) -> int:
        """Downgrade every claim citing an id no tool returned. Returns how many.

        This is D21 in code: the model may write prose, it may not invent a
        `finding_id`. A claim that fails here survives as a hypothesis, so the
        answer can still say "I think so" — it just cannot say "look at F-123".
        """
        universe = known if known is not None else self.refs()
        downgraded = 0
        for claim in self.claims:
            missing = [ref for ref in claim.evidence_refs if ref not in universe]
            if missing:
                claim.invalid = True
                claim.level = "hypothesis"
                downgraded += 1
        return downgraded

    # ── prompt material ────────────────────────────────────────────────────
    def summary(self) -> str:
        """A compact, delimited view of what is known. Data, not instructions."""
        lines = [f"label: {self.label}",
                 f"specialists run: {', '.join(sorted(self.visited)) or 'none'}"]
        if self.open_questions:
            lines.append("open questions: " + " | ".join(self.open_questions[:8]))
        if self.purls():
            lines.append("candidate components: " + ", ".join(self.purls()))
        for claim in self.claims[:12]:
            lines.append(f"claim [{claim.level}{' INVALID' if claim.invalid else ''}]: "
                         f"{claim.text} (refs: {', '.join(claim.evidence_refs[:6]) or 'none'})")
        for fact in self.facts[-6:]:
            try:
                body = json.dumps(fact.payload, default=str)
            except (TypeError, ValueError):
                body = str(fact.payload)
            lines.append(f"fact {fact.tool} {json.dumps(fact.args, default=str)}: "
                         f"{body[:900]}")
        text = "\n".join(lines)
        return text[:MAX_SUMMARY_CHARS]

    def as_dict(self) -> dict:
        return {"label": self.label, "steps": self.steps,
                "visited": sorted(self.visited), "skipped": list(self.skipped),
                "facts": [{"specialist": fact.specialist, "tool": fact.tool,
                           "args": fact.args, "fingerprint": fact.fingerprint,
                           "refs": sorted(fact.refs)[:40]} for fact in self.facts],
                "claims": [claim.as_dict() for claim in self.claims],
                "open_questions": self.open_questions}


BRIEF_TOOL_CHARS = 600
#: A **single record** a later step asked for by id belongs in the prompt, not behind a
#: pointer: `finding_detail` is the call whose whole value is `proof_request`,
#: `reproduction` and `evidence`. Dropping the body there made the model report "the
#: detail came back with references only, no proof body" about a row it had just read —
#: the pointer was the reason, not the data. Lists still travel as pointers.
BRIEF_FULL_CHARS = 2600


def _compact(value):
    """The payload without its empty fields: a finding carries ~60 keys, most null."""
    if isinstance(value, dict):
        return {key: _compact(item) for key, item in value.items()
                if item not in (None, "", [], {})}
    if isinstance(value, list):
        return [_compact(item) for item in value]
    return value


def brief_result(payload, tool: str = "") -> str:
    """What a later step needs: the record when it is small, a pointer when it is not.

    The raw rows are already in `run_state` and in the artefact; re-sending a 200-row
    page on every step is what turned a 3-step run into 26k input tokens. But a pointer
    is only honest for a *list*: a single record read by id is the answer, so it is sent
    compacted up to `BRIEF_FULL_CHARS`, and only past that does it become a pointer.
    """
    if not isinstance(payload, dict):
        payload = {"data": payload}
    compact = _compact(payload)
    body = json.dumps(compact, default=str, ensure_ascii=False)
    if len(body) <= BRIEF_FULL_CHARS:
        return body
    scalars = {key: value for key, value in payload.items()
               if key in {"total", "count", "limit", "offset", "coverage", "status"}
               and isinstance(value, (int, float, str)) and len(str(value)) < 200}
    text = json.dumps({**scalars, "tool": tool,
                       "refs": sorted(refs_from(payload))[:8],
                       "note": "full result kept in run_state; ask again only if the "
                               "summary is not enough"},
                      default=str, ensure_ascii=False)
    return text[:BRIEF_TOOL_CHARS]

"""The router: deterministic rules over the run's state (D20, D47).

The model does not choose the next step. Code does, from the question's shape and the
facts collected so far. Two reasons, both practical:

* A plan that changes with the temperature is a plan you cannot test. The tests here
  assert the plan, not the prose.
* A model that can decide to run `applicability` before `estate.inventory` will, and
  then it is guessing at component names instead of reading them.

The model still classifies the question at entry (D20) — one cheap call when the text
is ambiguous, none when a CVE or a purl is right there. Everything after that is code,
until `evidence.report` writes the answer.
"""
from __future__ import annotations

import re

CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)
PURL_RE = re.compile(r"\bpkg:[a-z0-9.+-]+/", re.IGNORECASE)
#: A package name with an explicit version, e.g. `lodash 4.17.20`, `django==4.2`.
PINNED_RE = re.compile(r"\b[a-z][a-z0-9._-]{2,}[\s@=]{1,2}\d+\.\d+", re.IGNORECASE)
COUNTING_RE = re.compile(
    r"\b(cu[aá]nt[oa]s?|how many|total|count|top|resumen|posture|estado)\b",
    re.IGNORECASE)

LABELS = ("cve", "estate", "posture")

#: The only plan that costs more than one specialist. A lookup is one specialist and
#: its own prose (D47, L1); an investigation is the chain, and only it ends in a
#: report (L2).
CVE_PLAN = ["intel.cve", "estate.inventory", "applicability", "remediation",
            "evidence.report"]
SINGLE_PLANS = {"estate": ["estate.inventory"], "posture": ["estate.inventory"]}


def classify(question: str) -> str:
    """Which plan the question deserves. Regex first, model never (for now).

    Deterministic on purpose: a wrong label costs an extra specialist (cheap), a
    non-deterministic label costs a test that passes on Mondays.
    """
    text = question or ""
    if CVE_RE.search(text):
        return "cve"
    if PURL_RE.search(text) or PINNED_RE.search(text):
        return "estate"
    if COUNTING_RE.search(text):
        return "posture"
    return "posture"


def plan(state) -> list[str]:
    """The specialists this run will visit, in order."""
    return list(CVE_PLAN if state.label == "cve" else SINGLE_PLANS.get(state.label,
                                                                     ["estate.inventory"]))


def should_run(name: str, state) -> tuple[bool, str]:
    """Skip a specialist that would spend tokens asking a question we cannot answer.

    The skip is recorded as an open question, never as silence (D57): a missing
    candidate, a missing grant and a missing provider all have names.
    """
    if name == "intel.cve" and not CVE_RE.search(state.question or ""):
        return False, "no CVE in the question"
    if name == "applicability" and not state.purls():
        return False, ("no candidate component found, so applicability has nothing to "
                       "test")
    if name == "remediation" and not state.affected():
        return False, "no claim says a deployment is affected"
    if name in state.visited:
        return False, "already visited"
    return True, ""


def cves(question: str) -> list[str]:
    return [match.upper() for match in CVE_RE.findall(question or "")]

"""Specialists: reusable units of work, declared as data (D40, D46).

A specialist is not a profile and not an agent. It is a *contract*: the tools it may
touch, the question it answers, and the shape of what it must hand back. The
orchestrator decides which one runs; the specialist never decides it can run.

Three executor classes exist (D46). Two are here:

* `query` — deterministic; no model. It exists so the cheapest questions never cost a
  token and can never be talked out of the truth.
* `analyst` — a model over facts, required to cite ids it actually read.

`field` (model with tools inside Shauron) is F4: nothing in this file may reach the
network, and the catalog it draws from is read-only by construction.
"""
from __future__ import annotations

SPECIALISTS: dict[str, dict] = {
    "intel.cve": {
        "name": "intel.cve",
        "executor": "analyst",
        "tools": ["advisory_resolve", "intel_kev", "intel_kev_catalog", "intel_epss",
                  "vulnerabilities_search"],
        "wants": ["kev: exploited in the wild?", "epss: probability",
                  "the advisory facts that scope the versions"],
        "sees": [],
        "prompt": (
            "You are intel.cve. Establish the external facts about one vulnerability: "
            "is it in CISA KEV, what is its EPSS, and what does the estate already "
            "record about it. Call the tools; do not recall CVEs from memory. If a "
            "tool answers 404, that is 'no intel record', not 'not exploited'.\n"
            "When the operator names it with a nickname (node2shell, log4shell) or a "
            "product, resolve it with `advisory_resolve` before concluding anything: "
            "the famous name is not in any row, so 'no match for that word' means the "
            "name is unresolved, never that the estate is clean.\n"
        ),
    },
    "estate.inventory": {
        "name": "estate.inventory",
        "executor": "analyst",
        "tools": ["advisory_resolve", "intel_kev_catalog", "components_impact",
                  "deployment_chain", "projects_list", "vulnerabilities_search",
                  "findings_search", "assets_search"],
        "wants": ["where it lives: purls, builds, deployments, environments",
                  "counts, when the question is a count"],
        "sees": [],
        "prompt": (
            "You are estate.inventory. Answer from the platform's rows: which "
            "components exist, in which builds, deployed where, and what the estate "
            "already knows about them. Never confuse 'in a repository' with 'running "
            "in production'. Cite the ids you read. An empty result is `unknown`, not "
            "'clean'.\n"
            "If the operator refers to a vulnerability by a nickname or a product "
            "instead of a CVE id, call `advisory_resolve` first: it maps the lore "
            "(node2shell, log4shell) to the CVE and returns what the estate holds "
            "for it. Searching the literal nickname is not the same question.\n"
            "A question about what appeared *in the world* — 'what came out this "
            "week', 'anything new', 'what is in the KEV now' — is `intel_kev_catalog` "
            "with `since` and `matched=true`, not a scan of this estate's findings: "
            "the catalog knows rows before any finding exists.\n"
            "Ids do not belong in your prose: they render as chips under the answer and "
            "travel in `evidence_refs`. Name the row, the count and the consequence.\n"
            "A count that adds the same packaged component across two projects is not a "
            "bigger finding. Report `unique` and `occurrences` separately and never "
            "present the sum as a total — two projects shipping the same image is one "
            "package with two deployments.\n"
            "When something is unknown, say which kind: the estate does not hold it, or "
            "the tool answer came back truncated. The second is a limit of this step, "
            "not a gap in the data, and calling it a gap is how an empty table gets read "
            "as clean.\n"
            "`findings_search` returns rows without proof bodies: open one with "
            "`finding_detail` before claiming the estate holds no recorded PoC — a "
            "pentest finding carries `proof_request`/`proof_response`.\n"
            "A gap a run could close — a deployment with `last_checked_at: null`, a "
            "version nobody verified — is not a dead end: tell the operator once that "
            "asking `@angmar <finding id>` writes a mission that waits for approval.\n"
        ),
    },
    "applicability": {
        "name": "applicability",
        "executor": "analyst",
        "tools": ["exposure_verdict", "deployment_chain"],
        "wants": ["affected | not_affected | unknown per deployment, with the reason",
                  "the missing edge when it is unknown"],
        "sees": ["the candidates estate.inventory found"],
        "prompt": (
            "You are applicability. For each candidate component, call "
            "exposure_verdict and report what it returns, per deployment. Keep the "
            "four questions apart: the component is present, the code path is "
            "reachable, the deployment is exposed, and exploitation has been "
            "demonstrated. A vulnerable version is not an exploitable deployment. "
            "Name the edge that is unknown; never answer not_affected without one.\n"
        ),
    },
    "remediation": {
        "name": "remediation",
        "executor": "analyst",
        "tools": ["vulnerabilities_search", "components_impact", "deployment_chain"],
        "wants": ["what to change, where, and what it unblocks"],
        "sees": ["the applicability verdict"],
        "prompt": (
            "You are remediation. For the deployments that came back affected or "
            "unknown, state the smallest change that removes the exposure: which "
            "version to move to, which build to rebuild, which deployment to "
            "re-check. Do not invent a fixed version you did not read.\n"
        ),
    },
    "evidence.report": {
        "name": "evidence.report",
        "executor": "analyst",
        "tools": [],
        "wants": ["one answer, citing the ids that survived"],
        "sees": ["every claim and fact of this run"],
        "prompt": (
            "You are evidence.report. Write the final answer for the operator from the "
            "claims below: lead with the answer, then the evidence ids. Claims marked "
            "INVALID cite ids no tool returned — either drop them or state them as "
            "hypotheses with no id. If the claims do not settle the question, say "
            "`unknown` and name the missing data. No new facts, no new tools, no "
            "padding.\n"
            "Answers are read on a screen that renders the ids as chips: do not paste "
            "them into the prose, and do not append a list of ids at the end. If the "
            "deployment is public, unauthenticated, or the CVE is in KEV with a past "
            "due date, say that in the first sentence — it is the reason the reader is "
            "here.\n"
            "Distinguish `unknown` because the estate lacks the row from `unknown` "
            "because this run ran out of calls: the second one names the tool that would "
            "settle it and does not blame the data.\n"
            "A reader who has just learned something should be able to act on it: after "
            "the prose, emit one fenced json block with at most three `suggestions`, "
            "chosen only from `ask`, `open_screen`, `validate_finding` and `open_run` "
            "(`validate_finding` needs a finding id a tool returned in this run; "
            "`open_run` needs this run's id). No block when nothing useful applies — an "
            "answer with no buttons is honest, a button that dead-ends is not."),
    },
}


def get(name: str) -> dict | None:
    return SPECIALISTS.get(name)


def tools_for(name: str) -> list[str]:
    row = SPECIALISTS.get(name)
    return list(row["tools"]) if row else []


def names() -> list[str]:
    return list(SPECIALISTS)

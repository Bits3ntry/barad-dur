"""The prompt budget: how much of a tool result the model actually needs.

These bounds are not cosmetic. Measured on the live estate, the same question cost
18k and 40k input tokens on two different runs: the difference was the same rows being
re-sent on every step, not new evidence.
"""
import json
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BACKEND_ROOT / "src"))

from backend.app.ai import state  # noqa: E402


def test_a_large_tool_result_is_bounded_and_keeps_the_scalars():
    payload = {"total": 900, "coverage": "full",
               "rows": [{"id": f"x{i}", "name": "n" * 200} for i in range(900)]}
    text = state.projection(payload)
    assert len(text) <= state.MAX_TOOL_CHARS
    assert '"total": 900' in text
    assert '"coverage": "full"' in text


def test_a_big_tool_result_travels_as_a_summary_not_a_pointer():
    payload = {"total": 900, "rows": [{"id": f"x{index}", "name": "n" * 200}
                                      for index in range(500)],
               "components": [{"purl": f"pkg:npm/x{index}@1"} for index in range(500)]}
    text = state.brief_result(payload, "project_inventory")
    body = json.loads(text)
    assert len(text) <= state.BRIEF_SUMMARY_CHARS
    assert body["tool"] == "project_inventory"
    assert body["total"] == 900
    assert body["summary"]["rows"]["count"] == 500
    assert body["summary"]["components"]["sample"]["purl"] == "pkg:npm/x0@1"
    assert "narrower query" in body["note"]
    assert "n" * 200 not in text, "a summary is not a copy of the page"


def test_a_deployment_chain_summary_carries_the_completeness_notes():
    """The chain is the payload whose *reason* is `completeness.unknown_edges`.

    Sent as eight bare refs, a run answered "the deployment chain came back as eight
    references with no content" — reporting our projection as a gap in the estate. The
    summary keeps the notes and the counts, so the answer can say "no deployment runs
    this version" when that is what the estate said.
    """
    payload = {
        "query": {"purl": "pkg:pypi/django@2.2.0", "component": None,
                  "project": None, "asset": None},
        "as_of": "2026-11-17T16:32:11+00:00",
        "edges": {
            "components": [{"id": "76025d4d", "name": "django", "version": "2.2.0"}],
            "builds": [],
            "deployments": [],
            "assets": [],
            "observations": [],
            "findings": [{"id": f"f{index}", "kind": "vulnerability"}
                         for index in range(120)],
        },
        "completeness": {"has_sbom": False, "has_deployment": False,
                         "has_asset": False, "has_observation": False,
                         "unknown_edges": ["no build links this component to a version",
                                           "no deployment runs this version"],
                         "truncated": {}},
        "ages_days": {"sbom": None, "deployment_check": None, "observation": None},
    }
    body = json.loads(state.brief_result(payload, "deployment_chain"))
    assert body["summary"]["edges"]["findings"]["count"] == 120
    assert body["summary"]["edges"]["deployments"] == [], \
        "an empty edge is an answer, not a field to drop"
    notes = body["summary"]["completeness"]["unknown_edges"]
    assert any("no deployment runs this version" in note for note in notes)
    assert body["summary"]["completeness"]["has_deployment"] is False, \
        "a boolean keeps its type"


def test_a_single_record_keeps_its_body_on_a_later_step():
    """The follow-up step must see the detail it asked for.

    `finding_detail` exists for `proof_request`/`reproduction`/`evidence`. On a second
    tool round the orchestrator used to send every result as a pointer, so the model read
    "detail: references only" and told the operator the estate held no proof of concept —
    about a row it had just opened.
    """
    detail = {"id": "6875cbb3b70a45209530fa6712cfbde1",
              "title": "Django SQL injection via _connector",
              "severity": "CRITICAL", "status": "open",
              "proof_request": None, "proof_response": None,
              "reproduction": "QuerySet.extra(kwargs={'_connector': ...})",
              "evidence": "static analysis", "line": None, "path": "db/models/query.py",
              "cvss_score": 9.1, "exploit_state": "none",
              # the fat, null half of every finding payload
              **{f"empty_{index}": None for index in range(40)}}
    text = state.brief_result(detail, "finding_detail")
    body = json.loads(text)
    assert body["reproduction"].startswith("QuerySet.extra")
    assert body["severity"] == "CRITICAL"
    assert "proof_request" not in body, "a null field is noise, not information"


def test_the_run_summary_stays_inside_its_budget():
    agent = state.AgentState(question="q", label="l")
    for index in range(40):
        agent.add_fact(state.Fact(specialist="s", tool="t",
                                  args={"i": index},
                                  payload={"body": "x" * 500},
                                  refs={f"r{index}"}))
    assert len(agent.summary()) <= state.MAX_SUMMARY_CHARS


def test_digest_handles_mixed_mapping_keys_from_a_tool_payload():
    """A tool result may carry a null JSON-object key from an external source.

    The digest is only a receipt/cache key, but it must not terminate the whole run
    while attempting to canonicalize that result.
    """
    payload = {None: "unknown", "title": "SQL injection", 3: {"id": "F-3"}}
    reordered = {3: {"id": "F-3"}, "title": "SQL injection", None: "unknown"}

    assert state.digest(payload) == state.digest(reordered)
    assert state.Fact(specialist="estate.inventory", tool="findings_search",
                      args={"q": "sql injection"}, payload=payload).fingerprint

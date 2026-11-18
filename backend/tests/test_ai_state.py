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


def test_a_brief_result_is_a_pointer_not_a_copy():
    payload = {"total": 900, "rows": [{"id": i} for i in range(500)],
               "components": [{"purl": f"pkg:npm/x{i}@1"} for i in range(500)]}
    text = state.brief_result(payload, "project_inventory")
    assert len(text) <= state.BRIEF_TOOL_CHARS
    assert "project_inventory" in text
    assert "run_state" in text, "it must say where the full result lives"
    assert "note" in json.loads(text)


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

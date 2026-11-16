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


def test_the_run_summary_stays_inside_its_budget():
    agent = state.AgentState(question="q", label="l")
    for index in range(40):
        agent.add_fact(state.Fact(specialist="s", tool="t",
                                  args={"i": index},
                                  payload={"body": "x" * 500},
                                  refs={f"r{index}"}))
    assert len(agent.summary()) <= state.MAX_SUMMARY_CHARS

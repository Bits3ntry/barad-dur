"""The baseline file is an artefact, not a note: it has to stay checkable.

`ai_budget_baseline.json` carries two kinds of number, and they must not blur:

* `before` / `target` — the deterministic budget of a stubbed run (a test ceiling);
* `measured` — one real run against a real estate and provider, kept as the anchor a
  regression must not drift from.

This test keeps the second kind honest: a measurement without its arithmetic (or with
tokens that do not add up) is a claim, and the whole point of the ledger is that claims
are checkable.
"""
import json
from pathlib import Path

BASELINE = Path(__file__).parent / "ai_budget_baseline.json"


def test_every_entry_declares_a_ceiling():
    data = json.loads(BASELINE.read_text())
    questions = {key: value for key, value in data.items() if not key.startswith("_")}
    assert questions, "a baseline with no question is a file nobody uses"
    for question, entry in questions.items():
        assert isinstance(entry.get("target"), int) and entry["target"] > 0, question


def test_a_measured_run_explains_itself():
    data = json.loads(BASELINE.read_text())
    measured = {key: entry["measured"] for key, entry in data.items()
                if isinstance(entry, dict) and "measured" in entry}
    assert measured, "the flagship question keeps the live measurement that anchors it"
    for question, entry in measured.items():
        assert entry.get("status") in {"answered", "stopped_budget",
                                       "stopped_max_steps", "failed"}, question
        assert entry.get("at") and entry.get("provider") and entry.get("model"), question
        assert entry["steps"] > 0 and entry["tool_calls"] >= 0, question
        if entry["status"] == "answered":
            # A measured answer has to say what it read and what it cost.
            assert entry.get("citations", 0) > 0, question
            assert entry["tokens_in"] + entry["tokens_out"] > 0, question
            assert entry.get("chain"), question

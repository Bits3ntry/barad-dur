"""The canonical questions must cost a fraction of what they cost before.

Measured baseline (2026-11-09, two runs per question): the same question answered with
the same input cost 18.144 and 40.012 tokens. That spread is repetition, not context —
so the bound is relative to the measured baseline, never an absolute ceiling that would
cut a legitimate question the day the estate grows.
"""
import json
import os
from pathlib import Path

import pytest

BASELINE_PATH = Path(__file__).with_name("ai_budget_baseline.json")
#: Each question carries its own target. A single factor is wrong in both directions:
#: the question that was wasting 40k must lose more than half, and the one that already
#: cost 3,7k must not be squeezed just because a global ratio was fashionable.
MARGIN = float(os.environ.get("AI_BUDGET_MARGIN", "1.0"))


def _baseline() -> dict:
    return json.loads(BASELINE_PATH.read_text())


@pytest.mark.skipif(not os.environ.get("AI_BUDGET_KEY"),
                    reason="needs a live provider key (set AI_BUDGET_KEY)")
def test_the_canonical_questions_cost_a_fraction_of_the_baseline():
    import httpx
    key = os.environ["AI_BUDGET_KEY"]
    base = os.environ.get("PLATFORM_URL", "http://127.0.0.1:8090")
    with httpx.Client(base_url=base, timeout=180) as client:
        for question, limits in _baseline().items():
            body = (client.post("/api/v1/ai/runs",
                                      headers={"X-API-Key": key},
                                     json={"question": question,
                                           "mode": "ask"})).json()
            run = body.get("data") or body
            total = (run.get("tokens_in") or 0) + (run.get("tokens_out") or 0)
            allowed = int(limits["target"] * MARGIN)
            assert total <= allowed, (
                f"{question!r}: {total} tokens, target {limits['target']} "
                f"(was {limits['before']})")

"""Capability, not prose: every answer must still contain the facts it is about.

An optimisation that lowers tokens by making the model know less is a product cut with a
better invoice. This set is the merge gate: 4/4 before and after, or the change that
lowered it is reverted.
"""
import os

import pytest

GOLDEN = [
    ("¿cuántos findings abiertos tengo?", ["finding"]),
    ("¿nos afecta node2shell?", ["CVE-2026-111497", "node"]),
    ("¿qué proyectos hay?", ["aurea"]),
    ("¿cuántos assets tengo por tipo?", ["asset"]),
]


@pytest.mark.skipif(not os.environ.get("AI_BUDGET_KEY"),
                    reason="needs a live provider key (set AI_BUDGET_KEY)")
def test_the_answer_still_contains_what_it_is_about():
    import httpx
    key = os.environ["AI_BUDGET_KEY"]
    base = os.environ.get("PLATFORM_URL", "http://127.0.0.1:8090")
    with httpx.Client(base_url=base, timeout=180) as client:
        for question, expected in GOLDEN:
            body = (client.post("/api/v1/ai/runs",
                                      headers={"X-API-Key": key},
                                     json={"question": question,
                                           "mode": "ask"})).json()
            run = body.get("data") or body
            assert run["status"] == "answered", f"{question}: {run.get('stop_reason')}"
            answer = (run.get("answer") or "").lower()
            missing = [frag for frag in expected if frag.lower() not in answer]
            assert not missing, f"{question}: answer lost {missing}"

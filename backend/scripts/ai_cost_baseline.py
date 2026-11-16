"""Measure the canonical questions against a live platform.

Usage: .venv/bin/python backend/scripts/ai_cost_baseline.py <api-key> [--repeat N]

Reads PLATFORM_URL (default http://127.0.0.1:8090). Prints one JSON line per attempt and
a summary per question: min / max / spread. The spread is the interesting number: the
same question answered twice at 16k and 21k means the cost is repetition, not context.
"""
import json
import os
import statistics
import sys
import urllib.request

QUESTIONS = [
    "¿cuántos findings abiertos tengo?",
    "¿nos afecta node2shell?",
    "¿qué proyectos hay?",
]


def call(path: str, key: str, payload: dict | None = None) -> dict:
    url = os.environ.get("PLATFORM_URL", "http://127.0.0.1:8090") + path
    data = json.dumps(payload).encode() if payload else None
    request = urllib.request.Request(url, data=data, headers={
        "X-API-Key": key, "content-type": "application/json"})
    with urllib.request.urlopen(request, timeout=180) as response:
        return json.loads(response.read().decode())


def main() -> int:
    args = [item for item in sys.argv[1:] if not item.startswith("--")]
    if not args:
        print("usage: ai_cost_baseline.py <api-key> [--repeat N]", file=sys.stderr)
        return 2
    key = args[0]
    repeat = 1
    if "--repeat" in sys.argv:
        repeat = int(sys.argv[sys.argv.index("--repeat") + 1])

    summary = {}
    for question in QUESTIONS:
        totals = []
        for _ in range(repeat):
            body = call("/api/v1/ai/runs", key, {"question": question, "mode": "ask"})
            run = body.get("data") or body
            total = (run.get("tokens_in") or 0) + (run.get("tokens_out") or 0)
            totals.append(total)
            print(json.dumps({"q": question, "status": run.get("status"),
                              "steps": run.get("steps"),
                              "tokens_in": run.get("tokens_in"),
                              "tokens_out": run.get("tokens_out")}, ensure_ascii=False))
        low, high = min(totals), max(totals)
        summary[question] = {
            "min": low, "max": high,
            "spread": round((high - low) / max(1, low), 3),
            "median": int(statistics.median(totals)),
        }
    print(json.dumps({"summary": summary}, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())

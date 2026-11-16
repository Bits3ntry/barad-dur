"""The agent harness: decisions, budgets, gates and the thread.

Nothing here imports a router. The router calls the harness; the harness takes a
`Session` and plain values, so it can be tested without an HTTP client and reused by
the worker path later.
"""

from backend.app.harness import budgets, events, evidence, gates, policy, runs  # noqa: F401

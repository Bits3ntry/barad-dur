"""Authority can narrow, never widen.

An agent declares tools; a child inherits the intersection of what its parent may call
and what it asks for. `None` means inherit, `[]` means none — a distinction that keeps
"no opinion" different from "explicitly nothing".
"""

from __future__ import annotations

import json

from backend.app import models


def _names(raw: str | None) -> list[str] | None:
    if raw is None:
        return None
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return []
    return [item for item in value if isinstance(item, str)] if isinstance(value, list) else []


def inherited(session, spec_slug: str, *, depth: int = 0) -> list[str] | None:
    """The tool set a spec inherits from its ancestors, or None when unbounded."""
    if depth > 8:
        return []
    spec = session.query(models.AgentSpec).filter_by(slug=spec_slug).one_or_none()
    if spec is None:
        return []
    own = _names(spec.allowed_tools)
    parent = _names(None)
    if spec.parent_slug:
        parent = inherited(session, spec.parent_slug, depth=depth + 1)
    if own is None:
        return parent
    if parent is None:
        return own
    return [name for name in own if name in parent]


def effective_tools(session, spec_slug: str, *, catalogue: list[str]) -> list[str]:
    """What this agent may actually call: its declaration, narrowed by its ancestors."""
    spec = session.query(models.AgentSpec).filter_by(slug=spec_slug).one_or_none()
    declared = _names(spec.tools if spec else None) or []
    allowed = inherited(session, spec_slug) if spec and spec.parent_slug else None
    known = set(catalogue)
    chosen = declared if allowed is None else [name for name in declared if name in allowed]
    return [name for name in chosen if name in known]


def assert_allowed(session, spec_slug: str, tool: str, *, catalogue: list[str]) -> None:
    """Raise when the tool is outside the agent's effective set — at dispatch, not in prose."""
    if tool not in effective_tools(session, spec_slug, catalogue=catalogue):
        raise PermissionError(
            f"{spec_slug} may not call {tool}: not in its effective tool set")

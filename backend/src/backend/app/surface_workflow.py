"""A workflow an organisation writes itself, validated by the engine's rules.

The catalog is *shauron's*: nine profiles, twenty tools, and a loader that refuses
an incoherent combination. A custom workflow is not a fork of that catalog — it is
the same document shape, checked against the same published rules, so the platform
can plan it and the CLI can run it without either learning a second dialect.

Every rejection is a code plus the value that failed (`{"code": ..., "at": ...}`),
because the console translates and the operator has to know which stage is wrong —
"invalid workflow" is a message that costs another attempt.

Rules come from `surface_catalog.json["rules"]`, published by
`scripts/sync_surface_catalog.py` from `shauron/catalog/__init__.py` itself.
"""
from __future__ import annotations

import json
import re

from backend.app import models, surface_plan

SLUG = re.compile(r"^[a-z0-9][a-z0-9._-]{2,95}$")
PREFIX = "org."
DEFAULT_LIMITS = {"rate_per_second": 20, "timeout_s": 300, "concurrency": 4}


class WorkflowError(ValueError):
    """A document the engine would refuse, named as such."""

    def __init__(self, code: str, **detail):
        super().__init__(code)
        self.code = code
        self.detail = detail

    def payload(self) -> dict:
        return {"code": self.code, **self.detail}


def rules() -> dict:
    published = surface_plan.rules()
    if not published:
        # A catalog published before the rules existed can plan but cannot
        # validate a document; refuse loudly instead of guessing the constants.
        raise WorkflowError("workflow.rules_unpublished")
    return published


def tools() -> dict[str, dict]:
    return surface_plan.catalog().get("tools") or {}


def _level_rank() -> dict:
    return rules().get("level_rank") or {}


def normalize(document: dict, *, slug: str) -> dict:
    """Validate and canonicalise. Returns the document the platform will store."""
    published = rules()
    levels = published.get("levels") or []
    planes = published.get("planes") or []
    kinds = published.get("target_kinds") or []
    known_tools = tools()

    if not SLUG.match(slug):
        raise WorkflowError("workflow.bad_slug", at=slug)
    label = str(document.get("label") or "").strip()
    if len(label) < 2:
        raise WorkflowError("workflow.label_required")

    level = document.get("level")
    if level not in levels:
        raise WorkflowError("workflow.bad_level", at=level)

    kind = document.get("target_kind") or "domain"
    if kind not in kinds:
        raise WorkflowError("workflow.bad_kind", at=kind)

    plane = [str(item) for item in (document.get("plane") or ["cloud"])]
    unknown = [item for item in plane if item not in planes]
    if not plane or unknown:
        raise WorkflowError("workflow.bad_plane", at=unknown or plane)

    raw_stages = document.get("stages") or []
    if not raw_stages:
        raise WorkflowError("workflow.stage_empty")

    # The engine's own walk: a stage reads from `targets` or from a stage that
    # came before it, and an id may not repeat.
    seen: list[str] = []
    stages: list[dict] = []
    ceiling = _level_rank().get(level)
    for index, raw in enumerate(raw_stages):
        stage_id = str(raw.get("id") or "").strip()
        if not SLUG.match(stage_id):
            raise WorkflowError("workflow.bad_slug", at=stage_id, index=index)
        if stage_id in seen:
            raise WorkflowError("workflow.stage_duplicate", at=stage_id)
        source = str(raw.get("from") or "targets").strip()
        if source != "targets" and source not in seen:
            raise WorkflowError("workflow.stage_unknown_from", at=source, stage=stage_id)
        if index == 0 and source != "targets":
            raise WorkflowError("workflow.stage_unknown_from", at=source, stage=stage_id)

        names = [str(name).strip() for name in (raw.get("tools") or [])]
        names = [name for name in names if name]
        if not names:
            raise WorkflowError("workflow.stage_tools_empty", stage=stage_id)
        for name in names:
            tool = known_tools.get(name)
            if tool is None:
                raise WorkflowError("workflow.unknown_tool", at=name, stage=stage_id)
            if kind not in (tool.get("targets") or []):
                raise WorkflowError("workflow.tool_wrong_target", at=name,
                                    stage=stage_id, target_kind=kind)
            tool_level = _level_rank().get(tool.get("level"))
            if ceiling is not None and tool_level is not None and tool_level > ceiling:
                raise WorkflowError("workflow.tool_above_level", at=name,
                                    stage=stage_id, tool_level=tool.get("level"),
                                    level=level)

        stages.append({"id": stage_id, "from": source, "tools": names})
        seen.append(stage_id)

    raw_limits = document.get("limits") or {}
    limits = {
        "rate_per_second": _bounded(raw_limits.get("rate_per_second"),
                                    DEFAULT_LIMITS["rate_per_second"], 1, 500),
        "timeout_s": _bounded(raw_limits.get("timeout_s"),
                              DEFAULT_LIMITS["timeout_s"], 5, 7200),
        "concurrency": _bounded(raw_limits.get("concurrency"),
                                DEFAULT_LIMITS["concurrency"], 1, 16),
    }

    return {
        "name": slug,
        "label": label,
        "question": str(document.get("question") or "").strip(),
        "target_kind": kind,
        "level": level,
        "plane": plane,
        "stages": stages,
        "limits": limits,
    }


def _bounded(value, fallback: int, low: int, high: int) -> int:
    try:
        number = int(value)
    except (TypeError, ValueError):
        return fallback
    if number < low:
        raise WorkflowError("workflow.limit_out_of_range", at=number, low=low, high=high)
    if number > high:
        raise WorkflowError("workflow.limit_out_of_range", at=number, low=low, high=high)
    return number


def from_catalog(name: str) -> dict:
    """A catalog profile as an editable document — the starting point, unedited."""
    source = surface_plan.profile(name)
    if source is None:
        raise WorkflowError("workflow.unknown_profile", at=name)
    return {
        "name": source.get("name"),
        "label": source.get("label") or source.get("name"),
        "question": source.get("question") or "",
        "target_kind": source.get("target_kind") or "domain",
        "level": source.get("level"),
        "plane": list(source.get("plane") or ["cloud"]),
        "stages": [{"id": stage["id"], "from": stage.get("from") or "targets",
                    "tools": list(stage.get("tools") or [])}
                   for stage in source.get("stages") or []],
        "limits": dict(source.get("limits") or DEFAULT_LIMITS),
    }


def document_for(row: models.ScanWorkflow) -> dict:
    """The stored row as the document the resolver expects."""
    return {
        "name": row.slug,
        "label": row.label,
        "question": row.question or "",
        "target_kind": row.target_kind,
        "level": row.level,
        "plane": json.loads(row.plane or "[]"),
        "stages": json.loads(row.stages or "[]"),
        "limits": json.loads(row.limits or "{}"),
    }

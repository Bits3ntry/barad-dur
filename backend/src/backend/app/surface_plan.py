"""Surface plans: what a profile can actually do, resolved against the engine.

The catalog is the *published* copy of `shauron/catalog` (see
`scripts/sync_surface_catalog.py`): the platform owns the composition, Shauron
owns the execution and validates the plan against its own copy. They meet on the
catalog hash, so drift is visible instead of silent.

Four states per step, each with the action that fixes it:

    allow          the engine grants the capability for these targets
    not_authorized the grant does not reach this capability
    not_accepted   the organisation turned the tool off
    not_installed  the executor cannot run it (image/binary missing)

A profile is refused as a whole when its plane does not include the caller's
(`web.redteam` is cloud-only), with a plane reason — never a grant one, because a
grant would not help.
"""
from __future__ import annotations

import hashlib
import json
from functools import lru_cache
from pathlib import Path

from sqlalchemy.orm import Session

from backend.app import authorization, models

CATALOG_PATH = Path(__file__).with_name("surface_catalog.json")
PLAN_SCHEMA = "barad-plan-v1"
LEVEL_RANK = {"simple": 0, "advanced": 1, "redteam": 2}


@lru_cache(maxsize=1)
def catalog() -> dict:
    document = json.loads(CATALOG_PATH.read_text())
    document.setdefault("tools", {})
    document.setdefault("profiles", {})
    return document


def catalog_hash() -> str:
    document = catalog()
    payload = (json.dumps(document["tools"], sort_keys=True)
               + json.dumps(document["profiles"], sort_keys=True))
    return hashlib.sha256(payload.encode()).hexdigest()


def profile(name: str) -> dict | None:
    return catalog()["profiles"].get(name)


def tools_for(profile_document: dict) -> list[str]:
    return [tool for stage in profile_document.get("stages", [])
            for tool in stage.get("tools", [])]


def policy_disabled(session: Session, org_id: str) -> set[str]:
    """Tools the organisation has turned off. A policy input, not a truth about
    the catalog: its effect is frozen into the plan that gets recorded."""
    row = (session.query(models.PlatformSetting)
           .filter_by(name="surface_policy").first()) if hasattr(
               models, "PlatformSetting") else None
    if row is None:
        return set()
    try:
        document = json.loads(row.value or "{}")
    except (TypeError, ValueError):
        return set()
    return set(document.get("disabled") or [])


def _target_kind(targets: list[dict]) -> str:
    kinds = {str(target.get("type") or "domain") for target in targets}
    if len(kinds) == 1:
        return kinds.pop()
    for candidate in ("url", "domain", "ip", "cidr"):
        if candidate in kinds:
            return candidate
    return "domain"


def needs_grant(document: dict) -> bool:
    """Intrusive testing is never an override.

    An operator may scan their own host without a grant because typing a hostname
    is the same act as running nmap by hand. Sending payloads at it is not: it is
    the one thing the whole authorization model exists for, and an admin who can
    `admin_override` a redteam run has removed the only control that distinguishes
    us from a scanner anyone can point anywhere.
    """
    return document.get("level") == "redteam" or any(
        (catalog()["tools"].get(tool) or {}).get("capability") == "intrusive_testing"
        for stage in document.get("stages", [])
        for tool in stage.get("tools", []))


def resolve(session: Session, org: models.Organization,
            profile_name: str, targets: list[dict], *,
            plane: str = "cli", principal: str = authorization.COLLECTOR_PRINCIPAL,
            check_grants: bool = True, actor: str | None = None) -> dict:
    """Turn a profile into a plan, with every step's verdict and its reason."""
    document = profile(profile_name)
    if document is None:
        raise KeyError(f"unknown profile {profile_name!r}")

    if plane not in (document.get("plane") or []):
        return {
            "schema": PLAN_SCHEMA, "profile": profile_name,
            "label": document.get("label"), "level": document.get("level"),
            "plane": plane, "refused": True,
            "reason": (f"{document.get('label') or profile_name} runs only from "
                       f"{'Barad-dûr' if 'cli' not in document.get('plane', []) else 'the CLI'}"),
            "targets": targets, "stages": [],
        }

    kind = _target_kind(targets)
    if kind != document.get("target_kind"):
        # A repository profile on a domain is a mistake worth naming, not a plan
        # with zero steps that looks like it ran.
        raise ValueError(f"{profile_name} targets {document.get('target_kind')}, "
                         f"not {kind}")

    if needs_grant(document):
        # Downgrade the caller's privilege: the plan is composed as the collector,
        # so every intrusive step is judged by the grant and nothing else.
        check_grants = True
        principal = authorization.COLLECTOR_PRINCIPAL

    disabled = policy_disabled(session, org.id)
    blocked: list[dict] = []
    for target in targets:
        exclusion = authorization._denied_by_exclusion(
            session, org.id, str(target.get("type") or "domain"),
            str(target.get("value")))
        if exclusion is not None:
            blocked.append({"type": target.get("type"), "value": target.get("value"),
                            "reason": exclusion.reason,
                            "exclusion_id": exclusion.id})

    stages = []
    for stage in document.get("stages", []):
        steps = []
        for tool_name in stage.get("tools", []):
            tool = catalog()["tools"].get(tool_name) or {}
            step = {
                "step": f"{stage['id']}.{tool_name}",
                "stage": stage["id"], "tool": tool_name,
                "capability": tool.get("capability"),
                "kind": tool.get("kind"), "runs": tool.get("runs"),
                "image": tool.get("image"), "needs": tool.get("needs") or [],
                "format": tool.get("format"), "produces": tool.get("produces"),
                # A gate the tool declares: the step only runs once the
                # evidence names what it looks for (wpscan waits for WordPress).
                "when": tool.get("when"),
                "state": "allow", "reason": "",
            }
            if blocked:
                step.update(state="excluded",
                            reason="a target is excluded from scope")
            elif tool_name in disabled:
                step.update(state="not_accepted",
                            reason="turned off for this organisation in the surface policy")
            elif check_grants:
                decision = authorization.authorize(
                    session, org.id, principal, str(tool.get("capability")), targets)
                if decision["decision"] != "allow":
                    step.update(state="not_authorized", reason=decision["reason"])
            elif tool.get("runs") == "container" and not tool.get("image"):
                step.update(state="not_installed",
                            reason="the tool declares no image to run")
            steps.append(step)
        stages.append({"id": stage["id"], "from": stage.get("from"),
                       "tools": stage.get("tools") or [], "steps": steps})

    plan = {
        "schema": PLAN_SCHEMA,
        "profile": profile_name,
        "label": document.get("label"),
        "question": document.get("question"),
        "level": document.get("level"),
        "plane": plane,
        "target_kind": kind,
        "targets": targets,
        "limits": document.get("limits") or {},
        "catalog_hash": catalog_hash(),
        "actor": actor,
        "basis": "admin_override" if not check_grants else "grant",
        "requires_grant": needs_grant(document),
        "principal": principal,
        "blocked_targets": blocked,
        "stages": stages,
        "refused": False,
        "reason": "",
    }
    plan["hash"] = plan_hash(plan)
    return plan


def plan_hash(plan: dict) -> str:
    payload = {key: value for key, value in plan.items() if key != "hash"}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, separators=(",", ":"),
                   default=str).encode()).hexdigest()


def states(plan: dict) -> dict:
    """Counts the console and the CLI both show: what runs, what does not, why."""
    counts: dict[str, int] = {}
    for stage in plan.get("stages", []):
        for step in stage.get("steps", []):
            counts[step["state"]] = counts.get(step["state"], 0) + 1
    return counts


def verdict(plan: dict) -> str:
    """The one sentence the run screen leads with."""
    if plan.get("refused"):
        return plan.get("reason") or "this profile cannot run here"
    if plan.get("blocked_targets"):
        blocked = plan["blocked_targets"][0]
        return (f"blocked: {blocked['value']} is excluded from scope "
                f"({blocked['reason']}). Nothing was sent.")
    counts = states(plan)
    allowed = counts.get("allow", 0)
    if not allowed:
        missing = counts.get("not_authorized", 0)
        if missing:
            return (f"nothing can run: {missing} step(s) need a capability the grant "
                    "does not cover. Widen it in Grants.")
        return "nothing can run: every step is disabled or unavailable"
    blocked_steps = len(plan.get("stages", [])) and sum(
        value for key, value in counts.items() if key != "allow")
    if blocked_steps:
        return f"{allowed} step(s) will run, {blocked_steps} will not — see the trace"
    return f"{allowed} step(s) ready"

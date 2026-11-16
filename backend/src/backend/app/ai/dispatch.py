"""In-process execution of the catalog for the read-only tools (F1).

Why not the HTTP executor here: an F1 run executes **inside the request that asked
for it**, with the caller's credential in scope. Calling our own API from that same
request adds a hop and, on a single-worker deployment, risks a synchronous
self-call. So the dispatcher maps a catalog name to the endpoint function that backs
it — the same function the HTTP route calls — and refuses anything that is not a
`GET`.

That is also the boundary for D44: the run carries `actor_role`, authorization
happened at the request boundary, and a tool that *writes* is not dispatched here at
all. Write tools (F2) go through `executor.run_tool` with the run's role, because
that is the only path where authorization can be re-evaluated per call.

`test_every_read_tool_is_dispatched` keeps this map from drifting from the catalog:
a tool that exists and cannot be dispatched is a lie in the tool list.
"""
from __future__ import annotations

import inspect
from typing import Any, Callable

from fastapi.params import Query

from backend.app.ai import lookup as id_lookup
from backend.app.ai import tools as catalog
from backend.app.routers import (agents, authorization as grants_api, deployment_chain,
                                 easm, exposure_verdict, findings, intelligence,
                                 inventory, projects, sbom, scope, vulnerabilities)

def grants_router_list(*, org, session, status=None):
    """`authorization.list_grants` keeps `status` optional; the map needs a wrapper."""
    return grants_api.list_grants(status=status, org=org, session=session)


# name -> (callable, allowed kwargs). The callable receives `org` and `session`.
_DISPATCH: dict[str, Callable[..., Any]] = {
    "lookup": id_lookup.lookup,
    "deployment_chain": deployment_chain.deployment_chain,
    "exposure_verdict": exposure_verdict.exposure_verdict,
    "components_impact": inventory.component_impact,
    "projects_list": projects.list_projects,
    "project_inventory": projects.project_inventory,
    "compare_versions": sbom.compare_versions,
    "authorized_targets": agents.authorized_targets,
    "asset_fingerprint": agents.asset_fingerprint,
    "probe.replay": agents.replay_request,
    "vulnerabilities_search": vulnerabilities.list_vulnerabilities,
    "findings_search": findings.list_findings,
    "finding_detail": findings.get_finding,
    "finding_trace": findings.finding_trace,
    "assets_search": easm.list_assets,
    "intel_kev": intelligence.kev_for,
    "intel_kev_catalog": intelligence.kev_catalog,
    "advisory_resolve": intelligence.advisory_resolve,
    "intel_epss": intelligence.epss_for,
    "scope_resolved": scope.resolved,
    "grants_list": grants_router_list,
}


def _call_plan(handler: Callable[..., Any]) -> tuple[dict[str, str], dict[str, Any]]:
    """`{declared name -> function kwarg}` plus the plain defaults to fill in.

    A route function normally runs behind FastAPI's injection, so a default written as
    `Query(default=None)` arrives as a **`Query` object** — not `None` — when the
    function is called directly, which is exactly what this dispatcher does. Passing
    that object through reaches SQLAlchemy as a bind parameter and every tool whose
    route uses `Query(...)` fails with `cannot adapt type 'Query'` (the run records it
    as `{"error": ...}` and the model reads a dead tool as an empty estate). So:
    resolve each declared name through the `Query`'s alias, and substitute its
    `default`.
    """
    names: dict[str, str] = {}
    defaults: dict[str, Any] = {}
    for name, param in inspect.signature(handler).parameters.items():
        if name in ("org", "session"):
            continue
        if isinstance(param.default, Query):
            names[name] = name
            names[param.default.alias or name] = name
            # `Query(...)` means required: Ellipsis is not a value to fill in.
            if param.default.default is not Ellipsis:
                defaults[name] = param.default.default
        else:
            names[name] = name
            if param.default is not inspect.Parameter.empty:
                defaults[name] = param.default
    return names, defaults


_PLANS: dict[str, tuple[dict[str, str], dict[str, Any]]] = {}


def call(name: str, args: dict, *, org, session) -> dict:
    """Run one read-only tool. Unknown names and unknown arguments are errors."""
    tool = catalog.BY_NAME.get(name)
    if tool is None:
        raise KeyError(f"unknown tool: {name}")
    if tool["method"] != "GET":
        raise PermissionError(f"{name} is not a read tool; write tools go through "
                              "executor.run_tool with the run's role")
    handler = _DISPATCH.get(name)
    if handler is None:
        raise KeyError(f"{name} is in the catalog but not dispatched")
    names, defaults = _PLANS.setdefault(name, _call_plan(handler))
    unknown = set(args) - set(names)
    if unknown:
        raise TypeError(f"{name} does not accept {sorted(unknown)}")
    kwargs = dict(defaults)
    kwargs.update({names[key]: value for key, value in args.items()
                   if value is not None})
    return handler(org=org, session=session, **kwargs)


def dispatched() -> list[str]:
    return sorted(_DISPATCH)

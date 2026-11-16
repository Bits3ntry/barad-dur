"""The tool catalog: one declaration, two transports (D2, D56).

Every tool is data — name, summary, method, path, parameters — never an
implementation. `mcp/` renders this list as MCP tools; `executor.py` runs the same
entries as HTTP calls. A tool that exists in one place therefore exists in the
other, and adding one is a dict, not a second code path.

Two rules the catalog enforces by construction:

* **Read before scan (D45).** Everything here reads. A tool that spends a scan is a
  job request, not a catalog entry.
* **No opinion field is requested.** The composite endpoints carry the discipline
  (D79); the catalog cannot ask for a score that does not exist.
"""

#: parameter spec: {"in": "query" | "path", "required": bool, "type": "string" | "int" | "bool"}
TOOLS: list[dict] = [
    {
        "name": "deployment_chain",
        "summary": ("Facts for one component, project or asset: repository → build "
                    "→ deployment (DEV/PRE/PRO) → asset → observation. Each edge is "
                    "`{value, source, observed_at, confidence}` — a fact and its age, "
                    "never a joined row: for rows with environments and counts use "
                    "`components_impact` or `project_inventory`. No severity, no "
                    "verdict."),
        "method": "GET",
        "path": "/api/v1/deployment/chain",
        "params": {
            "purl": {"in": "query", "type": "string"},
            "component": {"in": "query", "type": "string"},
            "project": {"in": "query", "type": "string"},
            "asset": {"in": "query", "type": "string"},
        },
    },
    {
        "name": "exposure_verdict",
        "summary": ("Are we involved? One vulnerability against the estate: "
                    "affected | not_affected | unknown, per deployment, with the "
                    "reasons and the missing edge. Call deployment_chain first if "
                    "you need the raw facts."),
        "method": "GET",
        "path": "/api/v1/exposure/verdict",
        "params": {
            "cve": {"in": "query", "type": "string", "required": True},
            "purl": {"in": "query", "type": "string"},
            "depth": {"in": "query", "type": "string"},  # match | rules | full
        },
    },
    {
        "name": "components_impact",
        "summary": ("Where a component is used across projects: one row per build, "
                    "with its finding counts. Resolves a name+purl to the identity "
                    "`deployment_chain` needs; ambiguous names are an error, never a "
                    "guess."),
        "method": "GET",
        "path": "/api/v1/components/impact",
        "params": {
            "component_id": {"in": "query", "type": "string"},
            "purl": {"in": "query", "type": "string"},
            "name": {"in": "query", "type": "string"},
            "version": {"in": "query", "type": "string"},
        },
    },
    {
        "name": "projects_list",
        "summary": "Every project in the organization, with its slug and group.",
        "method": "GET",
        "path": "/api/v1/projects",
        "params": {},
    },
    {
        "name": "project_inventory",
        "summary": ("One project's inventory: components, versions, deployments and "
                    "the counts the console shows."),
        "method": "GET",
        "path": "/api/v1/projects/{ref}/inventory",
        "params": {"ref": {"in": "path", "type": "string", "required": True}},
    },
    {
        "name": "vulnerabilities_search",
        "summary": ("Problems in the estate, grouped with their occurrences. Filter "
                    "by project, vector, severity, KEV or free text."),
        "method": "GET",
        "path": "/api/v1/vulnerabilities",
        "params": {
            "project": {"in": "query", "type": "string"},
            "vector": {"in": "query", "type": "string"},
            "severity": {"in": "query", "type": "string"},
            "status": {"in": "query", "type": "string"},
            "kev_only": {"in": "query", "type": "bool"},
            "q": {"in": "query", "type": "string"},
            "include_suppressed": {"in": "query", "type": "bool"},
            "limit": {"in": "query", "type": "int"},
            "offset": {"in": "query", "type": "int"},
        },
    },
    {
        "name": "finding_detail",
        "summary": ("One finding in full: its recorded `proof_request`/`proof_response` "
                    "(the exact request a pentest or a field task captured), "
                    "`reproduction`, `validation_output`, the axes and the subject. "
                    "Use it before saying an estate holds no proof of something."),
        "method": "GET",
        "path": "/api/v1/findings/{finding_id}",
        "params": {"finding_id": {"in": "path", "type": "string", "required": True}},
    },
    {
        "name": "lookup",
        "summary": ("What one 32-hex id is: finding, mission, task, run, cycle, asset or "
                    "component. Use it before saying an id does not exist — the text "
                    "searches match titles and CVE ids, never identifiers."),
        "method": "GET",
        "path": "/api/v1/ai/lookup/{ref}",
        "params": {"ref": {"in": "path", "type": "string", "required": True}},
    },
    {
        "name": "finding_trace",
        "summary": ("The story behind one finding: the envelope that authorised it, the "
                    "ordered events (tool → observation → decision), the gate verdicts, "
                    "and every `repeat` that already tried to reproduce it. Read this "
                    "before planning a validation: a plan that repeats an attempt which "
                    "already failed is not a plan."),
        "method": "GET",
        "path": "/api/v1/findings/{finding_id}/trace",
        "params": {"finding_id": {"in": "path", "type": "string", "required": True}},
    },
    {
        "name": "findings_search",
        "summary": ("Raw findings, one row per weakness/instance, matched by "
                    "`q` against title, rule, path and CVE — **never by id**. Zero rows "
                    "here does not mean the finding is absent: open it with "
                    "`finding_detail`, or resolve the id with `lookup`."),
        "method": "GET",
        "path": "/api/v1/findings",
        "params": {
            "project": {"in": "query", "type": "string"},
            "version": {"in": "query", "type": "string"},
            "kind": {"in": "query", "type": "string"},
            "q": {"in": "query", "type": "string"},
            "severity": {"in": "query", "type": "string"},
            "priority": {"in": "query", "type": "string"},
            "assignee": {"in": "query", "type": "string"},
            "source": {"in": "query", "type": "string"},
            "vector": {"in": "query", "type": "string"},
            "include_suppressed": {"in": "query", "type": "bool"},
        },
    },
    {
        "name": "assets_search",
        "summary": ("Externally observable assets: domains, IPs, URLs. Includes "
                    "classification status — ownership is not scan authorization."),
        "method": "GET",
        "path": "/api/v1/assets",
        "params": {
            "type": {"in": "query", "type": "string"},
            "project": {"in": "query", "type": "string"},
            "owner": {"in": "query", "type": "string"},
            "classification": {"in": "query", "type": "string"},
            "q": {"in": "query", "type": "string"},
            "include_archived": {"in": "query", "type": "bool"},
            "limit": {"in": "query", "type": "int"},
            "offset": {"in": "query", "type": "int"},
        },
    },
    {
        "name": "authorized_targets",
        "summary": ("Domains this estate may touch, with the grant, level and expiry "
                    "behind each one. A host that is not here has no route."),
        "method": "GET",
        "path": "/api/v1/agents/targets",
        "params": {},
    },
    {
        "name": "asset_fingerprint",
        "summary": ("What we already know about one authorized target: declared "
                    "runtime and version, last observations, open findings. Reads "
                    "rows; sends nothing to the host."),
        "method": "GET",
        "path": "/api/v1/agents/fingerprint",
        "params": {"asset": {"in": "query", "type": "string", "required": True}},
    },
    {
        "name": "probe.replay",
        "summary": ("Re-send the request a finding was recorded with, against an "
                    "authorized host only. No new payloads: the stored request, or "
                    "`blocked` when there is none."),
        "method": "GET",
        "path": "/api/v1/agents/replay",
        "params": {
            "finding_id": {"in": "query", "type": "string", "required": True},
            "target": {"in": "query", "type": "string"},
            "expect": {"in": "query", "type": "string"},
        },
    },
    {
        "name": "compare_versions",
        "summary": ("Component-level diff between two versions of the same project: "
                    "what an upgrade adds, removes and changes."),
        "method": "GET",
        "path": "/api/v1/sbom/compare",
        "params": {
            "project": {"in": "query", "type": "string", "required": True},
            "from_version": {"in": "query", "type": "string", "required": True},
            "to_version": {"in": "query", "type": "string", "required": True},
        },
    },
    {
        "name": "advisory_resolve",
        "summary": ("Resolve what the operator called a vulnerability into a CVE and "
                    "say what this estate holds for it. Use it when the name is a "
                    "nickname (node2shell, log4shell) or a product, not a CVE id."),
        "method": "GET",
        "path": "/api/v1/intel/advisory",
        "params": {"q": {"in": "query", "type": "string", "required": True}},
    },
    {
        "name": "intel_kev_catalog",
        "summary": ("The world's exploited-vulnerability catalog, newest first: what "
                    "came out since a date, by product, by publisher (cisa-kev, eu-kev, "
                    "vulncheck-kev), or only the rows touching this estate. Answers "
                    "'what is new' without needing a finding."),
        "method": "GET",
        "path": "/api/v1/intel/kev",
        "params": {
            "since": {"in": "query", "type": "string"},
            "until": {"in": "query", "type": "string"},
            "q": {"in": "query", "type": "string"},
            "product": {"in": "query", "type": "string"},
            "vendor": {"in": "query", "type": "string"},
            "source": {"in": "query", "type": "string"},
            "due_before": {"in": "query", "type": "string"},
            "ransomware": {"in": "query", "type": "bool"},
            "matched": {"in": "query", "type": "bool"},
            "sort": {"in": "query", "type": "string"},
            "limit": {"in": "query", "type": "int"},
            "offset": {"in": "query", "type": "int"},
        },
    },
    {
        "name": "intel_kev",
        "summary": ("Every mirrored KEV entry for a CVE: is it exploited in the wild, "
                    "who says so, and when is it due."),
        "method": "GET",
        "path": "/api/v1/intel/kev/{cve_id}",
        "params": {"cve_id": {"in": "path", "type": "string", "required": True}},
    },
    {
        "name": "intel_epss",
        "summary": "EPSS score for a CVE (probability of exploitation in 30 days).",
        "method": "GET",
        "path": "/api/v1/intel/epss/{cve_id}",
        "params": {"cve_id": {"in": "path", "type": "string", "required": True}},
    },
    {
        "name": "scope_resolved",
        "summary": ("Effective scope: targets minus exclusions. A wildcard is a rule, "
                    "never a host; an exclusion always wins."),
        "method": "GET",
        "path": "/api/v1/scope/resolved",
        "params": {},
    },
    {
        "name": "grants_list",
        "summary": ("Scan grants with their capability bundles. Read-only: approving "
                    "a grant is a human action and is not in this catalog."),
        "method": "GET",
        "path": "/api/v1/authorization/grants",
        "params": {},
    },
]

BY_NAME: dict[str, dict] = {tool["name"]: tool for tool in TOOLS}

#: The sentence an MCP client receives on `initialize`, kept here so the server and
#: the console's MCP panel cannot drift: one text, imported by both.
MCP_INSTRUCTIONS = (
    "Facts first: `deployment_chain` describes the estate (repository → build → "
    "deployment → asset → observation, with the age of every edge) and carries no "
    "severity or score. `exposure_verdict` interprets those facts for one "
    "vulnerability and answers affected | not_affected | unknown. 'unknown' is a "
    "real answer: never read it — or a 404 — as 'not affected'. Everything else "
    "is reachable through `barad_tool`, validated against the catalog."
)



def describe() -> list[dict]:
    """The list a model sees, and the list the executor uses — the same objects."""
    return [{"name": tool["name"], "summary": tool["summary"],
             "params": tool["params"]} for tool in TOOLS]

#: What each tool may do, in the vocabulary the console and the agent share.
#: A tool absent here is `read` and touches no target — the safe default.
_TOOL_META = {
    "authorized_targets": {"risk": "read", "target_kind": "none"},
    "probe.replay": {"risk": "probe", "target_kind": "asset"},
    "asset_fingerprint": {"risk": "read", "target_kind": "asset"},
    "deployment_chain": {"risk": "read", "target_kind": "asset"},
    "exposure_verdict": {"risk": "read", "target_kind": "none"},
}

for _tool in TOOLS:
    _tool.setdefault("risk", "read")
    _tool.setdefault("target_kind", "none")
    _tool.update(_TOOL_META.get(_tool["name"], {}))

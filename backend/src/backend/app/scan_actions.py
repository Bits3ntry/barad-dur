"""The closed catalog: what can be asked for, and what each answer needs.

Three layers, three owners (CONTRACT.md §8). An **action** is what a human picks;
a **task** is what must be produced; a **provider** is how — and providers live in
Shauron's manifest, never here. Adding a tool must not touch this file.

The catalog is deliberately closed: the console offers a list, not a prompt.
"""
from __future__ import annotations

# Task vocabulary. The output contract belongs to the task, so a second provider
# for an existing task changes nothing downstream.
TASKS: dict[str, dict] = {
    "sbom": {"capability": "vulnerability_analysis", "contract": "cyclonedx-1.6"},
    "misconfig": {"capability": "vulnerability_analysis", "contract": "sarif-2.1.0"},
    "secrets": {"capability": "vulnerability_analysis", "contract": "sarif-2.1.0"},
    "sast": {"capability": "vulnerability_analysis", "contract": "sarif-2.1.0"},
    "subdomain_enumeration": {"capability": "passive_discovery", "contract": "surface-v1"},
    "dns_collection": {"capability": "passive_discovery", "contract": "surface-v1"},
    "tls_validation": {"capability": "active_verification", "contract": "surface-v1"},
}

# A push ticket carries no grant: the caller already holds the code and the
# platform is not acting alone. That is only true for capabilities that stay on
# the caller's own machine, so a push may never ask for network work.
PUSH_CAPABILITIES = {"vulnerability_analysis"}

ACTIONS: dict[str, dict] = {
    "code": {
        "label": "Source review",
        "description": "SAST + secrets on the bound repository, at one commit.",
        "target": "repository",
        "tasks": ["sast", "secrets"],
        "deadline_s": 900,
        "network": False,
        "isolation": "container",
        "coverage": "full",
    },
    # The one action whose tasks leave the machine. Verifying a credential means
    # presenting it to its issuer, so this is the platform acting alone: console
    # only, grant required, and never part of a push.
    "secrets-verified": {
        "label": "Verified secrets",
        "description": ("Credential-shaped strings confirmed live against their "
                        "issuer. Sends the candidate credential to the provider."),
        "target": "repository",
        "tasks": ["secrets"],
        "providers": {"secrets": ["trufflehog"]},
        "deadline_s": 1800,
        "network": True,
        "isolation": "container",
        "coverage": "full",
    },
    "supply-chain": {
        "label": "Dependencies and configuration",
        "description": "SBOM, dependency advisories and misconfigurations.",
        "target": "repository",
        "tasks": ["sbom", "misconfig", "secrets"],
        "deadline_s": 1200,
        "network": True,
        "isolation": "container",
        "coverage": "full",
    },
    "web-surface": {
        "label": "Attack surface",
        "description": "Subdomains, DNS and TLS over the declared scope.",
        "target": "domain",
        "tasks": ["subdomain_enumeration", "dns_collection", "tls_validation"],
        "deadline_s": 3600,
        "network": True,
        "isolation": "container",
        "coverage": "full",
    },
}


def catalog() -> list[dict]:
    """What the console renders. `served` is unknown here on purpose: the
    platform learns it from a daemon's manifest, and until then it must not
    claim a task can run."""
    return [
        {
            "name": name,
            "label": spec["label"],
            "description": spec["description"],
            "target": spec["target"],
            "tasks": spec["tasks"],
            "capabilities": capabilities_of(build_tasks(name)),
            "deadline_s": spec["deadline_s"],
            "network": spec["network"],
            "coverage": spec["coverage"],
            "providers": spec.get("providers") or {},
        }
        for name, spec in ACTIONS.items()
    ]


def action(name: str) -> dict | None:
    spec = ACTIONS.get(name)
    return dict(spec, name=name) if spec else None


def build_tasks(action_name: str) -> list[dict]:
    spec = ACTIONS[action_name]
    extra = spec.get("providers") or {}
    tasks = []
    for task in spec["tasks"]:
        meta = TASKS[task]
        row = {
            "task": task,
            "contract": meta["contract"],
            "capability": meta["capability"],
            "required": True,
        }
        if extra.get(task):
            # Opt-in providers ride in the ticket: the daemon runs them only when
            # named, and refuses names it does not serve.
            row["additional_providers"] = list(extra[task])
        tasks.append(row)
    return tasks


def capabilities_of(tasks: list[dict]) -> list[str]:
    return sorted({t["capability"] for t in tasks})


def push_allowed(tasks: list[dict], network: bool = False) -> tuple[bool, str]:
    """A push ticket is a caller scanning code it already has."""
    extra = {t["capability"] for t in tasks} - PUSH_CAPABILITIES
    if extra:
        return False, (
            "a push ticket may not request "
            f"{sorted(extra)}; those capabilities mean the platform acts alone, "
            "which needs a grant and the console")
    if network:
        return False, (
            "a push ticket may not run a networked action: the platform is not "
            "acting alone, and reaching out is the platform's own act")
    return True, "ok"

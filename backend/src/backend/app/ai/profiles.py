"""Profiles: the operator modes a question can run under (D40–D43).

F1 ships them as code (`palantir` is the only one with `field_allowed=False` and no
lanes), because a profile is a promise about what the system will not do. They move to
an `ai_profiles` table when they become editable in Settings — the fields are already
the shape of that row, so it is a migration, not a redesign.
"""

PROFILES: list[dict] = [
    {
        "key": "palantir",
        "name": "Palantír",
        "tagline": "The seeing stone: answers from what the estate already knows.",
        "wants": ["a correct, cited answer", "an honest unknown with the missing edge"],
        "sees": ["components", "builds", "deployments", "assets", "observations",
                 "findings", "scope", "grants", "intel"],
        "lanes": [],
        "specialists": ["intel.cve", "estate.inventory", "applicability",
                        "evidence.report"],
        "budget": {"max_steps": 6, "max_tokens": 30000},
        "fanout_cap": 0,
        "approval": "auto",
        "field_allowed": False,
        "max_level": 2,
    },
    {
        "key": "angmar",
        "name": "Angmar",
        "tagline": "The blade: reproduce a documented finding, or dismiss it.",
        "wants": ["a documented finding reproduced or refuted, with the request "
                  "that decided it"],
        "sees": ["the finding", "its recorded evidence", "its target's scope"],
        "lanes": ["validate"],
        "specialists": ["validation.technical", "evidence.report"],
        "budget": {"max_steps": 20, "max_tokens": 60000},
        "fanout_cap": 1,
        "approval": "plan_review",
        "field_allowed": True,
        "max_level": 3,
    },
    {
        "key": "morgoth",
        "name": "Morgoth",
        "tagline": "The hunter: it wants vulnerabilities, not tickets.",
        "wants": ["a new confirmed vulnerability, with an artifact"],
        "sees": ["everything Palantír sees", "observed technology", "endpoints",
                 "rejected hypotheses", "signature coverage", "grants"],
        "lanes": ["discover", "exploit"],
        "specialists": ["recon.surface", "recon.code", "applicability",
                        "exploit.chain", "probe.sibling", "evidence.report"],
        "budget": {"max_steps": 40, "max_tokens": 400000},
        "fanout_cap": 20,
        "approval": "plan_review",
        "field_allowed": True,
        "max_level": 4,
    },
]

BY_KEY = {profile["key"]: profile for profile in PROFILES}


def get(key: str) -> dict | None:
    return BY_KEY.get(key)

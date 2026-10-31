# Acceptance criteria — the navigation criterion

Master criterion (from requirements): **from any finding there is a real,
verified path to**: project → version → component → repository (+ code
location) → service/deployment → domain/endpoint → audit entries → evidence →
Jira ticket → regression test — *only through relations that actually exist*.

Mechanism: a pytest in `backend/tests/test_navigation_criterion.py` walks real
FKs and asserts every declared link; each ramp-up item below extends the walk.
No "does not yet exist" links count as pass.

| Relation | Where it lives today | Ramp ID |
|---|---|---|
| finding → project/version | `findings.project_id`, `last_seen_version_id` | live |
| finding → component | `findings.component_id` (vulns) / path-based for SAST | live (code-weakness path is text — BL-010 will bind) |
| finding → code location | `rule_id`/`path`/`line` | live (text) |
| finding → evidence | CLI-side, redacted envelope only | BL-045 |
| finding → repository | — | BL-010 |
| finding → service/deployment | — | BL-010 |
| finding → domain/endpoint | — (EASM assets are unlinked) | BL-015a |
| finding → audit | ingest/approve/task events already in the chain | live (partial) |
| finding → Jira | — | BL-050 |
| finding → regression run | — | BL-080 |
| component → license | — | BL-060 |
| version → SBOM export | receipt + GET body | live (CycloneDX only — BL-025) |

Rule for phases: a phase closes only when its ramp rows turn "verified" in
this table AND the navigation test extends with them.

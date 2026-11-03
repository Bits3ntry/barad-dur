# Barad-dûr v0 — final report (audit → implementation → acceptance)

Date 2026-11-02. This is the §15 deliverable: what is implemented, what is
partial, what is pending, and why. "Implemented" means persistence + API +
permissions + console + tests, verified by running the suite, the migration
chain and a browser walkthrough. A screen or a route alone is never called
implemented below.

## Verification baseline

| Check | Result |
|---|---|
| `pytest -q` (backend) | **274 passed** |
| `alembic upgrade head` on a throwaway PostgreSQL DB | 0031 → **0042** |
| `alembic downgrade -1` / `upgrade head` for 0040–0042 | clean; artifacts, run origin and the MFA tables recreated with their FKs and indexes |
| `npm run build` (console) | passes |
| `scripts/demo_v0.py` on an isolated SQLite stack | 25 assertions, all green |
| Browser walkthrough of that stack (`--serve`) | see "Acceptance walkthrough" |

The suite runs against SQLite; the migration chain was exercised against the
compose PostgreSQL in a disposable database (`v0_mig_check`), never against the
live schema.

## Migrations added (all additive, chain 0031 → 0040)

| Rev | What |
|---|---|
| 0033_v0_inventory | application components, artifacts, inventory groups + members/stakeholders, finding owner/narrative/comments/attachments, asset ownership columns, deployment → artifact |
| 0034_scope_targets | declarative scope fields, wildcard apex flag, scope → canonical asset link |
| 0035_analysis_runs | analysis runs (tool/revision/coverage/evaluated) and `findings.last_evaluated_run_id` |
| 0036_analysis_material | analysis files, classified analysis findings, diff text, report format/rules/uninterpreted |
| 0037_attack_surface | observations (with coverage), exposure events, exposure decisions |
| 0038_web_and_lookalikes | web endpoints, lookalike domains |
| 0039_cycles_and_work | cycles, frozen memberships, cycle findings, work items |
| 0040_sbom_artifact | `sbom_imports.artifact_id` — a receipt can name the build it describes |
| 0041_analysis_origin | `analysis_runs.repository_id` + `pull_request` — which remote and PR a report came from |
| 0042_user_mfa | optional TOTP per user: `users.totp_secret/totp_enabled_at`, `mfa_challenges`, `mfa_recovery_codes` |

`0032_refresh_tokens` was already in the worktree and is the parent of 0033; its
code half remains out of these commits (see "Honest limits").

## Implemented (requirement → evidence)

| Requirement | Evidence |
|---|---|
| §3 shared model: technical components, artifacts, deployment→artifact, asset ownership, inventory groups, exposure events, cycles | `models.py`, migrations 0033/0037/0039/0040; groups and assets have screens and tests |
| §4 Findings: search/filters, manual creation (IDOR without CVE), assignment, comments, evidence, narrative fields, history | `routers/findings.py`, `Findings.jsx` drawer (Overview / Occurrences / History / Remediation / Related) |
| §4 Findings: an import or diff cannot close what it did not evaluate | `analysis.plan_closure`, 409 for diff/partial, tests pin the refusals |
| §4 Vulnerabilities: grouped by CVE over visible findings, honest enrichment, grouped actions with preview | `routers/vulnerabilities.py`, `Vulnerabilities.jsx`, tests (catalog ≠ inventory) |
| §4 My work: six trays, counters, 72 h window, acceptances 30 d, no self-approval, withdraw/remind with rate limit | `routers/work.py`, `MyWork.jsx`, tests |
| §4 Dashboard: counters with their filters and destinations | `GET /dashboard/v0` + `V0Overview` block in `Dashboard.jsx`; each counter navigates to the list it counts and carries its filter; test `test_dashboard_counters_equal_their_destinations` |
| §2 Navigation: Dashboard / My work / Findings / Vulnerabilities with no group label; CTEM cycle as one frame with Scoping, Discovery and Prioritization areas | `App.jsx` (`NAV` with `sections`), `nav-section` styles; legacy phase keys resolve to the cycle overview instead of landing on the dashboard |
| §4/§8 Prioritization: ordered first-match rules, SLA buckets, reclassification on save | `routers/lifecycle.py`, `Prioritization rules` screen (opens the rule editor directly) |
| §3/§8 Business impact: open work per application — priority mix, late, unassigned, CVEs, assets, production deployments — with `criticality: not modelled` declared | `routers/impact.py`, `BusinessImpact.jsx`, `tests/test_v0_impact.py` |
| §5 Scope: declared entries only, typed fields, validity, capabilities, wildcard rules, exclusions win, scope→asset, audit | `scoping.py`, `routers/scope.py`, `docs/architecture/scope-semantics.md`, `Scope.jsx`, tests |
| §5 Cycles: charter, explicit selection, preview, freeze, findings linking **inside the frozen selection**, review, close | `routers/cycles.py`, `Cycles.jsx`, `test_auto_link_respects_the_frozen_selection` |
| §6 Assets: inventory, needs-attention with reasons, groups, activity | `routers/easm.py`, `inventory_groups.py`, `Assets.jsx`, tests |
| §7 Changes: categories, before/after, source, equal-coverage comparison | `surface.py`, `/attack-surface/changes`, `Exposures.jsx` Changes tab, tests |
| §7 Web surface / Lookalikes / Review | `routers/attack_surface.py`, `AttackSurface.jsx`, tests (excluded = not evaluated; passive only) |
| §8 Exposures: decisions with reason and validity, stable identity, reopen policy | `routers/exposures.py`, tests |
| §9 SBOM landing: CycloneDX + SPDX, hash/receipt, per-version usage, direct/transitive, licenses | `routers/sbom.py`, `components` screens, tests |
| §9/§3 artifact chain: version → artifact → SBOM → deployment, "in production" read from deployments | `routers/artifacts.py`, `test_artifact_sbom_deployment_chain` |
| §10 SAST: SARIF + OpenGrep, snapshots, diff, viewer with syntax colour, repository + revision + branch + PR on every run, classification only against a comparable base | `sast.py`, `routers/analysis.py`, `Analysis.jsx`, `highlight.jsx`, `docs/analysis-formats.md`, tests |
| §10 navigation: result → finding → same run and line | `#findings::<id>` and `#analysis::run=<id>&path=…&line=…`; the finding shows the run that last evaluated it and the viewer links back |
| §12 authentication: optional TOTP per user (enrol → confirm → recovery codes), SSO through OIDC with pre-registered users only, both composable | `app/mfa.py`, `routers/mfa.py`, `Security.jsx`, `Login.jsx`, `docs/security/mfa-and-sso.md`, `tests/test_v0_mfa_sso.py` |
| §11 notifications: in-app, email, signed webhook and Slack incoming webhook | `routers/notifications.py`, `Notifications.jsx` channels card, `docs/integrations/slack.md` (payload verified against a local mock) |
| §12 isolation and audit on every new surface | org checks in every route, `_audit` on mutations, isolation tests per slice |
| §14 steps 1–13 | `backend/tests/test_v0_acceptance.py` + `scripts/demo_v0.py` (steps 1–13, including the cross-organization check) |

## Defects found and corrected during acceptance

| # | Defect | Fix |
|---|---|---|
| 1 | Cycle auto-link dropped findings when the selection named a project: the assets resolved from that project were treated as a *narrowing* filter, so findings without a located asset never linked | a project (or whole-org) selection is the declared scope; only asset/group/environment selections narrow. Test asserts a finding on a sibling deployment of the same project stays out |
| 2 | Findings and the dashboard sent the project **name** where the API read the **slug** → `HTTP 404: project not found` on a project whose name differs from its slug | `backend/app/projects.py:by_ref` accepts either; used by findings, dashboard, analysis, vulnerabilities, attack-surface review and the cycle resolver |
| 3 | `/dashboard/summary` and `/dashboard/exposure-flow` answered **the whole organization** when the requested project did not exist — an unknown scope silently widened | 404 when a project was requested and is not visible; an omitted project still means the portfolio. Tests cover both |
| 4 | Exposure counters were computed over the *filtered* rows, so the header said "0 accepted" while one acceptance existed | counts are computed over the organization's events; `total_events` added |
| 5 | `GET /artifacts/{id}` omitted its coverage keys for artifacts without an SBOM | both branches return `sbom` / `components` / `usage_per_artifact`, the last one declared "not implemented" |
| 6 | The v0 dashboard block existed in the API only | `V0Overview` wired into `Dashboard.jsx`, with the coverage note ("a gap means nothing was observed, not that it is clean") |
| 7 | "Team queue" claimed a team model that does not exist | backend returns `scope: organization` + label "Organization queue (no teams yet)"; the tray explains it instead of implying teams |

## Partial — separated by cause

### A. Shortfall of this delivery (real v0 functionality thinner than the spec)

| Area | What exists | What is missing |
|---|---|---|
| §2/§9 Components and artifacts in the console | SBOM import, component catalog, usage, licenses, `GET /artifacts/{id}` with the full chain | No artifact screen and no deep link from a component to the artifact/deployment that uses it; the chain is API + tests only |
| §10 repository/project screen links | The finding drawer links to the run and line; project/repository screens do not link into the viewer yet | A project-level "recent analyses" list |
| §10 source→sink traces | `codeFlows` count is kept and displayed as a count | No trace rendering: scanners rarely supply enough data and inventing impact is forbidden by the spec |
| §11 connector contract | Repositories, Jira links/outbox, notification channels, manual references | Capability-shaped connector contract + health check; "connected" is never claimed without a probe (v0 scope was manual references) |
| §14 weekly summary | `GET /attack-surface/summary` + recipients config | Scheduled delivery: `delivery.configured=false`, no scheduler/channel in this delivery |

### B. Explicit future extension (out of v0 by the spec itself)

- Scans, sensor administration, CI/CD execution, provider synchronization.
- Access groups and per-team data scoping (`My work → My team` stays org-wide and says so).
- Quality policies / enforcement over analysis runs (the structure admits a gate; none reads it yet).
- Dynamic inventory groups and advanced expressions.
- Configuration group (users/roles/permissions/connectors) as one menu; those screens exist under Members/Grants/Settings.

## Pending (not started)

- Alert-driven tasks: remediation exists, no per-finding notification rule.
- Advisory re-evaluation records (a new advisory version re-scoring an unchanged artifact).
- Advisory alias merging policy (aliases are surfaced, never merged silently).

## Acceptance walkthrough (isolated stack)

`python scripts/demo_v0.py --serve` sets `PLATFORM_DATABASE_URL` to a temporary
SQLite file, seeds Bitsentry → AUREA → backend v3/v4 → `api-aurea` → deployment →
SBOM → findings → SAST base/head with diff → group → cycle → review → close, then
serves the built console plus the API on `127.0.0.1:8099`. It prints the ids and
writes them to `barad_demo_state.json` so a browser pass can be tied to records.

Verified in the browser during acceptance:

1. **Persistence** — the closed cycle keeps its frozen snapshot, charter and two review criteria across a full reload; findings stayed at 3 rows over two reloads (no duplicate from the re-import path).
2. **Links between screens** — the v0 counter "open findings: 3" navigates to Findings and the list renders exactly 3 rows; "changes 7d" opens the Changes tab with the open-port event.
3. **Empty vs error vs no-permission** — Vulnerabilities shows "0 CVEs affecting this inventory" as an honest empty state; an invalid key produces `HTTP 401: the API key or session was rejected.` and the Findings header reads "not loaded" instead of "0 findings in scope"; the cross-organization check is asserted in the demo (cycle 404, zero findings).
4. **SAST viewer** — file tree → code with the rule in the gutter at line 12 (`py.sqli · CWE-89`), diff tab with 1 added / 1 removed, results tab showing `persistent` and `modified line: yes` (not "introduced").
5. **Exposures** — `1 open · 1 accepted` after the acceptance decision, with Changes showing `open port · — → 8080 · demo-import`.
6. **Assets** — the scope-created asset appears once, with group `Production`, `no_owner` / `no_project` in Needs attention, and the ledger rows for cycle/deployment in Activity.

Not covered by that pass: mobile widths, Safari/Firefox, concurrent operators,
and anything requiring a real collector (scans, crt.sh sweeps).

## Decisions taken during implementation

1. A wildcard scope rule excludes the apex unless `include_apex` is set; depth is unlimited (`docs/architecture/scope-semantics.md`).
2. Exposures and findings are separate identities: a condition under management vs. a weakness with a location.
3. Only a `coverage: full` run may close findings, and only those it evaluated.
4. Analysis classification is `no_reference` without a comparable baseline; "new" is never inferred.
5. A cycle freezes charter + membership at activation; later discoveries are candidates for the next cycle.
6. A project reference is accepted as slug or name on reading screens; unknown references answer 404 rather than widening to the organization.

## Honest limits of this delivery

- **Nothing was deployed.** The live compose stack still serves the previous image; per instruction, deployment is a later action. Everything above ran on an isolated SQLite database and a disposable PostgreSQL database.
- The worktree carries unrelated, unfinished refresh-token code (`auth_local.py`, `accounts.py`, `Login.jsx`, `Settings.jsx`, parts of `models.py`/`api.js`). Those hunks were deliberately kept out of these commits; the API-key 401 message improvement in `api.js` rides with that pending work.
- Application components are seeded directly in the demo: they have a model and relationships but no CRUD endpoint yet (documented in Partial A).
- This report does not claim parity with OpenCTEM; it records what this fork does now, verified by the suite, the migration chain and the walkthrough above.

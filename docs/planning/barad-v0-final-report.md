# Barad-dûr v0 — final report (audit → implementation)

Date 2026-11-02. This is the §15 deliverable: what is implemented, what is
partial, what is pending, and why. "Implemented" means: persistence + API +
permissions + console + tests, verified by running the suite and the migration
chain. A screen or route alone is not called implemented anywhere below.

Verification baseline for every slice: `pytest` green, `alembic upgrade head`
(and the slice's `downgrade`) applied on a throwaway PostgreSQL database, and
`npm run build` passing the console's import guard. The suite ended at
**253 passed**.

## Migrations added (all additive, chain 0031 → 0039)

| Rev | What |
|---|---|
| 0033_v0_inventory | application components, artifacts, inventory groups + members/stakeholders, finding owner/narrative/comments/attachments, asset ownership columns, deployment → artifact |
| 0034_scope_targets | declarative scope fields, wildcard apex flag, scope → canonical asset link |
| 0035_analysis_runs | analysis runs (tool/revision/coverage/evaluated) and `findings.last_evaluated_run_id` |
| 0036_analysis_material | analysis files, classified analysis findings, diff text, report format/rules/uninterpreted |
| 0037_attack_surface | observations (with coverage), exposure events, exposure decisions |
| 0038_web_and_lookalikes | web endpoints, lookalike domains |
| 0039_cycles_and_work | cycles, frozen memberships, cycle findings, work items |

(`0032_refresh_tokens` was already in the worktree and is the parent of 0033;
its code half remains out of these commits.)

## Implemented (requirement → evidence)

| Requirement | Evidence |
|---|---|
| §3 shared model: technical components, artifacts, deployment→artifact, asset ownership, inventory groups, exposure events, cycles | `models.py`, migrations 0033/0037/0039; groups and assets have their own screens and tests |
| §4 Findings: search/filters, manual creation (IDOR without CVE), assignment, comments, evidence, narrative fields, history | `routers/findings.py` (`/findings`, `POST /findings`, assignee, comments, attachments, `/history`), `Findings.jsx` drawer |
| §4 Findings: an import or diff cannot close what it did not evaluate | `analysis.plan_closure` + `POST /analysis/runs/{id}/close-unseen` (409 for diff/partial), tests pin the refusals |
| §4 Vulnerabilities: grouped by CVE over visible findings, assets/projects/findings counts, honest enrichment, grouped actions with preview | `routers/vulnerabilities.py`, `Vulnerabilities.jsx`, tests (catalog ≠ inventory, manual IDOR excluded) |
| §4 My work: six trays, counters, expiry ordering, 72 h window, acceptances 30 d, no self-approval, withdraw/remind with rate limit | `routers/work.py`, `MyWork.jsx`, tests |
| §5 Scope: declared entries only, typed fields, validity, capabilities, wildcard rules documented and enforced, exclusions win, scope→asset, audit | `scoping.py`, `routers/scope.py`, `docs/architecture/scope-semantics.md`, `Scope.jsx`, tests |
| §5 Cycles: charter, explicit selection, preview, freeze on activation, candidates outside the reference, findings linking, review criteria, close keeps history | `routers/cycles.py`, `Cycles.jsx`, tests |
| §6 Assets: inventory with filters/paging/owner/project/classification/archive, needs-attention with reasons and actions, groups, activity | `routers/easm.py`, `inventory_groups.py`, `Assets.jsx`, tests |
| §7 Changes: categories, before/after, source, equal-coverage comparison | `surface.py`, `/attack-surface/changes`, `Exposures.jsx` Changes tab, tests (failed collection ≠ closed port) |
| §7 Web surface: origins/paths, states, excluded = not evaluated, 200 ≠ vulnerable | `routers/attack_surface.py`, `AttackSurface.jsx`, tests |
| §7 Lookalikes: watch root, candidates, similarity, registration state, passive-only, decisions with reason | same router/screen, tests (no scope entry, "authorization: none") |
| §7 Review: ownership queue, confirm/external/discard with reason, ownership ≠ authorization | same router/screen, tests |
| §8 Exposures: overview with decisions, stable identity, reopen policy, decision history; four summaries over the same findings | `routers/exposures.py`, tests |
| §10 SAST: SARIF + OpenGrep import, snapshots, diff, file/diff viewer, classification only against a comparable base, "on a modified line" ≠ "introduced" | `sast.py`, `routers/analysis.py`, `Analysis.jsx`, `docs/analysis-formats.md`, tests |
| §12 isolation and audit on every new surface | org checks in every route; `_audit` on all mutations; isolation tests per slice |
| §14 acceptance steps 1–10 and 12–13 | covered by the slice test files listed above (see `tests/test_v0_*.py`) |

## Partial (declared, with the reason)

| Area | What exists | What is missing and why |
|---|---|---|
| §4 Dashboard | `GET /dashboard/v0` returns assets, projects, findings by severity/priority, CVE/KEV counts, recent changes, open exposures, cycles, acceptances expiring, coverage gaps — each with a link | The console block on `Dashboard.jsx` was not wired to it yet; the existing dashboard still shows the pre-v0 summary |
| §9 Components/SBOM | CycloneDX + SPDX import, per-version usage, direct/transitive, licenses, `components/impact` | Artifact-level SBOM association (artifacts exist but no import path binds a document to one); advisory alias handling and re-evaluation records |
| §10 SAST | One format pair done end to end; viewer with tree/code/diff | Source→sink traces (only a `codeFlows` count is kept); deep links from Components/Assets/project; PR intake from a provider |
| §11 Integrations | Repositories, Jira links/outbox, notification channels; references are manual | Capability-based connector contract, connection health check, credential store, sync/idempotency |
| §2 Navigation | General / Scoping / Discovery / Code security groups with the v0 screens | Configuration group (users/roles/permissions/connectors) still spread across Members/Grants/Settings; "My team" has no team objects — the tray says so |
| §14 acceptance demo | Every step is covered by an automated test | There is no single runnable demo script that walks the 13 steps against a live stack; the tests are the reproducible proof today |

## Pending (not started)

- Acquisition: scans, sensor administration, CI/CD execution, provider sync.
- Scheduled weekly delivery: the query exists, `delivery.configured=false`; no
  scheduler/channel wiring.
- Alert-driven tasks: remediation exists, but no per-finding notification rule.
- Access groups and per-team data scoping (`My work → My team` is org-wide).
- Quality policies/enforcement on analysis runs (the structure admits them; no
  gate reads them yet).

## Decisions taken during implementation

1. A wildcard scope rule excludes the apex unless `include_apex` is set; depth is
   unlimited. Documented in `docs/architecture/scope-semantics.md`.
2. Exposures and findings are separate identities: a condition under management
   vs. a weakness with a location. Neither duplicates the other.
3. Only a `coverage: full` run may close findings, and only the ones it
   evaluated (same tool, path inside `evaluated.paths`).
4. Analysis classification is `no_reference` without a comparable baseline; "new"
   is never inferred from the absence of a base run.
5. A cycle freezes charter + membership at activation; later group changes are
   shown as candidates for the next cycle, not merged into the reference.

## Honest limits of this delivery

- Nothing was deployed: the running stack still serves the previous image. The
  worktree also carries unrelated, unfinished refresh-token code that was
  deliberately kept out of these commits.
- The console was rebuilt and type-checked by its import guard, but not clicked
  through in a browser during this session.
- This report does not claim parity with OpenCTEM; it records what this fork does
  now.

# Barad-dûr v0 — spec gap matrix (KEEP / EXTEND / REPLACE / NEW)

Audit date 2026-11-02. Source of requirements: the owner's v0 functional spec
("Barad-dûr v0 — especificación funcional", 2026-11-02). This document is the
deliverable of spec §13.1 and the "matriz inicial" of §15: it audits the repo as
it stands and decides, per requirement, whether to keep, extend, replace or
build new. **It does not claim any requirement is implemented.** Screens and
routes named below exist today; the column "gap" says what is still missing
before the v0 criterion is met.

Method: read `AGENTS.md` (absent), `docs/architecture/*`, `docs/planning/*`,
`backend/src/backend/app/models.py`, every router under
`backend/src/backend/app/routers/`, the migrations chain 0001–0032, the test
suite under `backend/tests/`, and the console screens under `frontend/src/`.
Per-file evidence is cited as `path:line`.

Legend: **KEEP** = reuse unchanged · **EXTEND** = reuse and add fields/routes ·
**REPLACE** = same intent, different model/contract (needs migration +
compatibility) · **NEW** = does not exist in any usable form.

Honesty rule: a route with no UI consumer is not done; a UI with no persisted
state is not done; an import that was never re-run is not proven idempotent.

## 0. What the repo is today

A single-org-per-tenant FastAPI platform (SQLAlchemy 2 + Alembic) with a React
console, covering the supply-chain and code-security loop end to end:

- Org / API keys / users / sessions / 4 roles — `routers/organization.py`,
  `routers/accounts.py`, `models.py:1145`.
- Projects → versions → components, SBOM (CycloneDX) ingest, SPDX 2.3
  ingest/export, OSV matching, findings with fingerprints, suppressions,
  priority rules, SLA, occurrences, remediation tasks.
- EASM-lite: assets (domain/ip/url/cidr) from crt.sh + manual, snapshots, DNS
  and TLS collection behind scan grants, per-asset change detection.
- SAST: SARIF ingest → findings/occurrences, code-file snapshots, PR records
  with base↔head diff, new/existing/baselined classification, gate verdict,
  GitHub/GitLab publishing.
- Scope: static positive targets + exclusions + resolution; scan grants as the
  authorization engine.
- CTEM "overview": five phases derived from existing tables — a read-only
  reporting view, not a persisted cycle.

What v0 asks for that has **no** representation at all: a persisted CTEM cycle
with charter/snapshot; exposure events as a managed condition; vulnerability
aggregation by CVE as a screen; My work queues; inventory groups; asset
activity/history screen; attack-surface changes/web-surface/lookalikes/review;
SAST report import without GitHub and a code viewer bound to an analysis
record; finding assignment, manual creation, comments and evidence attachments.

## 1. Shared model and identity rules (spec §3)

| Requirement | Decision | Current evidence | Gap |
|---|---|---|---|
| Organization isolation | **KEEP** | `models.py:41`; every endpoint goes through `auth.require_org`; isolation tests `test_bl015_authorization.py`, `test_console_round_authz.py` | Audit every new route; add org-scoped tests for each v0 table. |
| Project/application | **KEEP** | `models.py:60` (`projects`, `group_name` at `:72`) | "AUREA" is just a project/group; no new entity needed. |
| Technical component (backend/frontend/worker) | **NEW** | `Component` is a *software package* (`models.py:105`), `Service` is a deployable service (`models.py:556`) | v0 distinguishes a technical component of the app (backend/frontend/worker) from a dependency. Introduce a typed "application component" (kind + project) rather than overloading `services`. |
| Repository, N:M, monorepos | **KEEP** | `models.py:522`, `project_repositories` `:541`, `routers/relationships.py:34` | None. |
| Version | **KEEP** | `ProjectVersion` `models.py:75`; relabel endpoint `inventory.py:206` | No commit/build link column; add nullable `commit_sha`, `build_id`. |
| Artifact/build (digest, provenance, SBOM) | **EXTEND** | Implicit in `project_versions` + `sbom_imports` (`models.py:86`, dedupe by content hash) | No artifact entity: digest, provenance, "which SBOM belongs to which exact build". Add `artifacts` (+ `artifact_sbom`). |
| Deployment (environment, state, in production) | **EXTEND** | `Deployment` `models.py:588` (environment, dates, status) | No artifact/version FK and no history; and note the spec's rule: never a single `in_production` flag on the version. Wire deployment → artifact → version. |
| Asset, typed, no duplicate identity | **KEEP** | `Asset` `models.py:394`; unique `(org, type, value)`; `AssetLink` `:604` | No `classification_status`, `owner`, `project_id`, `last_observed` summary; extend columns. |
| Domain / IP / endpoint | **KEEP** (assets) / **NEW** (endpoint paths) | assets cover domain/ip/url/cidr (`easm.py:106`) | No endpoint/path inventory (§7 web surface) and no endpoint↔deployment relation. |
| Software component (purl/ecosystem/versions) | **KEEP** | `Component` `models.py:105`, `version_components` `:122` (is_direct), `component_licenses` `:712` | Usage is per version; must render per artifact once artifacts exist. |
| Finding (target, location, evidence, owner, history) | **EXTEND** | `Finding` `models.py:154`; status endpoint `findings.py:133`; occurrences `:685`; contexts `:622` | No `assignee`, no manual create, no comments/attachments, no severity-from-rule for imported reports outside the 3 ingest kinds. |
| Vulnerability/advisory | **EXTEND** | `Vulnerability` `models.py:136`; OSV reconcile `intelligence.py:199`; KEV/EPSS mirrors `:98`,`:109` | No per-CVE aggregate endpoint/screen; aliases not modeled (`cve_id` + `source_id` only). |
| Exposure event (first/last observed, state) | **NEW** | Nothing. `finding_contexts`/`occurrences` are sighting rows, `AssetSnapshot` `:799` is a technical snapshot | New `exposure_events` table with stable identity + reopen policy; Exposures manages it, Changes reports it. |
| Inventory group (N:M, notes, owners) | **NEW** | Nothing. `Project.group_name` is a label; user groups absent too | New `inventory_groups` + `inventory_group_members`. Explicitly separate from access groups. |
| Cycle (time-boxed evaluation, scope, result) | **REPLACE** | `routers/ctem.py:39` derives five phases from existing tables; no table | New `cycles`, `cycle_targets` (snapshot), `cycle_findings`, `cycle_results`. Keep the phase overview as a *derived reading* over the persisted cycles. |
| Dedup per finding kind, import traceability, idempotency | **KEEP** | recipes in `incidents.py:76`, `vulns.py`, SARIF fingerprint rule+path, `sbom_imports` content hash; `receipts` in responses | Manual findings need their own recipe; imported CVEs from scanner reports need a recipe distinct from OSV matching. Document per-kind recipes in one place. |
| Inventory groups ≠ access groups | **KEEP (as rule)** | No access groups exist yet | Access groups are new (§12 config), and must never be derived from inventory groups. |

## 2. General screens (spec §4)

| Requirement | Decision | Current evidence | Gap |
|---|---|---|---|
| Dashboard: assets/projects, open findings by severity/priority, CVEs, recent changes, expiries, cycles; counters link to filtered lists; freshness | **EXTEND** | `dashboard.py:22` (`summary`), `:291` (`exposure-flow`), `:184-267` time series; `Dashboard.jsx`, `ExposureFlow.jsx` | No CVE counter, no "recent changes" feed, no expiries (acceptances/cycles), no freshness stamp per block, counters not deep-linkable. |
| Findings list: search, filters (project, asset, source, type, status, severity, priority, owner, version, environment) | **EXTEND** | `findings.py:292` supports `project`, `version`, `kind`, `status`, `include_suppressed` | Missing search, severity/priority/owner/source/tool filters, pagination, sorting. Filters must compose with asset/deployment relations. |
| Manual create, import, assign, comment, attach evidence, status, remediation link | **EXTEND** | import `findings.py:56` (3 kinds only), status `:133`, remediation `models.py:276` | No manual create (IDOR-without-CVE is impossible today), no assignee, no comments, no attachments. NEW table `finding_comments`, `finding_attachments`. |
| Detail: description, impact, location, rule/CWE/CVE, origin, analysis/commit, evidence, reproduction, recommendations, history | **EXTEND** | `findings.py:102`; `CodeReview.jsx` shows file context; `occurrences` history | Missing `cwe`, `impact`, `recommendation`, `reproduction`, structured location per kind, change history (only status_changed_at). |
| Secrets hidden by default, never in logs/exports | **KEEP** | `redaction.py`; ingest contract requires pre-redaction (`incidents.py:1-12`) | No export path exists yet; enforce at export time. Prove with a test. |
| Triage decisions survive imports; partial import must not close unevaluated findings; inconclusive ≠ fixed | **KEEP (rule) + test** | Fingerprint + `last_seen_at` refresh; OSV reconcile `intelligence.py:199` | No explicit "scope of evaluation" record per import, so "not seen because not evaluated" is indistinguishable from "fixed". Add `analysis_runs` (tool/version/coverage) and only close findings inside an analysis with `coverage=full` covering them. |
| State transitions and permissions defined in backend | **EXTEND** | `findings.py:133`; policy in `lifecycle.py` | No per-role transition matrix; no reason enforcement per transition. |
| Vulnerabilities: grouped by CVE, assets/findings affected, severity/priority, affected/fixed versions, enrichment with source+date, unknown when missing | **NEW (screen) / EXTEND (data)** | `vulnerabilities` table `models.py:136`; KEV/EPSS `intelligence.py:98`,`:109`; VEX `:164` | No `GET /vulnerabilities` aggregate, no affected/fixed version extraction, no UI. Grouped actions need a preview endpoint. |
| My work: 6 queues with counters, expiry ordering, 72 h filter, acceptances expiring 30 d, approve/reject with reason, requester withdraw/remind (rate-limited), no self-approval | **NEW** | `SuppressionRule` has `requested_by`/`approved_by` and self-approval guard (`models.py:199` comment, `findings.py:248`); `RemediationTask` `models.py:276`; nothing for acceptances/tasking | New `work_items` (assignment/request/review) + `tasks`; queues are computed queries, not static data. Reminder rate limit needs a column. |

## 3. Scoping (spec §5)

| Requirement | Decision | Current evidence | Gap |
|---|---|---|---|
| Scope lists only declared entries; fields type/value/reason/owner/source/validity/state/restrictions/capabilities | **EXTEND** | `ScopeTarget` `models.py:473`, `ScopeExclusion` `:492`, routes `scope.py:39-96` | Missing `reason`, `owner`, `source`, `valid_until`, `state`, `restrictions`, `capabilities`; no `PATCH`/deactivate/audit on scope. |
| No wildcard type; `*.x` semantics documented (root included?, depth, URL/path, IP rules) | **REPLACE (documented semantics)** | `docs/architecture/scopes-and-authorization.md` calls wildcard handling "next"; `scope.py:48` accepts free `target_type` | Must implement and pin with tests: `*.bitsentry.xyz` = rule/seed, not hosts. Root-domain inclusion is currently unspecified — decide and test. |
| Specific scope entry creates/links canonical asset with source `scope` | **NEW (link)** | assets and scope are unrelated tables today | Add `asset_id` on scope target or a link row; audited. |
| Exclusions prevail; absence of permission denies active action; cloud account reference does not authorize provider IPs | **KEEP** | `scope.py:97` resolution + `ScanGrant` `models.py:641` fail-closed | No cloud-account target type; resolution mechanism for it undefined (declare unsupported in v0). |
| Cycles: charter, dates, owner, states planning→active→review→closed, scope preview before activation, empty selection = incomplete, freeze snapshot on activation, new discoveries as candidates, results and learnings on review, no authorization granted | **NEW** | Only derived `ctem/overview` | Full cycle model + snapshot tables + state machine + preview endpoint + UI. |

## 4. Discovery / Assets (spec §6)

| Requirement | Decision | Current evidence | Gap |
|---|---|---|---|
| Inventory: manual add, import, search, filters, pagination, edit, archive; types, projects, owners, provenance, classification state, last observation | **EXTEND** | `easm.py:83` list, `:106` create; `Assets.jsx` | No update/archive routes, no search/filters/pagination, no owner/classification, no CSV/JSON import of assets. |
| Relation domain → endpoint → deployment → artifact → version → component → project | **EXTEND** | `AssetLink` (project/service/deployment) `models.py:604`, `relationships.py:237` | No endpoint or artifact entity; version link missing. |
| Detail: info, relations, notes, versions/deployments, findings, dependencies, activity | **EXTEND** | `Assets.jsx` shows snapshots/changes | No notes, no per-asset findings list, no activity. |
| Technology source distinguished (declared / SBOM / external observation); no exact version from generic fingerprint | **EXTEND** | `AssetSnapshot` carries TLS/DNS detail (`models.py:799`) | No technology table with provenance. |
| Needs attention queue with reasons and actions; "not observed" ≠ "does not exist" | **NEW** | — | Computed endpoint + screen. |
| Groups (manual, N:M, notes, owners/collaborators, bulk add/remove, removal keeps asset) | **NEW** | — | New tables + routes + screen. |
| Activity (add/edit/relation/import/assignment/observation, actor human/system, source, resource, change, run reference; audit protected) | **EXTEND** | `AuditLog` `models.py:328` (hash chain), `GET /audit` `routers/identity.py:144` (UI: `Audit.jsx`), notifications | Audit exists but is written selectively; no user-facing per-resource activity feed, no import/run FK. |

## 5. Attack surface (spec §7)

| Requirement | Decision | Current evidence | Gap |
|---|---|---|---|
| Derived from inventory + observations; real counters; no network effect from opening a screen | **KEEP (rule)** | all collection is explicit (`easm.py:330`), gated by grants | New aggregates must be read-only queries. |
| Changes: dangling DNS, new exposure, open port, new host, cert expiry/new cert, DNS changed, technology changed, port closed, host disappeared; old/new value, source, dates; comparable coverage only | **EXTEND** | `easm.py:256` diffs snapshots; `test_bl090_snapshots.py` | Categories incomplete (no dangling DNS, no technology/port model), no coverage marker on the observation, no screen; a failed collection must not read as "port closed". |
| Web surface: origins, paths, indicators, last observation, method/evidence, candidate vs confirmed, exclusions as unevaluated, never auto-navigate | **NEW** | — | New `web_endpoints`/observations + import path + screen. |
| Lookalikes: root domains watched, candidates, similarity type, review state, registration/DNS/cert evidence, passive-only, cadence, never present a scheduled check as performed | **NEW** | — | New tables + importer + UI. |
| Review: confirm ownership/association/scope; external/not ours/discard with reason; ownership ≠ active permission; shared IP/CDN caveat | **NEW** | — | New review queue over assets + resolved addresses (`scope.py:97` already resolves, no ownership state). |
| Weekly summary: query/render + recipients config; sending depends on a real channel/scheduler | **NEW (query)** | `NotificationChannel` `models.py:1245`, `ScanSchedule` `:1195` | Build the query; label delivery "not configured" until a channel exists. |

## 6. Exposures (spec §8)

| Requirement | Decision | Current evidence | Gap |
|---|---|---|---|
| Overview of events needing a decision: asset, type, severity, origin, first/last observation, evidence, state; resolve/accept with reason+validity/false positive/reactivate; audited | **NEW** | No exposure entity | New `exposure_events` + decision history; permissions; reopen policy. |
| Changes = technical chronology, Exposures = condition under management; shared observations, no duplication per scan | **NEW (rule + model)** | snapshots exist | One observation row may create at most one open event with the same stable identity. Test it. |
| Secrets / Code weaknesses / Misconfigurations / Vulnerabilities are filtered summaries over Findings; Secrets implemented once | **EXTEND** | kinds `secret|misconfiguration|code-weakness` already in `incidents.py:18` | No filtered summary routes/screens; "Secrets" appears once in nav. |

## 7. Components / SBOM (spec §9)

| Requirement | Decision | Current evidence | Gap |
|---|---|---|---|
| CycloneDX + SPDX JSON import, documented versions, validation, useful errors | **KEEP** | `routers/sbom.py`, `routers/spdx.py`, `test_sbom_ingest_shapes.py`, `test_spdx_ingest_compare.py`; docs on supported specs | Document exact supported versions in one place (v0 deliverable). |
| Document tied to project/component/version/artifact; hash, source, date, receipt; uninterpreted elements reported | **EXTEND** | `SbomImport` `models.py:86` keyed by content hash | No artifact FK, no "uninterpreted/skipped" counter surfaced. |
| Package catalog, licenses, direct/transitive, location, graph, where used | **KEEP** | `components` + `version_components.is_direct`, `component_licenses`, `inventory.py:261/306`, `test_component_impact.py` | Graph rendering is minimal; artifact-level usage pending artifacts. |
| One package row per identity, not per import | **KEEP** | unique identity + `VersionComponent` edges | Prove by re-import test (exists). |
| Enrichment: decide whether v0 correlates advisories or consumes scanner reports; SBOM alone creates no CVE; source/date/matching/confidence; aliases not merged blindly; reassessment when intel changes | **EXTEND** | OSV reconcile `intelligence.py:199`; KEV/EPSS; VEX | No confidence/matching metadata on the finding↔advisory link; no alias table; no re-evaluation record. |
| CVE → finding → package/asset visible from Components, Assets, project, Vulnerabilities | **EXTEND** | `components/impact` joins component→version→findings | Add asset/deployment legs and a per-CVE view. |
| Unknown fixed versions shown as unknown | **KEEP (rule)** | no fixed-version extraction exists | Implement as explicit `None` + "unknown" label; never blank. |

## 8. SAST / PR viewer, SonarQube-style (spec §10)

| Requirement | Decision | Current evidence | Gap |
|---|---|---|---|
| Works with manually imported reports; ready for PR intake | **REPLACE (intake) / KEEP (engine)** | SARIF route `code_review.py:275` (inside a PR) and `routers/sarif.py` (project+version) | No analysis record independent of a PR; no OpenGrep JSON parser; no "import report + code snapshot + diff" without GitHub. |
| Each analysis keeps repo, exact revision, branch/PR, base/head, tool/version, rules, coverage full/diff/partial | **NEW** | `PullRequest` `:1070` holds some of it; `SastBaseline` `:1099` | New `code_analyses` + `analysis_files` + rule metadata. |
| Code snapshot + diff supplied by import while GitHub is absent | **EXTEND** | `POST /code/files` `code_review.py:63`, `GET /code/diff` `:447` | Requires `repository_id`; allow a standalone repository-less analysis or create the repository on import. |
| Viewer: file tree, highlight, line numbers, rule, severity, CWE, message, evidence, navigation to finding | **EXTEND** | `CodeReview.jsx`, `/code/file`, `/code/findings/{id}/context` | No full-file viewer with rule panel; no CWE; no line-range highlighting from SARIF regions. |
| Diff view with added/removed hunks and correct commit position | **EXTEND** | `/code/pull-requests/{id}/diff` `:470` | Diff is computed between code snapshots; needs hunk model and per-line classification. |
| Escape code/report content; never execute it | **KEEP (verify)** | React renders text; server stores text | Add a sanitization test at ingest and rendering. |
| "On a modified line" ≠ "introduced by the PR"; new/persistent/resolved needs a comparable baseline; otherwise "no reference / not evaluated" | **EXTEND** | `PrFinding.classification` `:1125`, baselines `code_baselines.py` | No coverage comparison between analyses; no explicit `not_evaluated`. |
| History of analyses + triage decisions | **EXTEND** | `pr_findings`, `sast_baselines` | No analysis history keyed by revision. |
| Source→sink traces only when the scanner provides them; no invented impact | **KEEP (rule)** | — | Render only if present in the report; otherwise state absent. |
| Local/remote execution, automatic PR comments, PR blocking | **KEEP OUT OF SCOPE (v0)** | publishing exists (`:514`) but must be declared optional | Document as not part of v0 acceptance. |

## 9. Integrations (spec §11)

| Requirement | Decision | Current evidence | Gap |
|---|---|---|---|
| Separate connection config, credentials, external refs, synced data | **EXTEND** | `repositories` (provider, url), `jira_links` `models.py:892`, `jira_outbox` `:915`, `scm_client.py`, `NotificationChannel` | No generic `connections` entity or capability-based connector contract; provider fields are provider-specific. |
| GitHub/Jira/Slack are not inventory projects; own instance can be an asset | **KEEP (rule)** | projects are created explicitly by ingest (`ingest.py:259`) or by the SBOM import dialog, never as a side effect of a connection | Enforce in any sync code later. |
| Connector contracts by capability (repos/code/PR, tickets, notifications); multiple connections per provider | **NEW** | — | Capability interface + registry; v0 ships manual references only. |
| Secrets protected, least privilege, audit, retries, idempotency | **EXTEND** | API keys hashed; `jira_outbox` retry pattern | No encrypted credential store for connectors. |
| Never show "connected" without a live check | **NEW (rule)** | — | Health-check endpoint per connection, cached with `checked_at`. |

## 10. Cross-cutting (spec §12)

| Requirement | Decision | Current evidence | Gap |
|---|---|---|---|
| Org isolation in reads/writes/imports/exports/background jobs | **KEEP + per-feature tests** | `test_bl015_authorization.py` | Every new table/route needs an isolation test including counters and exports. |
| Backend permissions; counters/search respect visibility | **EXTEND** | `auth.require_org` + roles; `authorization.py` for grants | No per-resource permission check (e.g. only assignee may accept); no role matrix for new actions. |
| Notes/attachments: access control, sanitization, limits, secret protection | **NEW** | — | New tables + size/type limits + sanitizer. |
| Audit scope/permission/status/exception/association changes | **EXTEND** | hash-chained `AuditLog` | Not every mutation writes an audit row today. |
| Timezone-aware dates, provenance, last update; consistent filters/pagination | **EXTEND** | UTC everywhere; no consistent pagination | Introduce one pagination contract across new lists. |
| Referential integrity; archive keeps history | **KEEP** | FK discipline + soft-remove (`removed_at`) | Extend the pattern to assets and groups. |
| Distinguish empty / not configured / no permission / error / incomplete coverage | **NEW (contract)** | partially in `CtemCycle` and portfolio | Standardize response envelope + UI states per screen. |
| Compatibility and additive migrations | **KEEP** | chain 0001–0032; never rewrite a live migration | New migrations start at `0033`. |

## 11. Navigation: target vs current

| Target group | Target entries | Today |
|---|---|---|
| General | Dashboard, My work, Findings, Vulnerabilities | Dashboard, Findings (Work group) |
| Scoping | Scope, Cycles | Scoping phase + Cycle overview (derived) |
| Discovery | Assets, Attack surface, Exposures, Components | Attack surface = `Assets.jsx`; Components |
| Code security | Analysis/PR viewer reachable from repo, project, finding | Pull requests (Delivery group) |
| Configuration | Users, access groups, roles, permissions, settings, connectors | Members, Grants, Settings, Setup |

Consequences for `frontend/src/App.jsx` (NAV at `:32`): the CTEM-cycle sidebar
added in `c3e5060` is **replaced** as the primary spine. The five phases remain
accessible from the Cycles screen as a reading of persisted cycles, not as five
top-level entries. Screens to add: My work, Vulnerabilities, Scope (own screen),
Cycles, Assets/Inventory + Needs attention + Groups + Activity, Attack surface
(Changes/Web surface/Lookalikes/Review), Exposures (Overview + 4 summaries),
Code analysis viewer. Delivery/Supply chain/Administration entries move under
Configuration or are declared post-v0 (scans, CI/CD execution, sensor admin,
full provider sync) per §2.

## 12. Implementation plan (maps to spec §13)

Dependencies only reorder work; nothing below is dropped silently.

1. **Slice A — audit + matrix** (this document). Decisions to confirm: persisted
   cycles replace the derived overview; exposures are first-class; new nav
   replaces the CTEM-cycle spine.
2. **Slice B — shared model**: artifacts + deployments→artifact, application
   components, asset columns (owner/classification/project), `inventory_groups`
   + members, `finding_comments`/`finding_attachments`, finding `assignee`,
   activity writer on every mutation. Migrations 0033–0036.
3. **Slice C — Scope**: typed target fields, wildcard semantics implemented and
   tested, scope→asset link, update/deactivate with audit.
4. **Slice D — Imports/Findings/Vulnerabilities/Components**: manual finding
   creation with its own fingerprint recipe, analysis runs with coverage,
   `GET /vulnerabilities` aggregate, artifact-level SBOM usage.
5. **Slice E — SAST viewer**: `code_analyses` intake (SARIF + OpenGrep JSON),
   coverage-aware classification, file/diff viewer, deep links from repo,
   project and finding.
6. **Slice F — Attack surface / Review / Exposures**: observation import,
   change categories, web surface, lookalikes, review queue, exposure events.
7. **Slice G — Cycles / My work / Dashboard**: cycle model + snapshot +
   state machine, work items/tasks queues, dashboard counters with deep links.
8. **Slice H — verification**: the 13 acceptance steps of §14 as an executable
   demo script plus per-feature isolation/dedup/coverage tests; capabilities doc
   splitting implemented / partial / pending.

## 13. Open decisions that change migrations

1. Application components: new table vs `services.kind` — recommendation: new
   `application_components` (service is a deployment unit, not a code unit).
2. Exposure vs finding boundary for imported scanner results: recommendation —
   exposures hold observations requiring a decision; findings hold weaknesses
   with a reproducible location; never both for the same identity.
3. Code analysis intake: create a repository implicitly when the report names a
   URL — recommendation: yes, with `source=import` provenance so it is not
   mistaken for a connected provider.

## 14. Progress log

### Slice B — shared model (2026-11-02)

Landed (backend + tests + console tabs, migration `0033_v0_inventory`):

| Piece | Evidence | Still missing |
|---|---|---|
| Application components + artifacts | `models.py` (`ApplicationComponent`, `Artifact`), `deployments.artifact_id` | No API/UI yet; deployments cannot be pointed at an artifact from the console. |
| Asset ownership & classification | `assets.owner/project_id/classification_status/notes/archived_at`, `PATCH /assets/{id}`, archive/unarchive, filters + search + paging (`easm.py`) | No asset↔deployment/version link from the UI; technology provenance table still absent. |
| Inventory groups | `inventory_groups.py` (CRUD, bulk membership, soft removal, stakeholders), `Assets.jsx` Groups tab | Dynamic groups, per-group findings view. |
| Needs attention | `GET /assets/needs-attention` with reason codes + actions, own tab | Rules are the four implemented ones only (owner, project, classification, staleness, deployment). |
| Activity | `GET /activity` over the audit ledger, Activity tab, audited asset/group/finding mutations | Import/run FKs are not attached to audit rows yet. |
| Finding ownership + narrative + evidence | `findings.assignee/cwe/impact/recommendation/reproduction`, `PATCH /findings/{id}/assignee`, comments, attachments (`findings.py`) | Detail screen fields, attachment export guard, comment edit/delete. |
| Manual findings (IDOR without CVE) | `POST /findings` with its own `manual|…` fingerprint recipe, dedup on repeat | Manual findings reach Findings list/detail; project screen not yet. |
| Findings list filters | search, severity, priority, assignee, source, pagination (`findings.py:get list`) | Asset/deployment/environment filters need the relations from slice C. |

Verification run for this slice: `pytest` 219 passed (incl. `tests/test_v0_inventory.py`,
8 cases covering N:M membership, removal keeping the asset, group deletion, org
isolation, needs-attention reasons, activity scoping, manual IDOR with no CVE,
assignment/comments/attachments); `alembic upgrade head` applied cleanly on a
throwaway PostgreSQL database; `npm run build` passes the UI import guard.

Not deployed: the image was not rebuilt, because the worktree also carries the
unfinished refresh-token work (`0032` is committed here only as the migration
parent of `0033`; its code half stays uncommitted).

### Slice C — Scope (2026-11-02)

Landed (migration `0034_scope_targets`, engine in `backend/app/scoping.py`,
console screen `Scope.jsx` under a new **Scoping** nav group):

| Piece | Evidence | Still missing |
|---|---|---|
| Normalization + matching engine | `scoping.py`: types, wildcard depth/apex, URL scheme+host+port+path-prefix, IP/CIDR containment, capability defaults | No IPv6 UI hint, no port-range rules. |
| Declared fields | `scope_targets.reason/owner/source/valid_from/valid_until/restrictions/capabilities/include_apex/asset_id`, `scope_exclusions.owner/status/expires_at` | Restrictions are stored, not enforced by any collector. |
| Decisions without side effects | `POST /scope/check` returns allowed/denied with the matching rule or the exclusion that won | No batch check across a group. |
| Exclusions prevail | Engine evaluates exclusions first; patterns cover concrete targets; expired exclusions stop applying | No exclusion templates or approval workflow. |
| Scope → inventory link | Concrete targets create/link the canonical asset with `source=scope`; patterns create nothing | No unlink action; asset screen does not yet show "declared in scope". |
| Validity, disable, audit | `PATCH /scope/targets/{id}`, `DELETE` disables by default (`hard=true` explicit), every mutation audited | No scheduled expiry job (state is computed per read). |
| Console | `Scope.jsx`: targets, exclusions, check panel, declare/exclude dialogs | Cycle selection still uses `ctem` counts only. |

Semantics are documented in `docs/architecture/scope-semantics.md` and pinned by
`backend/tests/test_v0_scope.py` (7 cases). Verification: `pytest` 226 passed;
`alembic upgrade head`, `downgrade 0034`, `upgrade head` all applied on a
throwaway PostgreSQL database; `npm run build` passes the UI import guard.

### Slice D (part 1) — Vulnerabilities aggregation (2026-11-02)

Landed: `routers/vulnerabilities.py` + `Vulnerabilities.jsx` (nav under Work,
next to Findings).

| Piece | Evidence | Still missing |
|---|---|---|
| CVE grouping over visible findings | `GET /vulnerabilities` (filters: project, severity, KEV, CVE search, pagination); a CVE with no finding and a manual IDOR never appear | Cross-organization "my team" scoping; CVSS vector display. |
| Detail | `GET /vulnerabilities/{cve}` returns the concrete findings with project, version, component purl, assignee | No deep link from a finding row (id rendered only). |
| Honest enrichment | KEV row + date/source/fetched_at, EPSS score/percentile/fetched_at, `exploit.known=false` with reason | No exploit feed; no re-evaluation record when intel changes. |
| Versions | `versions_known=false` + reason: v0 stores no advisory ranges | Affected/fixed version extraction. |
| Grouped action | `bulk-preview` (writes nothing) then `bulk-status` over exactly the previewed ids; suppressed rows skipped; every change audited | No permission pre-check beyond the viewer write guard. |

Verification: `pytest` 231 passed (5 new cases), `npm run build` passes the UI
import guard. No migration in this slice.

### Slice D (part 2) — coverage-gated closure + finding history (2026-11-02)

Landed (migration `0035_analysis_runs`): `analysis_runs` records tool, version,
revision, branch, base, coverage (`full|diff|partial|unknown`) and an explicit
`evaluated` map; `findings.last_evaluated_run_id` points at the run that judged
it. `POST /analysis/runs/{id}/close-unseen` previews by default and **refuses
(409) unless coverage is `full`**; a full run closes only open findings of the
same version whose tool matches and whose path was inside `evaluated.paths`.
Every closure is audited (`finding.closed_by_analysis`). `GET
/findings/{id}/history` merges audit rows, sightings, comments and attachments;
the Findings drawer now renders that timeline plus owner, CWE and narrative
fields.

Verification: `pytest` 235 passed (4 new cases: diff/partial refusal, tool/path
narrowing, validation + isolation, merged history); `alembic upgrade head` /
`downgrade 0035` / `upgrade head` on a throwaway PostgreSQL database;
`npm run build` passes the UI import guard.

Still pending in slice D: recording runs automatically from the OSV analyze path
and the SARIF/OpenGrep ingest, artefact-level SBOM usage, and the analysis-run
list screen (it lands with the SAST viewer in slice E).

### Slice E — SAST viewer intake (2026-11-02)

Landed (migration `0036_analysis_material`): `POST /api/v1/analysis/import`
accepts **SARIF 2.1.0 and OpenGrep/Semgrep JSON** end to end, plus optional code
snapshots and a unified diff. `analysis_files` stores the code we were given,
`analysis_findings` one row per result location with classification
(`new|persistent|resolved|no_reference`), `on_modified_line` and
`introduced_by_pr`. Viewer endpoints: `/runs/{id}/files`, `/file?path=`,
`/diff`, `/findings`; `Analysis.jsx` renders the tree, the code with a line
gutter and flagged lines, the diff hunks with finding positions, and the result
table. Formats and semantics documented in `docs/analysis-formats.md`.

Verification: `pytest` 241 passed (6 new cases: SARIF import + tree/code/diff,
re-import dedupe, OpenGrep JSON + missing snapshot, baseline new/persistent/
resolved, base tool/version mismatch 409, isolation + validation); migrations
`upgrade → downgrade 0036 → upgrade` on a throwaway PostgreSQL database;
`npm run build` passes the UI import guard.

Still missing for §10: source→sink traces (kept only as a count), analysis
history screen per repository/project from Components/Assets (deep links land
with the nav restructure), PR intake from a connected provider (post-v0).

### Slice F (part 1) — observations, changes, exposures (2026-11-02)

Landed (migration `0037_attack_surface`): `observations` (kind, subject, port,
value, source, **coverage**), `exposure_events` with a stable identity and an
explicit reopen policy, `exposure_decisions` as history.
`POST /observations` imports observations, derives changes and manages events;
`GET /attack-surface/changes` derives the chronology on read; `GET
/exposures`, detail with decision history, `POST /exposures/{id}/decide`;
`GET /exposures/summary/findings` returns secrets/code-weaknesses/
misconfigurations/vulnerabilities as filtered summaries over the same findings.
Console: **Exposures** under a new *Discovery* group, with Overview, Changes and
the four summaries.

Honesty rules pinned by tests: changes require equal **full** coverage (a failed
collection yields a coverage note, never `closed_port`/`host_disappeared`); the
same condition observed again bumps `occurrences` instead of creating a second
event; accept requires a reason and a future validity; a resolved event reopens
on a new observation under `on_new_observation`, while an accepted one holds
until its window expires.

Verification: `pytest` 245 passed (4 new cases); migrations `upgrade → downgrade
0037 → upgrade` on a throwaway PostgreSQL database; `npm run build` passes the
UI import guard.

**Still missing in slice F**: Web surface (paths/origins, excluded-as-unevaluated),
Lookalikes (watch roots, candidates, review states, passive-only), Review queue
(ownership confirmation, external/discard), the weekly summary query, and the
lookalike/web-surface importers. Declared pending, not claimed.

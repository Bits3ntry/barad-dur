# Backlog — prioritized, with IDs

Rules: every item carries ID, objective, priority (P0 blocks product claims /
P1 next iteration / P2 later), dependencies, acceptance criteria, tests (T),
and real status. Statuses: `designed` | `in_progress` | `landed` (with gate
picture) | `todo`. Anything else is NOT implemented.

## AI harness — review 2026-11-14 (active workstream)

Source: `docs/planning/ai-integration-review.md` — the measured state, the evidence
for each defect, and the full acceptance per phase live there. IDs map 1:1: BL-110 =
A1, … BL-119 = A10. **Sequence** (§7 of the review, not numeric order): A2 → A1 → A3 →
A5 → A4 → A8 → A6 → A9 → A10 → A7. Every item's definition of done includes a number
read from the running stack, not from the logs.

**Landed on `feat/ai-flow-100` (2026-11-14, uncommitted — the tree's untracked AI
subsystem has to be committed by its owner first):** BL-110, BL-111, BL-112 complete;
BL-113 and BL-114 partial (see their rows). Proof: `tests/test_ai_ledger.py` (8 tests),
whole backend suite green, migration `0083` applied on the live stack (`ai_settings`
now reads 12/6 with `updated_by` null → reconciled), `/ai/spend` counts field steps,
and the console serves the bundle that renders the receipt.

- **BL-110 One ledger for every token** (A1) — objective: `agent_missions.run_id` set at
  creation (`create_mission` + `scan_cycle`); `/llm/complete` writes
  `AiStep(role="field")` and increments the run, so the mission ceiling and the monthly
  cap both bind. **P0** (the spend meter reads 7,156 tokens for a month in which the
  field half alone reported 143,959 in its final turns) | deps none | AC: a mission's
  tokens move `/ai/spend` by the same amount, and a mission at its ceiling answers
  `429 mission token budget reached`; T: `tests/test_ai_ledger.py`;
  status `landed` (`feat/ai-flow-100`: run created with the mission + lazy self-heal in
  `/llm/complete`, `AiStep(role="field", phase=task.kind)`, `max_tokens` passthrough,
  `_narrow_tools` filters the offered schema to the envelope; `/ai/spend` splits the
  month by `mode` — ask / mission / compact — so the field half cannot hide behind
  the chat's cents, and `/ai/runs?mode=` filters the ledger).
- **BL-111 Ceilings that cannot go stale** (A2) — objective: seed/patch `ai_settings`
  in the migration that declares the defaults (12 steps / 6 specialists) and set both
  monthly caps on the live row; a test asserts the live row equals the model defaults
  after `alembic upgrade head`. **P0** (a CVE question on the live stack ends
  `stopped_max_steps` with no answer and never reaches `evidence.report`) | deps none |
  AC: a CVE question answers through the report step; `GET /ai/settings` reads 12/6;
  T: the stub chain at both settings values; status `landed` (`feat/ai-flow-100`:
  migration `0083` reconciles untouched rows, and `orchestrator` runs the terminal
  report even when the specialist cap truncates the chain, recording each skip in the
  step's receipt).
- **BL-112 The answer carries its receipt** (A3) — objective: persist `citations` on the
  assistant turn from the run's claims and tool refs, render them as chips that
  navigate, add the run card (steps · tool calls · tokens · status) opening
  `#ai-runs::<id>`, inject the session's `subject_kind/subject_id` in `assemble()`, and
  give `chat_pins` a UI. **P0** (the guide promises every answer renders evidence chips;
  today the chat renders plain prose and `citations` is hard-coded `[]`) | deps none |
  AC: a chip lands on the finding; the card's numbers equal `GET /ai/runs/{id}`;
  T: chat + turn assertions; status `landed` (`feat/ai-flow-100`: `_citations` reads the
  run's own steps into the turn, chips navigate to `#search::<ref>`, the card opens
  `#ai-runs::<id>`, `subject_digest` reaches `assemble()`, pins have a UI).
- **BL-113 Stop burning field steps on a misdiagnosed call** (A5) — objective: separate
  `malformed_call` from `not_allowed` (28/28 allowlist refusals carried `tool: null`,
  i.e. `run_tool({})`), return the schema instead of an accusation, filter
  `payload.tools` against the mission's allowlist in `/llm/complete`, and normalise a
  mission target to its origin in the create form. **P1** | deps none | AC: zero
  `tool: null` allowlist refusals across the next 20 missions; T: worker loop +
  gateway; status `partial` (`feat/ai-flow-100`: the gateway narrows the offered
  `run_tool` enum to the envelope **and** a URL mission target is normalised to its
  origin with the value as written kept in `declared` — the 14 same-origin envelope
  refusals can no longer happen. What is left needs the Shauron checkout, which is not
  in this workspace: the worker's `malformed_call` message and recording the tool name
  on a refusal).
- **BL-114 The await stops being a held request** (A4) — objective: `proxy_read_timeout`
  on the console's `/api/`, `POST /ai/runs` returns the id immediately with the loop in a
  background thread, console polls the run. **P1** | deps BL-110 (a background run must
  close its own ledger row) | AC: a 7-call chain survives the console proxy; closing the
  tab still leaves a closed run; status `landed` (`feat/ai-flow-100`: console proxy at
  300s, `POST /sessions/{id}/turns` with `background: true` returns **202 + run id** and
  finishes in its own session/thread, the client polls `GET /ai/runs/{id}`, and both
  paths share one `_finish_turn` so the receipt cannot land on only one of them).
- **BL-115 Prompts you can see, edit and define** (A8) — objective: `ai_prompts` versions
  with one active per key, `resolve(key)` falling back to `specialists.py`, the set frozen
  at the start of `execute()`, `ai_steps.prompt_version = "<key>@<n>"`,
  `agent_specs.prompt_key`, the editor with per-version receipts and `mode="eval"` runs,
  and `/llm/complete` injecting the active `field.generic` body so the field prompt is
  editable without rebuilding the Shauron image. **P1** (revises D24) | deps BL-110,
  BL-111 | AC: two versions of `intel.cve` compared on the same question in the ledger;
  a zero-row database answers exactly as today; status `landed` (`feat/ai-flow-100`:
  `ai_prompts` + migration `0084`, `prompts.freeze()` at the start of every run,
  `ai_steps.prompt_version = "<key>@<n>"`, `/ai/prompts` GET/POST/PATCH/activate with
  per-version receipts, the field prompt injected by `/llm/complete`, and the Prompts
  screen).
- **BL-116 The channel, over one ledger** (A6) — objective: `ai_runs.session_id`,
  `agent_specs` as identity + tool **ceiling** (`effective = mission.tools ∩ spec.tools`),
  one thread endpoint merging `chat_turns` + `ai_steps` + `agent_task_events` by time,
  and retirement of `agent_runs`/`agent_messages`/`agent_artifacts` (0 rows each). **P1**
  | deps BL-110, BL-112 | AC: one thread shows five delegations plus a mission with the
  same tokens/steps/cost as the ledger; no screen reads a 0-row table; status `partial`
  (`feat/ai-flow-100`: `ai_runs.session_id` + migration `0085`, a mission can be created
  from a thread, `GET /ai/sessions/{id}/thread` merges the three tables by time with
  totals, and `Chat.jsx` has a *relaciones* view. Left: retiring
  `agent_runs`/`agent_messages`/`agent_artifacts`, which is a destructive migration and
  belongs in its own deliberate step).
- **BL-117 The meter says allowance** (A9) — objective: read `usage.opencode.allowance`,
  store it beside `cached_tokens`, render "% of this month's plan" when no price exists.
  **P2** | deps BL-110 | AC: a live completion writes an allowance figure and `/ai/spend`
  shows a percentage; status `partial` (`feat/ai-flow-100`: the provider's `usage` block
  is stored verbatim on `ai_steps.usage_json` — minus the counters already in columns —
  and `/ai/spend.provider_usage` shows it as reported, rendered in Settings. The
  percentage is the remaining half and it waits for one real response: interpreting a
  number whose unit we have not seen is the guess this design refuses).
- **BL-118 Quality regression, not just budget** (A10) — objective: a golden set (~12
  questions with expected facts) + `ai_feedback` (D24's missing half), folded with
  `ai_budget_baseline.json`. **P1** | deps BL-115, BL-110 | AC: CI fails when a prompt
  version loses an expected fact or doubles the tokens; the editor shows the score per
  version; status `todo`.
- **BL-119 Code reachability** (A7) — objective: `repository.code_access`, the index,
  then `code.search`/`code.slice` (query) and `code.analyze` (field); today
  `code_files` is 0 rows across 10 repositories, so every verdict says
  `unknown` on reachability. **P2** (its own campaign; scanner-shaped) | deps none |
  AC: one verdict names `(repository, ref, commit, fetched_at)` or `code_access=none`;
  status `todo`.

Micro-fixes with no phase of their own (max_tokens ignored, `cached_tokens` never
returned, caps `NULL`, dead `engine.execute`) are listed in §7c of the review and ride
along with the phase named there.

## Phase 2–3 (scopes + supply chain)

- **BL-010 Repo/Service/Deployment entities** — objective: platform entities
  for repository, service, deployment + typed relations project↔repo,
  component↔service. **P0** | deps none | AC: CRUD via API, FK from findings
  navigable, migration 0009; T: pytest CRUD + FK navigation test; status
  `landed` (`d6bc72e`: 0009+0010 migrations on live Postgres, N:M links, asset
  polimórfico y finding-contexts, suite test_bl010_relationships.py toda
  verde + gate live en AUDIT.md).
- **BL-015 observed-vs-authorized split** — objective: `scan_grants` +
  `scan_grant_targets` binding principals to capabilities over targets with
  approver + window; engine authorize() default-deny; exclusions beat grants;
  Shauron surface under /api/v1/authorization. **P0** (safety-critical) | deps
  BL-010 | status `landed` (`7500414`+`5f6865d`: engine + API + 10 tests with
  multi-tenant isolation, gate live in AUDIT.md incl. mid-run revocation).
- **BL-040 Occurrences** — objective: one finding keeps occurrence rows (per
  scan run/asset/commit) instead of refresh counters; enables history replay.
  **P1** | deps none | status `landed` (`f6725a5`: migration 0013, ingest
  wired, GET /findings/{id}/occurrences, idempotent sighting keys, 3 tests +
  live gate).
- **BL-060 License policies** — objective: license set per component, policies
  with allow/deny + report per version. **P1** | deps components (live) |
  status `landed` (`9139ecf`: component_licenses (multi-license, idempotent),
  org/project policies, deterministic evaluator, expiring exceptions, 6 tests
  + live gate: GPL denied → exception → excepted; console Licenses tab).
- **BL-025 SPDX export + ingest receipts surfacing** — export `landed`
  (SPDX 2.3 JSON, 2 tests, live gate); SPDX *ingest* still pending. **P2**.
- **BL-065 Signed feed trust** — objective: office signing of the
  vulnerability catalog sync (concept from their vulnfeed) with key pinning.
  **P2** | deps BL-060 not blocking.
- **BL-070a Continuous reanalysis scheduler** — objective: periodic per-org
  OSV/KEV/EPSS re-run + reconcile; **P1** | deps none | AC: job + counters +
  honest reconcile idempotency; T: pytest + live second-run gate.
- **BL-030 Multi-org** — objective: org switcher console endpoints + scoping
  checks; **P1** | deps none platform-side | tests behind key→org mapping.

## Phase 3 (vuln management deepening)

- **BL-045 Evidence vault** — objective: findings carry evidence refs (redacted
  boundary preserved); **P1** | deps BL-040.
- **BL-055cf Gate policies** — objective: gate thresholds/hard_rules into
  policy table with overrides + approval; status `landed` (BL-055: org/project
  gate policies, deterministic evaluator with severity/KEV/license rules,
  audited; console tab; 6 tests + live gate).
- **BL-040b SARIF + baselines** — status `partial` (ingest + version diff via
  occurrences landed with 4 tests; inline code/diff viewer and PR status
  publishing still pending).
- **KEV→priority automation** — objective: rule type `intel.kev` in priority
  rules; **P0** (few hours, direct value) | AC: known-exploited CVE → P0
  reclassification + reclass counter; T: pytest with stubbed KEV fetch; status
  `designed`.

## Phase 4–5 (pentest, Jira, SAST review)

- **BL-070 Pentest campaigns** — objective: campaigns/engagements/tests/notes/
  evidence/report + retest status; finding linkage mandatory. **P1** | deps
  BL-015 (authorization), BL-010.
- **BL-050 Jira bridge** — objective: outbox → Jira create/update + webhook
  inbound with idempotency keys, loop prevention, state-mapping table.
  **P1** | deps issue-like entity (BL-050a) | AC: bidirectional reconciling
  test with fake Jira; no duplicate tickets across two sends.
- **BL-040b SARIF + baselines + PR screens** — objective: ingest SARIF from
  engines/cameras, branch baseline compare, inline code viewer path, QG
  override surface. **P1** | deps BL-010 | AC: SARIF import → findings with
  same fingerprints; baseline diff list; screens read-only POC. 

## Phase 6–8

- **BL-090 EASM probing jobs** — status `partial`: snapshots + change
  detection landed (`test_bl090_snapshots.py`, live gate); active DNS/TLS
  collectors and scheduled sweeps still pending, gated by scan grants.
  **P1** | deps assets live | AC: snapshot diff endpoint; loopback-safe,
  passive only without BL-015 grant.
- **BL-080 Regression suites** — authorized HTTP test suites with variables,
  auth injection, assertions, secret redaction, rerun per version; **P2**
  | deps BL-015 | AC: suite run stores assertions results, reruns produce
  occurrences tied to versions.

## Phase 9

- **BL-100 DT/Dojo retirement path** — decision record + gradual endpoint
  deprecation; **P2** | deps everything above.
- **BL-101 Ops** — backups (pg_dump schedule to migration-backup volume
  contract), metrics endpoint, downtime runbook; **P1** before prod claims.
- **BL-102 LICENSE + attribution doc** — decided 2026-10-31: proprietary/private
  for now; no GPL/AGPL adoption; dependency obligations (Composition, not
  linking: Apache-2.0 engines) documented in `docs/planning/compatibility-
  and-licenses.md`; status `landed` (decision recorded; LICENSE file still
  pending if distribution ever happens).

### Pending limitations (console round, carried after validation)

- Grant PATCH/conditions editor absent — grant-level conditions deny (honest)
  until an owner for that evaluator exists.
- Occurrence history has no pagination in the UI (server endpoint paginates
  nothing yet either); acceptable at current scale.
- Audit filter by capability is a prefix match, not an exact-field filter.

### Next objective queued

- **BL-060 License Management** — next phase after this round's merge; not
  started; no code, schema or UI change for it lives in this branch.

## BL-020b — Worker container isolation (done)

`barad worker --isolate-image <img@sha256:...>` composes a digest-pinned
throwaway container (no network, read-only rootfs, noexec tmp, all caps
dropped, uid 65534, 1g/1cpu/256 pids, target read-only) and refuses to build
anything unsafe. Remaining: ship a Shauron image that carries the scanners so
the sandbox can run a real scan without the host engines.

## BL-020c — Sandbox image shipped (done)

`deploy/shauron/Dockerfile` + `sandbox.barad.yml` produce an image that runs a
real scan (Trivy secret/misconfig + OpenGrep SAST) with no network, read-only
root and non-root user. Verified through the orchestration API. Multi-arch build (linux/amd64 + linux/arm64,
per-arch Trivy digests, per-arch base images) is verified in both architectures;
remaining: shipping a pre-populated Trivy database, since the sandbox cannot
update it, and a Windows container image (not supported — Windows hosts run the
worker against these Linux images).

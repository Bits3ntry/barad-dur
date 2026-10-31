# Backlog — prioritized, with IDs

Rules: every item carries ID, objective, priority (P0 blocks product claims /
P1 next iteration / P2 later), dependencies, acceptance criteria, tests (T),
and real status. Statuses: `designed` | `in_progress` | `landed` (with gate
picture) | `todo`. Anything else is NOT implemented.

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

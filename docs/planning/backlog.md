# Backlog — prioritized, with IDs

Rules: every item carries ID, objective, priority (P0 blocks product claims /
P1 next iteration / P2 later), dependencies, acceptance criteria, tests (T),
and real status. Statuses: `designed` | `in_progress` | `landed` (with gate
picture) | `todo`. Anything else is NOT implemented.

## Phase 2–3 (scopes + supply chain)

- **BL-010 Repo/Service/Deployment entities** — objective: platform entities
  for repository, service, deployment + typed relations project↔repo,
  component↔service. **P0** | deps none | AC: CRUD via API, FK from findings
  navigable, migration 0009; T: pytest CRUD + FK navigation test; status `todo`.
- **BL-015 observed-vs-authorized split** — objective: `scan_authorizations`
  table binding assets/scopes to allowed profiles with approver + window;
  intrusive endpoints reject without a grant. **P0** (safety-relevant), deps
  BL-010 | AC: nuclei-class profile → 403 without grant; audit entry on grant;
  T: pytest + live gate; status `designed` (see scopes doc).
- **BL-060 License policies** — objective: license set per component, policies
  with allow/deny + report per version. **P1** | deps components (live) |
  AC: upload SBOM with licenses → component carries license + policy verdict;
  T: pytest; status `todo`.
- **BL-025 SPDX export + ingest receipts surfacing** — objective: SPDX 2.3
  export alongside CycloneDX. **P2** | deps none.
- **BL-065 Signed feed trust** — objective: office signing of the
  vulnerability catalog sync (concept from their vulnfeed) with key pinning.
  **P2** | deps BL-060 not blocking.
- **BL-070a Continuous reanalysis scheduler** — objective: periodic per-org
  OSV/KEV/EPSS re-run + reconcile; **P1** | deps none | AC: job + counters +
  honest reconcile idempotency; T: pytest + live second-run gate.
- **BL-030 Multi-org** — objective: org switcher console endpoints + scoping
  checks; **P1** | deps none platform-side | tests behind key→org mapping.

## Phase 3 (vuln management deepening)

- **BL-040 Occurrences** — objective: one finding keeps occurrence rows (per
  scan run/asset/commit) instead of refresh counters; enables history replay.
  **P1** | deps none | AC: two scans same finding → 2 occurrences, one finding;
  T: pytest + dedup unchanged.
- **BL-045 Evidence vault** — objective: findings carry evidence refs (redacted
  boundary preserved); **P1** | deps BL-040.
- **BL-055cf Gate policies** — objective: gate thresholds/hard_rules into
  policy table with overrides + approval; **P1** | env gate stays fallback.
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

- **BL-090 EASM probing jobs** — DNS/TLS service probe, tech fingerprint,
  snapshot history; **P1** | deps assets live | AC: snapshot diff endpoint;
  loopback-safe, passive only without BL-015 grant.
- **BL-080 Regression suites** — authorized HTTP test suites with variables,
  auth injection, assertions, secret redaction, rerun per version; **P2**
  | deps BL-015 | AC: suite run stores assertions results, reruns produce
  occurrences tied to versions.

## Phase 9

- **BL-100 DT/Dojo retirement path** — decision record + gradual endpoint
  deprecation; **P2** | deps everything above.
- **BL-101 Ops** — backups (pg_dump schedule to migration-backup volume
  contract), metrics endpoint, downtime runbook; **P1** before prod claims.
- **BL-102 LICENSE + attribution doc** — decision + LICENSE file (see
  compatibility doc); **P0** (repo hygiene, blocks any distribution claim).

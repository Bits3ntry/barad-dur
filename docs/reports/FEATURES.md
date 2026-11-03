# Barad-dûr — functional inventory

Generated from the running code, not from documentation: 136 API paths
(`/openapi.json`), 64 tables, 28 migrations, 18 console screens, 175 backend
tests + 177 CLI tests passing on this commit.

Legend: **COMPLETE** = backend + UI + tests + verified against the live stack.
**PARTIAL** = works but has a declared limit.

---

## 1. Identity and access

Backend (10 endpoints under `/api/v1/auth`, 3 under `/org`, 3 under `/members`)
- First account via one-time `BOOTSTRAP_TOKEN` (`POST /auth/bootstrap`).
- Email/password login → session token; logout revokes it; disabling a user
  revokes their sessions.
- Roles `viewer < analyst < admin < owner`, enforced server-side; write methods
  require analyst, administrative surfaces require admin.
- Service identities: organization API keys (create, list, revoke; the last
  active key cannot be revoked).
- Worker tokens scoped to the worker endpoints only (a compromised worker
  cannot read findings, grants or audit).
- Password change for the signed-in user (`POST /auth/users/{id}/password`).
- OIDC: `start`, `callback` and `status` for configured providers.
- `GET /auth/me` for identity probing (the console uses it to prove a key before
  storing it).

Console
- **Entrance screen**: sign-in (email, password, optional org) and API-key
  modes; a key is validated before it is stored; rejected credentials leave
  nothing behind.
- **Settings** modal: platform URL, key, sign-in, identity detail, key
  management (create/revoke).
- **Members**: accounts, invitations/memberships, roles, audit of changes.
- Session chip and sign-out in the top bar.

Status: COMPLETE. Limit: the entrance has no OIDC button or password reset yet.

## 2. Scope and scan authorization (BL-015)

Backend (8 endpoints under `/authorization`)
- Grants carry capabilities (`passive_discovery`, `active_verification`,
  `vulnerability_analysis`, `intrusive_testing`), tools, targets and conditions.
- Target types: domain, wildcard subdomain, CIDR, URL, repository, service.
- Default deny; exclusions always win and expire grants; revocation is
  immediate; unknown conditions fail closed.
- `POST /authorization/authorize` simulates a decision without side effects;
  `POST /grants/{id}/revalidate` re-runs the invariants on an existing grant.
- Every decision is audited in the per-org SHA-256 chain.

Console
- **Grants**: server-side filters, create grant, simulate `authorize()` against
  a target, revoke; shows expiry and revocation reason.
- **Audit trail**: filterable log with chain verified/broken indicator.

Status: COMPLETE. Invariant: no active scan path bypasses this gate — job claims
re-evaluate the grant and fail the job when it is gone.

## 3. Inventory, projects and attack surface

Backend (projects 2, repositories 1, services 1, deployments 1, assets 7,
scope 3)
- Organizations → projects → versions; repositories, services and deployments
  linked many-to-many; a project can own several domains and share
  infrastructure with another project.
- Assets: domain, subdomain, IP, CIDR, URL, service; ownership, criticality,
  tags, links to projects/services.
- Passive discovery (`crt.sh`) and active collection (DNS A/AAAA, TLS) each
  gated by their own capability; a denied collection writes no partial snapshot.
- Asset snapshots with field-level change detection between consecutive
  snapshots (IP, technology, TLS issuer, …).

Console
- **Assets**: seed a domain and discover, per-asset collect, snapshot recorder,
  history with changes since previous snapshot.
- Dashboard posture table links project → findings.

Status: COMPLETE (v1). Limit: no scheduled TLS collection (TLS stays explicit).

## 4. Supply chain (Dependency-Track replacement)

Backend (sbom 4, spdx 2, components 2, licenses 7, vex 1, sbom baselines 1)
- CycloneDX and SPDX ingestion (SPDX normalised through the CycloneDX pipeline
  to inherit idempotency), export to SPDX 2.3.
- Components with PURLs, versions, direct/transitive flag, per-project-version
  usage, cross-project impact.
- OSV/GHSA/PYSEC correlation with CVE aliasing, KEV and EPSS enrichment, VEX.
- License inventory, policies, exceptions with approval, evaluation.
- Version-to-version SBOM comparison (added/removed/changed) and named SBOM
  baselines.
- Re-ingest is idempotent: duplicates return the original receipt, never a
  second component or finding.

Console
- **Components**: inventory per project/version, impact view, SBOM import.
- **Licenses**: inventory, policies, exceptions, evaluation result.
- VEX panel inside the finding detail.

Status: COMPLETE.

## 5. Findings, occurrences and remediation

Backend (findings 7, suppressions 3, remediation 4, priority 1, sla 1, intel 3,
analyze 1, sarif 2, imports 1)
- Kinds: vulnerability, secret, misconfiguration, code-weakness, license.
- Findings are per-target consolidations; every sighting is an occurrence with
  its own version/scan/evidence — dedup never merges unrelated issues.
- Priority rules (severity, KEV, EPSS, criticality), SLA policies with deadlines.
- Status lifecycle with reasons: open, acknowledged, in progress, resolved,
  suppressed, false positive; suppression requires a second approver (409 on
  self-approval) and can expire.
- Remediation tasks with linked findings, owners and state.
- SARIF import, ad-hoc analysis endpoint, external imports.

Console
- **Findings**: filters (project, version, kind, suppressed), priority/severity/
  SLA/status columns, detail with tool, location, component, intel, occurrences,
  Jira link, task creation, disposition.
- **Remediation**: task board, priority rules, SLA policies.

Status: COMPLETE.

## 6. Pentest management (DefectDojo replacement)

Backend (9 endpoints under `/pentest`)
- Engagements scoped to project/version with lead, methodology, window, status.
- Tests (methodology, tester, state) and findings with target, method, CVSS,
  reproduction, HTTP request/response evidence, remediation.
- Retest/verification: only verification evidence closes a finding.
- Reports: JSON, printable self-contained HTML, and PDF (dependency-free
  writer) with scope, tests, evidence, remediation and verification.

Console
- **Pentests**: engagement list, detail with tests and findings, evidence entry,
  status transitions, retest, report HTML/PDF links.

Status: COMPLETE. Limit: no report template editor.

## 7. Code security and pull request review

Backend (13 endpoints under `/code`)
- Repositories, branches, commits, pull requests.
- SARIF ingestion with per-finding classification: new, existing, baselined
  (only from an **approved** named baseline; drafts silence nothing).
- Gate evaluation per PR with explainable reasons; verdicts recorded.
- Source context around a finding and base↔head diff, both redacted (secret
  material never crosses the API).
- Publishing: GitHub commit status + idempotent comment + check run with inline
  annotations; GitLab commit status + idempotent note + inline discussions
  anchored to diff positions. Missing token → 503 naming the variable.
- Named baselines with two-person approval, audit and per-PR counters.

Console
- **Pull requests**: list with gate verdict and new/existing/baselined counts,
  review view grouped by file, source context, diff viewer, publish, baseline
  panel (snapshot from PR, approve/reject).
- **Pipelines**, **Quality gates**: CI runs and policy evaluation.

Status: COMPLETE. Limits: republishing an MR adds discussions rather than
updating them; GitLab annotations are discussions, not check annotations.

## 8. Security regression testing

Backend (4 endpoints under `/regression`)
- Reusable HTTP checks with variables, headers, auth context, typed assertions
  (`status_equals`, `body_contains`, `header_absent`, …), suites, environment and
  version scope, optional link to a pentest finding.
- Every run calls the authorization engine for the exact URL; without a grant
  the run is 403 and nothing is sent. POST/PUT/PATCH/DELETE additionally require
  `intrusive_testing`.
- Reintroduction detected only when a previously green check fails.

Console
- **Regression**: checks, run, history per check.

Status: COMPLETE.

## 9. Policies and quality gates

Backend (gates 4, license policies 3)
- Gate policies (max severity, block KEV, block denied licences) evaluated
  deterministically with a reason list; used by CI, PR and console evaluation.
- License policies and exceptions with approval.
- Priority and SLA policies feed finding classification.

Console
- **Quality gates**: policy list, evaluate for project/version, verdict with
  reasons; license policy panels under Licenses.

Status: COMPLETE.

## 10. Orchestration (Shauron execution plane)

Backend (16 endpoints under `/orchestration`)
- Scanner registry with capabilities and versions; worker registry with health.
- Jobs: `queued → leased → running → succeeded | failed | cancelled`, leases
  with expiry, heartbeat, `max_attempts` retry, concurrency ceiling, cancellation.
- Authorization re-evaluated at claim time; a revoked grant fails the job.
- Results are summaries plus artifacts (manifest, log, SBOM, SARIF); the
  management plane never executes scanner code.
- Scan schedules with idempotent tick.

Execution plane (CLI, 4 commands)
- `barad scan`, `barad run`, `barad health`, `barad worker`.
- Worker claims authorized jobs, runs OpenGrep + Trivy locally, uploads SBOM
  (CycloneDX) and SARIF, reports real counters.
- `--isolate-image`: digest-pinned throwaway container, no network, read-only
  root, non-root uid, cpu/memory/pids limits, no Docker socket; refuses
  privileged or unpinned compositions.
- Image ships CLI + Trivy + verified OpenGrep engine, built for linux/amd64 and
  linux/arm64 with per-arch digests.

Console
- **Orchestration**: scanners, workers, jobs, schedules, enqueue and cancel.

Status: COMPLETE. Limits: the sandbox image cannot update the Trivy database
(no network); no Windows container image (Windows hosts run the worker against
these Linux images).

## 11. Dashboards and reporting

Backend (dashboard 2, notifications 5, audit 1)
- Summary for organization/project/version: findings by severity, KEV, SLA,
  new/resolved, assets, occurrences, remediation, CI verdicts, gate, supply
  chain, orchestration health, pentest.
- Project posture table.
- Notifications: signed webhook channels and SMTP email channels, SLA breach
  tick with per-channel-per-day dedupe, honest `smtp_not_configured` failures.

Console
- **Dashboard**: scope selector, finding metrics, assets/CI/remediation cards,
  scanner execution card, pentest card, gate banner, clickable posture table.
- Pentest and asset reports as HTML/PDF from their screens.

Status: COMPLETE (v1). No charts by design (no chart dependency).

## 12. Administration and operations

Backend and deployment
- Health endpoint, 28 migrations, audit chain with full-chain verification.
- Docker Compose: Postgres, platform API (loopback 8090), console (loopback
  8092); no port exposed beyond 127.0.0.1.
- Documented deploy/upgrade procedure, backup and restore, secrets handling
  (`.env` chmod 600, no secret ever printed or committed).
- Multi-tenant isolation asserted by tests across every module.

Console
- **Members** (users, roles, audit), **Settings** (connection, keys), **Audit
  trail**.

Status: COMPLETE.

---

## Console UX summary

- Shell: grouped sidebar (Overview, Supply chain, Code, Testing, Operations,
  Administration), hash deep-links, breadcrumb, session chip, sign-out.
- Entrance: dedicated sign-in screen; nothing renders without credentials.
- Design system: obsidian ground, one ember accent, brand mark, tabular numbers,
  responsive down to phone width, focus rings, hover/disabled states.
- Shared primitives: page header, card, table (with empty slot), empty state,
  loading skeletons, error banner with retry, two-step confirm button, modal.
- States: every migrated screen has loading, empty, error+retry and read-only
  rendering; tables scroll inside their own container.

## Known gaps (explicit)

1. Detail views for findings and pull requests are expanded table rows, not
   side panels.
2. Destructive actions in a few legacy screens still use `window.confirm`/
   `prompt` instead of the two-step button.
3. Dark theme only; no density toggle.
4. No password reset / OIDC button on the entrance.
5. No charts (deliberate: no chart dependency).
6. Notifications have no per-finding push; one aggregated event per channel per
   day.
7. Scheduled EASM collects DNS only; TLS stays an explicit action.
8. Sandbox image cannot update the Trivy vulnerability database.

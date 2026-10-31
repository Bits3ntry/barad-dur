# Verification ledger

This ledger records observed checks for the current architecture. It does not turn unrun checks into claims.

## 2026-10-31 Code diff viewer (PR base↔head)

| Item | Result | Evidence |
|---|---|---|
| File diff | PASS live | `GET /code/diff?repository_id&from_ref&to_ref&path` produces a structured unified diff (hunk/added/removed/context rows) from the indexed snapshots; every line is redacted. Live: adding `token = "sk-live-..."` in head produced `token=[REDACTED]` and `secret leaked: false`. |
| PR diff | PASS live | `GET /code/pull-requests/{id}/diff` diffs base↔head for every file carrying PR findings. Live PR #2001: status `diff`, +3/−1, hunk header and rows correct. |
| Honest states | PASS | A missing baseline is `missing_base` (or `missing_head`), never "no changes"; a PR without repository/branch context is `missing_refs`. Both pinned by tests — absence of a baseline is not evidence of safety. |
| Console | PASS | Each file in the review panel gains `show diff`, rendering added/removed lines with +/− gutters and a diff-unavailable message when snapshots are missing. |
| Tests | PASS | 3 in `test_code_diff.py` (generic diff + redaction, missing-base honesty, missing-refs + isolation). Suite total 130. |

Known limits: diffs are per-file and line-based (no rename/move detection),
and only files with findings get a PR diff entry.

## 2026-10-31 EASM collection (DNS passive, TLS active)

| Item | Result | Evidence |
|---|---|---|
| DNS discovery | PASS live | `POST /assets/{id}/collect` resolves A/AAAA via stdlib `getaddrinfo` and stores the observation as an asset snapshot (source `dns-collector`), refreshing `last_seen`. Live: `api.councilbox.com` → `52.143.19.233`. No grant → 403 and **nothing stored** (snapshot count stays 0, pinned by test). |
| TLS probe | PASS live | Optional handshake records issuer/subject/validity/TLS version/cipher. It is active verification: it needs `active_verification` for the exact domain, and with only `passive_discovery` the call returns 403 `tls probe not authorized` and writes no half-snapshot (verified live and by test). |
| Honest failures | PASS | A host with no TLS listener returns the socket/certificate error inside the observation instead of a fabricated certificate; DNS resolution failure → 502 `dns resolution failed`. |
| Validation | PASS | Only `domain`/`subdomain` assets collect (422 otherwise); foreign-org asset → 404; every action audited (`easm.collected`, `easm.collect_denied`, `easm.tls_denied`). |
| Change history | PASS live | Collected snapshots flow into the existing `/changes` diff: live comparison surfaced `dns`, `ip`, `tech`, `tls_issuer` against earlier manual observations. |
| Console | PASS | Assets rows for domain/subdomain gain a `collect dns` action that reports the observed address count and reloads. |
| Tests | PASS | 4 in `test_easm_collect.py` (grant required, DNS snapshot, TLS needs active grant + no partial write, validation/isolation). Suite total 127. |

Known limits: no scheduled collection yet (schedules cover scan jobs only),
no certificate chain/history beyond the latest snapshot, and no technology
fingerprinting (HTTP fingerprinting is intentionally not implemented).

## 2026-10-31 SPDX ingest + SBOM version comparison

| Item | Result | Evidence |
|---|---|---|
| SPDX ingest | PASS live | `POST /spdx/import` accepts an SPDX 2.3 JSON document, maps packages → components (name, versionInfo, purl from `externalRefs`, declared licenses split on AND/OR/WITH) and runs the existing CycloneDX pipeline, so idempotency, findings correlation and licensing come for free. `NOASSERTION` versions stay unknown instead of being invented. Non-SPDX input → 422. |
| Round-trip | PASS live | Exported `lic-live@1.0` (3 packages) and imported it as `spdx-roundtrip@1.0`: 3 components created, both licenses of the multi-licensed component preserved (`BSD-3-Clause` + `MIT`), `Apache-2.0` intact. |
| Idempotency | PASS | A repeated import returns `status: duplicate` and does not duplicate components/links (receipt exposes the original counters). |
| Version comparison | PASS live | `GET /sbom/compare?project&from_version&to_version` diffs components by name: added / removed / changed (version moves), unchanged stays quiet; unknown version → 404. Live: `worker-live` 1.0 vs 1.1 correctly reports no drift (both scans identical). |
| Tests | PASS | 4 in `test_spdx_ingest_compare.py` (import+licenses+idempotency, non-SPDX rejection, compare added/removed/changed, tenant isolation). Suite total 123. |

Known limits: SPDX import maps only identity and licenses (no SPDX
relationships graph), and the comparison compares two versions rather than a
stored baseline snapshot.

## 2026-10-31 Scan schedules + printable pentest report

| Item | Result | Evidence |
|---|---|---|
| Schedules | PASS live | Recurring definitions (scanner/capability/principal/targets/profile/interval 15 min–1 y) with enable/patch; scanner capability mismatch → 422, duplicate name → 409, cross-tenant access → 404. |
| Tick | PASS live | `POST /orchestration/schedules/tick` queues due jobs through the same `authorize()` path. `next_run_at` advances **before** queueing, so a double tick cannot duplicate: live tick1 queued 1 job, tick2 processed 0. Denied schedules record `denied: <reason>`, queue nothing and still advance (no retry storm against unauthorized targets). |
| Report | PASS live | `GET /pentest/engagements/{id}/report.html` renders a self-contained printable report (inline CSS, print rules) with metadata, test table, findings ordered by severity, HTTP evidence in `<pre>`, verification evidence and the footnote that a closed ticket elsewhere is not remediation. Live: 200, 2 185 bytes, verification block present. |
| Escaping | PASS | Every interpolation goes through `html.escape`; a test pins that `<script>` in title/target/evidence never reaches the document as markup. |
| Tests | PASS | 4 in `test_schedules_and_report.py` (tick once per interval, denied schedule behaviour, validation + isolation, report escaping/evidence). Suite total 119. |

Known limits: scheduling needs an external cron/systemd calling the tick
endpoint (the platform runs no background thread by design); the report is
HTML only (no PDF renderer) and has no template editor yet.

## 2026-10-31 Users, sessions and RBAC

| Item | Result | Evidence |
|---|---|---|
| Password credentials | PASS | stdlib scrypt (n=2^14, r=8, p=1) with per-user salt, constant-time compare, 8-char minimum; no third-party crypto dependency. |
| Sessions | PASS live | Opaque 32-byte tokens stored only as SHA-256 hashes, 12 h TTL (`SESSION_TTL_HOURS`), logout revokes, disabling a user revokes all their sessions (verified live: `me` 200 → logout → 401). |
| Bootstrap | PASS live | First owner only: requires `BOOTSTRAP_TOKEN` (unset ⇒ 503 `bootstrap_disabled`) and an org with zero users (second attempt 409). Live: owner created on org `poc`. |
| Login | PASS live | Email + password (+ optional org slug); every failure returns the same `invalid credentials` (no user enumeration); failed attempts audited as `auth.login_failed`. |
| RBAC | PASS live | `viewer` read-only (POST → 403 "role 'viewer' is read-only"), `analyst` writes operational data but POST /auth/users and POST /authorization/grants → 403 "requires admin", `admin`/`owner` administer. Enforced in the auth dependency, so no router can forget it; API keys keep full org rights as machine identities. |
| User admin | PASS live | List/create/patch (role, active/disabled) and password reset (revokes sessions); the last owner cannot be demoted (409). |
| Console | PASS live | Settings gains sign-in/sign-out and shows the current principal; Members gains an accounts table (role, status, last login, disable) plus the account creation form, above the named-members and audit sections. Fixed a real UX defect found while verifying: the settings panel could only be closed by saving — it now has a close button. |
| OIDC | PASS (guarded) | Discovery/authorization/token/client-claims implemented with stdlib; RS256 verification needs the optional `cryptography` extra, and without it the endpoints answer 503 `oidc_requires_cryptography_extra` — never an unverified token. Not enabled in this deployment. |
| Tests | PASS | 5 in `test_auth_users.py` (bootstrap gating, login/me/logout, viewer+analyst RBAC, disable revokes sessions, tenant isolation). Suite total 115. |

Known limits: no password reset email flow or MFA; OIDC is implemented but
untested against a real IdP (no crypto dependency installed here), so it is
documented as guarded-not-verified; sessions are bearer tokens in
localStorage (no httpOnly cookie flow yet).

## 2026-10-31 Shauron worker (execution path validated with real scans)

| Item | Result | Evidence |
|---|---|---|
| Worker CLI | PASS live | `barad worker --platform-url --api-key --name [--limit/--once]` registers, heartbeats every 30 s, claims, starts (honouring `cancelled: true`), executes and reports. |
| Real execution | PASS live | Job `opengrep` on `/tmp/shauron-gate/src` ran the pinned OpenGrep engine and the Trivy SBOM step: SBOM ingested to `worker-live`, **4 components received / 3 created**, and 2 real SAST findings landed at `app.py:8` (HIGH, `python-subprocess-shell-true`) and `app.py:12` (MEDIUM, `python-unsafe-yaml-load`). Job `succeeded` with manifest + log artifacts. |
| Failure honesty | PASS | Missing `target_path` → job `failed` with `target_path not found`; scan error → `failed` with the tool's own text; no artifacts produced → `failed` with `no_artifacts`. Nothing is reported as success without evidence. |
| Bug found by the gate | FIXED | The first worker run reported `succeeded` while uploading nothing: the CLI nests runs (`<target>/<status>/scan-<id>/`) and the worker looked for artifacts flat. Now artifacts are located recursively, and an empty artifact set fails the job. Second bug in the same gate: OpenGrep `check_id` arrives fully qualified (`…rules.<name>`) and paths were absolute — normalized to the rule name and repo-relative path, verified on the next job (`app.py:8`). |
| Tests | PASS | 5 in `tests/test_worker_contract.py` against a real local HTTP stub of the platform: API-key header, clean no-job exit, cancellation means no execution, missing target → failed, scan error → failed. Suite: 107 backend + 156 CLI. |

Known limits: single-process polling worker (no graceful drain beyond
`--limit`), SBOM/SARIF ingestion assumes project/version in the job profile,
and artifact upload is capped by the API (20 artifacts/job, 200 KB each).

## 2026-10-31 BL-040b part 2 — code review

| Item | Result | Evidence |
|---|---|---|
| Source snapshots | PASS live | `POST /code/files` indexes a file per (repo, ref, path) with a content hash; identical re-push → `created:false`; binary content and >400 KB rejected. CI pushes source; the platform never reaches into a repo by itself. |
| Redaction | PASS live (after fix #2) | Served file text and context lines run through the shared `redaction` module. The live gate exposed a second real leak: `api_key = 'sk-live-...'` kept its quoted value because the pattern stopped at the quote — fixed to consume an optional quote pair, pinned by test, and re-verified live (`secret leaked: false`). |
| Finding context | PASS live | `GET /code/findings/{id}/context?radius=` returns numbered lines around the finding from the latest snapshot of the project's linked repository, with the target line flagged; a path with no snapshot → 404, a finding without a location → 409. |
| PR registration | PASS live | `POST /code/pull-requests` upserts by (org, repo, number), optional project/version scope, `open|merged|closed` transitions audited (`code.pr_registered`, `code.pr_status`). |
| PR scan + classification | PASS live | `POST /code/pull-requests/{id}/sarif` ingests one SARIF run, links findings to the PR and classifies `new` when the fingerprint did not exist in the org before this scan, `existing` otherwise. Live: first scan `new:1`, rescan `existing:1`; repeated ingestion never duplicates links (unique pr+finding). |
| Quality gate on the PR | PASS live | The existing `gates.evaluate` runs for the PR's project/version: live verdict `fail` on a CRITICAL code-weakness. |
| Review comment | PASS live | Rendered markdown payload with verdict, NEW/existing markers, `rule/path:line`, and the explicit note that absence means `absent_from_current_scan`, never "fixed". |
| Console | PASS | 3rd tab `code`: PR table with gate verdict and new/existing counts, expandable review grouped by file, inline numbered code with the finding line highlighted, and the PR comment payload. Verified in the live console (screenshot). |
| Tests | PASS | 3 in `test_bl040b_code_review.py` (push/context/redaction, new→existing rescan, status + tenant isolation). Suite total 110. |

Known limits: no diff view between base and head blobs yet (context only),
no SCM PR status/comment publishing (the payload is returned for CI to
post), no rule explanation catalogue, and no explicit baseline object —
"new" is derived from fingerprint history.

## 2026-10-31 BL-020 orchestration (Shauron management side)

| Item | Result | Evidence |
|---|---|---|
| Scanner registry | PASS live | `POST /orchestration/scanners` registers name → capability (validated against the BL-015 catalogue), version and adapter; a job whose capability differs from the scanner's registration is rejected 422 (a scanner name never grants capabilities). |
| Workers | PASS live | registration/upsert with capability list, labels and `max_concurrent`; heartbeat endpoint; listing computes stale (>120 s) as `offline`; claims above the concurrency ceiling → 409. |
| Job lifecycle | PASS live | `queued → leased (900 s lease) → running → succeeded/failed/cancelled`; artifacts stored separately; live run: trivy job queued, leased with `authorization.decision=allow`, started, succeeded with `{"findings":2}`, 1 artifact persisted and readable. |
| Authorization at queue time | PASS live | creation calls `authorize()` and stores the full decision (policy version included); no grant → **403, no job row** (verified live). |
| Authorization at claim time | PASS live | the claim path re-evaluates `authorize()`; a grant revoked between queueing and claiming made the worker claim return `data:null` + rejection reason and the job go to `failed` with `authorization revalidation denied: ...` (verified live). |
| Leases | PASS | expired leases return jobs to the queue until `max_attempts`, then fail with `lease expired and max attempts reached`; retry re-checks authorization before requeueing. |
| Cancel / retry | PASS live | cancel works on queued/leased/running (409 on terminal); retry only from failed/cancelled and re-authorizes. |
| Audit | PASS | `orchestration.scanner_registered`, `worker_registered`, `job_queued`, `job_denied`, `job_leased`, `job_revalidation_denied`, `job_cancelled`, `job_requeued`, `job_succeeded/failed`. |
| Console | PASS | 15th tab `orchestration`: jobs table (status, attempts, cancel/retry), workers with claim-next, scanners table, and forms to register scanners/workers and queue jobs. |
| Tests | PASS | 5 in `test_bl020_orchestration.py` (deny without grant, full lifecycle with lease+artifacts, revalidation after revoke, cancel/retry/isolation, scanner capability mismatch). Suite total 107. |

Known limits: this is the **management side** only — no scanner execution,
no container spawning, no worker auth tokens (worker identity is org API key
today), and the Shauron CLI/contract live outside this repository. Artifacts
are text (≤200 KB each, max 20 per job).

## 2026-10-31 BL-080 security regression suites

| Item | Result | Evidence |
|---|---|---|
| Test definitions | PASS | HTTP checks with method, URL, headers, body, typed assertions (`status_equals`, `status_not_equals`, `body_contains`, `body_not_contains`, `header_equals`, `header_absent`), suite label, project/version scope and optional source pentest finding. |
| Authorization gate | PASS live | Every run calls `authorize()` with capability `active_verification` for the exact URL target; no grant → **403 and nothing is sent** (verified live: 403, no run recorded). Methods POST/PUT/PATCH/DELETE additionally require `intrusive_testing` — a GET grant never implies them (403 pinned by test). |
| Redaction | PASS live (after fix) | Request headers `authorization/cookie/x-api-key/...` stored as `[REDACTED]`; credential-looking body patterns (`token=`, `api_key=`, `password=`, ...) scrubbed. Live gate caught a real gap — `token=sk-...` in a JSON body was NOT scrubbed by the first pattern; the regex was extended and the case is now pinned (`api_key=[REDACTED]` assertion) and re-verified live (`token=[REDACTED]`, zero leakage). |
| Regression detection | PASS live | `reintroduced` is true only when the previous run passed and the current one fails. Live: target vulnerable → failed; flipped to fixed → passed; flipped back → failed with `reintroduced: true`. |
| Audit + history | PASS | `regression.test_created`, `regression.run`, `regression.denied` on the hash chain; run history keeps status, latency, redacted evidence and errors. |
| Console | PASS | 14th tab `regression`: checks table with last result/reintroduced badge, run + history actions, run timeline, and a creation form (URL, method, suite, expected status, body-must-not-contain). |
| Tests | PASS | 4 in `test_bl080_regression.py` against real local HTTP servers: deny-without-grant, full fail→pass→fail with redaction, mutating method needs intrusive grant, tenant isolation. Suite total 102. |

Known limits: assertions cover status/body/header only (no JSON-path or
timing assertions); runs are on-demand from the API/console, not scheduled
by the future orchestration queue (BL-020).

## 2026-10-31 BL-050 Jira bridge

| Item | Result | Evidence |
|---|---|---|
| Link + create issue | PASS live | `POST /jira/links` queues a `create` item in `jira_outbox` (dedupe `create:<link>`), then calls Jira REST v3 (basic auth, ADF description, severity/rule/path context). Live against a stub Jira on the compose network: issue `SEC-1` created from a CRITICAL finding, link `linked`, outcome `sent`. |
| Idempotency | PASS | A second link for the same finding → 409; outbox dedupe keys (`create:`, `assignee:`, `transition:`) prevent duplicate issues/transitions on retry; repeated webhooks report `changed: []`. |
| Webhook | PASS live | `POST /jira/webhook` requires `X-Barad-Secret` (hmac.compare_digest; missing secret config → 503, wrong → 401), is idempotent and **never closes a finding**: Done flipped the link to `verification_required` while the finding stayed `open` (verified live). |
| Permitted sync | PASS | `POST /jira/links/{id}/sync` pushes only assignee and explicit transitions (whitelisted by exact status name); unconfigured Jira → 503, no silent success. |
| Reconciliation | PASS | `POST /jira/reconcile` pulls status/assignee per linked issue, audits `jira.drift_detected`, flips links to `verification_required` on terminal statuses and returns `verification_required` finding ids — never edits finding status. |
| Audit | PASS | `jira.link_created`, `jira.link_synced`, `jira.webhook`, `jira.drift_detected` on the existing per-org hash chain. |
| Tests | PASS | 4 in `test_bl050_jira.py` against a REAL local HTTP stub (no mocks): create+push, webhook-never-closes, reconcile drift, isolation. Suite total 98. |
| Console | PASS | 13th tab `jira`: links table (issue link, remote status/assignee, sync state, last error), in-progress/done actions, reconcile summary, and a "link to jira" action from the finding detail. |

Operational notes: integration is dormant until `JIRA_BASE_URL`, `JIRA_EMAIL`,
`JIRA_TOKEN` and `JIRA_WEBHOOK_SECRET` are set (compose passes them through);
while unconfigured, links queue as `pending` and the API reports
`jira_configured:false` instead of pretending to sync. Verified against a
controlled stub, not a customer Jira tenant — the REST shapes used are the
documented v3 endpoints.

## 2026-10-31 BL-070 pentest management

| Item | Result | Evidence |
|---|---|---|
| Engagement lifecycle | PASS live | `draft → active → completed/cancelled` with starts/ends timestamps, project/version scope, lead, methodology, scope notes; audited (`pentest.engagement_*`). Live: "Demo engagement Q4" on `lic-live@1.0`. |
| Tests | PASS live | tests per engagement (name, methodology, tester, notes) with `pending → in_progress → done/blocked`; audited. |
| Manual findings + evidence | PASS live | findings carry severity (validated enum), CVSS string, target, reproduction, request AND response evidence, remediation; optional link to a test and to an asset in the same org (cross-engagement test or foreign asset → 404). |
| Reverification | PASS live | `verified`/`closed` require `verification_evidence` (422) and the verifier must differ from the reporter (409, self-verification blocked — same discipline as suppression approvals). Live: self-verify → 409, reviewer verify → 200 with `verified_by`. |
| Report | PASS live | `/engagements/{id}/report` renders engagement metadata, test status counts, findings totals by severity and by status, and the finding items (evidence included) — the export payload for a professional report. |
| Console | PASS | 12th tab `pentest`: engagement table with counts and start/complete actions, expandable detail (tests, findings with severity/status pills and retest/verify/close actions, report line) and inline new-finding form with evidence fields. Verified in the live nginx console (screenshot). |
| Tests | PASS | 4 in `test_bl070_pentest.py` (lifecycle, evidence+verification flow, tenant isolation + audit chain, invalid severity/status); suite total 94. |

Known limits: report is JSON only (no PDF/HTML template yet), no Jira link
field (BL-050), no attachment upload (evidence is text), and no conversion of
a pentest finding into a regression test yet (BL-080).

## 2026-10-31 BL-025 SPDX export + operations runbook

| Item | Result | Evidence |
|---|---|---|
| SPDX 2.3 export | PASS live | `/spdx/export?project=&version=` renders an SPDX 2.3 JSON document from stored components: packages with versionInfo, `licenseDeclared` (multi-license joined with AND), purl externalRefs and DESCRIBES relationships; unlicensed components get NOASSERTION. Live: `lic-live@1.0` → 3 packages / 3 relationships (`Apache-2.0`, `BSD-3-Clause AND MIT`, `GPL-3.0-only`). |
| Tests | PASS | 2 in `test_bl025_spdx.py` (document shape + unknown version 404); suite total 90. |
| Operations | PASS | `docs/OPERATIONS.md`: deploy/upgrade procedure, nightly pg_dump backup + restore into a fresh DB, secrets policy, health checks and the recurring drift/port/chain troubleshooting recipes. |

Known limits: SPDX export is one-way (export only; SPDX ingest is the next
item), and the runbook's backup step is documented, not yet scheduled.

## 2026-10-31 BL-090 asset snapshots + change detection

| Item | Result | Evidence |
|---|---|---|
| Snapshots | PASS live | `POST /assets/{id}/snapshots` stores structured observations (ip/tech/tls/... keys) with source + timestamp; asset last_seen refreshed; snapshot never implies scan authorization (passive data only). Live: two DNS-scan snapshots on `api.councilbox.com`. |
| Change detection | PASS live | `/assets/{id}/changes` diffs consecutive snapshots (ip changed 203.0.113.10→.11; tech list gained `redis`; unchanged `tls_issuer` stayed quiet) and returns full history. |
| Console | PASS | Assets tab row → history panel: snapshot count, latest changes, JSON observation entry to record new snapshots. |
| Tests | PASS | 3 in `test_bl090_snapshots.py` (history/diff, single-snapshot quiet state, tenant isolation + audit); suite total 88. |

Known limits: probing (DNS/TLS/tech collection) is supplied by collectors or
manual JSON for now — active probing stays gated behind scan authorization.

## 2026-10-31 BL-055 quality gates + BL-040b SARIF + BL-110 dashboards

| Item | Result | Evidence |
|---|---|---|
| BL-055 gate policies | PASS live | org/project-scoped, deterministic verdicts: severity threshold (default HIGH), optional KEV block, optional license-denial block, suppressed findings excluded by default, policies audited. Live: `release-gate` evaluated on f2-fixture@1.2.0 → `fail` (2 open ≥ HIGH), KEV rule pass, license rule pass; project policy overrides org (test). |
| BL-055 tests | PASS | 6 in `test_bl055_gates.py`: threshold fail→pass after resolution, custom threshold, suppression exclusion, project override, KEV block, tenant isolation + audit. |
| BL-040b SARIF ingest | PASS live | `POST /api/v1/sarif` ingests SARIF runs into the findings pipeline (rule/path/line identity, `security-severity` property → CRITICAL), creates occurrence rows via the shared sighting recipe, idempotent re-ingest (`created:1` then `existing:1`); live gate created the `py.sqli` CRITICAL finding. |
| BL-040b baseline diff | PASS | `/sarif/diff` compares versions through occurrence history (stable record, not the mutating last_seen pointer) and labels absences `absent_from_current_scan` with an explicit "does not assert remediation" note; tests cover new/absent/common and RBAC isolation. |
| BL-110 dashboard | PASS live | `/dashboard/summary` and `/dashboard/projects` over real tables: severities, KEV open, SLA breached/soon, 7-day inflow/outflow, assets, CI verdicts, remediation progress, license counts, gate verdict. Live: 7 open findings (CRITICAL 1 / HIGH 3 / MEDIUM 2 / LOW 1), gate fail. Foreign orgs see zeroed scopes (test). |
| BL-110 console | PASS | New **dashboard** tab (default landing) with metric cards + project posture table (click-through to project scope); new **gates** tab (policies, evaluation with per-rule reasons). |
| Regression | PASS | Full suite **85 pytest** + 151 CLI unittest; UI bundle 58 kB gzip. |
| Fixed en route | — | `resolved` was missing from the allowed finding statuses, so the console's "mark resolved" always 422'd; now allowed and covered by gate/dashboard tests. |

Known limits: SARIF PR-status publishing and inline code/diff viewer still
pending (backend ingest/diff land now); gate thresholds are create-only (no
PATCH); dashboards have no time-series charts (cards + lists only, by design).

## 2026-10-31 BL-060 license management

| Item | Result | Evidence |
|---|---|---|
| License inventory | PASS live | SBOM with licenses=[Apache-2.0, GPL-3.0-only, MIT+BSD-3-Clause] → 4 license rows; re-ingest adds none (uq component+license); legacy single `license` column unchanged. |
| Policies | PASS | org- and project-scoped; allow/deny CSV lists; deny-list wins; project policy overrides org (test); unknown_action carried. |
| Evaluation | PASS live | counts `{components:3, denied:1, allowed:3}`; per-row verdict+reason; unlicensed components counted separately (never silently allowed). |
| Exceptions | PASS live | expiry-aware waiver: GPL denied → exception (90d) → `excepted` with approver/reason; expired → back to denied (test). |
| Console | PASS | Licenses tab: project/version picker, evaluate, counts pills, verdict table, policy create/disable, exceptions create/list. |
| Audit | PASS | `license.policy_created/policy_status/exception_created` in the hash chain (`chain_ok: true`). |
| Tests | PASS | 6 in `test_bl060_licenses.py` + suite total 72; tenant isolation asserted. |

Known limits: SBOM license expressions are compared as raw strings (no SPDX
normalization yet); policies have no approval workflow (single-actor create);
license violations are not yet materialized as findings for the findings
pipeline — evaluator-only for now.

## 2026-10-31 Console-round pre-merge validation (gate run)

| Gate | Result | Evidence |
|---|---|---|
| Full suites | PASS | 66 backend/pytest + 151 CLI unittest; vite production bundle 55 kB gzip. |
| RBAC + tenant isolation | PASS | Covered and green: `test_tenant_isolation_on_authorization_endpoints` (foreign org: zero grants, 404 on foreign revocation), `test_multi_tenant_isolation` (bl015), keys carry the org everywhere (`require_org`). |
| Audit chain vs filters/pagination | **FIXED** | The filtered view previously verified only its own subset; `read_audit` now walks the COMPLETE ledger from genesis for `chain_ok` regardless of filters, and exposes `total/shown/chain_position`. Regression test: tampering outside the filtered window flips `chain_ok` to false in BOTH the filtered and unfiltered views. |
| Occurrence failure resilience | PASS | Induced `TypeError` on the occurrences fetch in the live console: the finding detail still renders full metadata (source/tool/location/priority/sla/intel/VEX), no error state, occurrences section omitted gracefully. |
| Simulator read-only + condition deny | PASS | `/authorize` writes only an audit entry; grants with `conditions` are never silently treated as unconditional (`test_unsupported_conditions_deny`); decision audit lines carry `[policy vN]`. |
| Console states | PASS | Empty (`No audit entries for these filters.`), error (invalid key → 401 surfaced), expiry (expired filter reports honestly; the one historical grant is `revoked`, not expired). |
| PR hygiene | FIXED | `barad.egg-info/` untracked (it was committed before the ignore pattern landed); secret scan of the whole branch diff found only redacted test fixtures (`AKIA4T...WP2X` masks), no real credentials; no node_modules/dist/console_html tracked. |

Pending limitations carried into the backlog: grant PATCH/conditions editor, occurrences UI pagination, per-capability exact audit filter. BL-060 remains the next objective and is NOT started here.

## 2026-10-31 Console round: grants, audit trail, occurrences views

The three priority views validated against the LIVE API through the containerized console (:8092). Requirements honored: authorization logic stays server-side (the simulator POSTs to `/authorize` — no engine duplication in JS); tenant isolation reused from the API layer; no unsupported grant operations exist in the UI.

| View | What landed | Visual evidence |
|---|---|---|
| Grants | filters (status/principal/capability/tool/target/expiry, all server-side), detail columns incl. justification/issued_by/policy_v, revoke with confirm dialog, issue form (targets `type=value` lines), and the **authorize() simulator** rendering decision + reason + policy v + evaluated_at from the backend engine | `/tmp/console-grants.png` — grant row (revoked, staged campaign, caps+targets visible), simulator showing `deny / no active grant... / policy v1` |
| Audit trail | filtered ledger (actor/action prefix/date-window/free-text, server-side), chain-integrity chip (`chain verified` green / `CHAIN BROKEN` red), decision rows carrying `[policy v1]` prefix | `/tmp/console-audit.png` — 20 entries, chip verified, both remediation task lifecycle entries visible |
| Occurrences in finding detail | fetched on detail open; rows show seen_at, tool, source, version id (CI-run link only renders if ci_run_id exists — never invented); "no sightings recorded yet" empty state | `/tmp/console-occurrences.png` — occurrences (1) with `tool trivy · source api · version 131f67e8` |

Backend contracts added for the console (all server-side, 5 new tests in `test_console_round_authz.py`): grant list filters (status/principal/capability/tool/target/expired), audit filters (actor/action/since/until/q) with chain verification on the FILTERED set, decision audit entries prefixed `[policy vN]`, and the **unsupported-conditions deny rule**: a grant carrying `conditions` is never treated as unconditional — default deny with an honest reason until a supported evaluator exists. Suites: 65 pytest + 151 unittest OK; live API 51 paths; bundle 55 kB gzip.

Known limits: excluded rows in grants/audit come from the same org only (isolation preserved); simulator runs with the caller's principal (real authorization identity); occurrences for historical findings predating 0013 remain absent (only new sightings are recorded).

## 2026-10-31 BL-015 scan authorization engine + BL-040 occurrences

| Item | Result | Evidence |
|---|---|---|
| BL-015 engine | PASS live | `authorize()` (7500414): default deny (fixture request without grant → deny); grants carry principal/capabilities/targets/tools/environment/conditions/issuer/justification/policy_version/validity; exclusion (`thirdparty.example`) beats grants; wildcard `*.empresa.com` covers only own subdomains (apex + sibling TLD + IP + third-party denied); CIDR→IP containment; URL exact origin+path; repository/service id targets; invasive capabilities refuse self-authorization (409); expiry honored; revoke mid-run flips subsequent decisions immediately (real revoke → deny); revalidate exact path blocks target-switching (`does not cover`). 10 pytest in `test_bl015_authorization.py` incl. multi-tenant isolation (other org's key sees zero grants, same target denied). |
| BL-015 audit integration | PASS | `/audit` chain recorded `authorization.granted/revoked/decision/revalidated` (19 entries, chain_ok true); grant responses expose revoked_by+reason (`5f6865d`). |
| BL-040 occurrences | PASS live | Migration 0013; ingest (created or refreshed) records one occurrence per distinct sighting (idempotent via `uq(finding, sighting_key)`); live re-ingest of an existing finding → `refreshed=1` + occurrence with version/tool/source; endpoint `GET /findings/{id}/occurrences`; suppression workflow coexists (history preserved, chain_ok true). 3 pytest. |
| Suites | PASS | 60 pytest + 151 unittest OK; live API 51 paths, migrations head 0013. |

Deliberate non-goals honored: no nuclei execution, no worker orchestration, no EASM probing UI (backlog). Shauron will consume `/authorize` + `revalidate` as its contract surface; scanners stay decoupled from persistence.

## 2026-10-31 Phase 0 audit docs + BL-010 relationships + KEV rule (requested increments)

| Item | Result | Evidence |
|---|---|---|
| Phase 0 deliverables (9 docs) | PASS | `docs/planning/*` + `docs/architecture/*` committed (`7b7922c`); matrix KEEP/EXTEND/REPLACE/REMOVE by area; A–J audit honest; clean-room status verified per-file (no upstream code anywhere). |
| License decision (BL-102) | DECIDED | Proprietary/private for now; no LICENSE GPL/AGPL adoption; obligations of our dependencies documented (Apache-2.0 engines, composition not linking); no OpenCTM code copied — recorded in compatibility doc. |
| BL-010 relationships | PASS live | Migration 0009 (+0010 timestamp fix-up) at head on the live Postgres; repositories/services/deployments created via REST; repo N:M across projects (idempotent relink, same repo row), asset↔deployment `observed_at` and finding→service context links; every mutation audited (`/audit` 11 entries, chain_ok true). Test suite `test_bl010_relationships.py` covers N:M sharing, orphan assets, temporal unlink + audit trail, and the one-component-across-projects dedupe invariant. **Timestamp-drift family fired twice** (RemediationFinding in B-earlier, repositories/services in 0009→0010) — tests run on both engines and catch these. |
| KEV→P0 rule (configurable) | PASS | `priority_rules.match_intel='kev'` column (migration 0011); classify() consults the local KEV mirror only (no runtime network); rule creation accepts intel criterion (validator: `kev` only); unit test proves promote P0 with an exploited CVE and that findings without CVEs/the criterion stay on severity fallback. **Live gate**: `/intel/sync` pulled the canonical CISA feed into the mirror (1766 KEV + 500 EPSS — the first URL attempt returned 404 and was honestly swapped to the official feed); reclass counter 0 because the fixture findings carry no CVEs (rule correctly inert there). |
| Suites | PASS | 47 pytest + 151 unittest OK; live API 40 paths (openapi) rebuilt within the compose service. |

## 2026-10-31 Console as a deployed service (nginx, loopback 8092)

The console stopped depending on the dev server: `console_html/` holds the built dist, `deploy/console/nginx.conf` serves it with a same-origin `/api` reverse-proxy to `platform-api:8090` (no CORS) and an SPA fallback. Service in both composes: digest-pinned `nginx:1.27-alpine`, loopback-only publish, PROD_URL default `http://127.0.0.1:8092`. Live evidence: index 200, proxied `/api/v1/projects` 401 with an invalid key (auth enforced through nginx), `/healthz` proxied ok, and the full console (6 tabs, findings with priority/SLA) rendering in a real browser at :8092 with the same data as the dev instance. Release recipe: `npm run build` in `frontend/` → rsync `dist/` → `console_html/` → `docker compose up -d console`.

## 2026-10-31 Parity blocks 1–4 (B1–B4): lifecycle, identity/audit, intel catalog, EASM

The four agreed parity blocks against the OpenCTM functional inventory. Every check ran live against the containerized API on :8090 and in the real browser console. Backend commit `1b344df` + UI commit.

| Block | What landed | Live gate evidence |
|---|---|---|
| B1 lifecycle | Priority rules (ordered, rule > severity fallback, honest `priority_reason`), default SLA policy stamping deadlines, remediation tasks with the one-open-task-per-finding contract | Policy saved (7/15/30/60 days); rule `sev∈CRITICAL,HIGH→P0` reclassified 6 findings (P0 carried the org reason, MEDIUM fell back to P2); UI findings show `P0/P2` + "6d left"; detail→create task linked (`python-subprocess-shell-true (P0)`) and renders in the remediation tab |
| B2 identity/audit | org_members (owner/admin/analyst/viewer; accountable actor required) + per-org hash-chained audit ledger (prev-hash + chain position, pg advisory lock on append) wired into approvals/remediation/VEX/EASM | Member santiago@councilbox.com added (admin); ledger verifies `chain_ok: true` in UI; tampering unit-tested (hash mismatch detected) |
| B3 intelligence | KEV/EPSS local mirrors + public sync (catalog outages → 502), VEX statements per finding, grouped reconcile re-keying vulnerability findings onto CVE fingerprints | KEV/EPSS reads live (CVE-2024-35195 not known-exploited); reconcile idempotent (0); VEX `affected` statement posted; finding detail shows the intel row ("not in KEV") |
| B4 EASM | assets table (domain/ip/url/cidr), manual adds, crt.sh certificate-transparency sweep with dedupe + last-seen | LIVE sweep of councilbox.com: **267 real subdomains** created (+seed row); resweep refreshes; assets tab lists real CT-logged names |

Model/migration drift caught by the live gate (the 5th occurrence of the recipe family): `RemediationFinding` carried TimestampMixin columns the migration never ships — the model now drops the mixin (added_at is the timestamp of record); the audit append skips its Postgres-only `hashtext` lock on sqlite; `0007` guards its `vulnerabilities.cve_id` add behind a SQLAlchemy inspector check. Postgres-first migrations + sqlite create_all in tests keep surfacing these on both engines.

New API surfaces: `/api/v1/remediation/*`, `/priority-rules`, `/sla/policies`, `/members`, `/audit`, `/vex`, `/intelligence/reconcile`, `/intel/{kev,epss}/:cve`, `/intel/sync`, `/assets`, `/assets/discover`. The console grows remediation/members/assets tabs; findings gain priority+SLA columns and intel/VEX/task rows in the detail. Suites after: 39 pytest + 151 unittest OK; vite build 53 kB gzip.

Limits kept honest: no OIDC (API-key identity plane), priority rules stay attribute-only (KEV/EPSS read through to the UI but don't yet drive rules), VEX statements unsigned, EASM is CT-log domains only (no DNS probing, ports, or takeover checks) — post-POC backlog territory.

## 2026-10-30 F5 gate: packaging, docs and demo rehearsal (fifth milestone — POC closed)

The platform API is now a Compose service (`platform-api`, built from `backend/Dockerfile`: digest-pinned `python:3.12-slim`, non-root, migrations at boot, loopback-only publish on 8090, `edge` network). Record:

| Check | Result | Evidence |
|---|---|---|
| Packaging build | PASS | `docker compose build platform-api` succeeds; container healthy with `GET /healthz → {"status":"ok"}`; finds inventory via the same API key (5 findings listed through the container). |
| Migration resolution in the container | FIX | First boot failed: `run_migrations` resolved the project root from the installed module location (site-packages) and missed `alembic.ini`; it now searches upward from cwd and the module path — checkout and container both work. |
| Ownership handoff | PASS | Host dev server killed; the container took over port 8090 exclusively (the list of active listeners checked first, per the F4 lesson). |
| Demo rehearsal through the containerized API | PASS | Fresh `barad run` → `PUBLISHED (receipt_verified)`; analyze and views answered through the container; UI end-to-end again in the browser (findings 5 default / components / verdict badge). The fixture had moved to `pyyaml==6.0.1`, so `analyze` matched **0 advisories** — the honest no-CVE case, plus the still-present 4 gate findings refreshed (rehearsal validated both paths). |
| Ingest limits | PASS | `MAX_FINDINGS_PER_INGEST=1000` enforced server-side with a bounded 422 (ingest limit), documented. |
| Docs | PASS | `docs/PLATFORM.md` (5-command quickstart, four delivery surfaces, post-POC backlog), README architecture row, `poc-scope.md` status flip to delivered. |
| Suites after packaging | PASS | 151 CLI unittests including the gitignore contract (frontend artifacts kept without breaking the `.barad/`-last invariant); 36 backend/adapter pytest. |

Limits of the POC as delivered: the CI plane trusts the org API key (no OIDC), gate thresholds/hard-coded, no SLA/ticketing/audit-chain, static scope, single org. The full backlog lives in `docs/PLATFORM.md`.

## 2026-10-30 F4 gate: minimal console (F0–F3 surfaces in a browser)

`frontend/`: Vite + React 18 in plain JavaScript (no TypeScript, per the agreed stack), four sections only (findings+detail, components+SBOM upload, pipelines/runs, connection settings), one list per domain, no charts (150-line CSS, no chart library; production bundle 50 kB gzip). Verified in a real browser session against the deployed API through the Vite dev proxy:

| Check | Result | Evidence |
|---|---|---|
| Production build | PASS | `npm run build` → dist (156.98 kB js / 50.09 kB gzip, 0 errors). |
| Findings tab | PASS | 5 rows (default view hides the suppressed AWS secret), severity badges sorted CRITICAL→Low, kind/cve/rule/path columns; `include suppressed` → 6 (5 open + 1 suppressed with reason). |
| Finding detail | PASS | Row click expands: source (`cli`), tool, location (`app.py:6`), component purl, detail text, status reason, advisory link, and disposition buttons (acknowledge / mark resolved / reopen). |
| Components tab | PASS | 2 components with purl/license/manifest/direct; SBOM upload through the same `postRaw` path as the file input returned a 201 receipt and refreshed the table (`created=0` dedup on equal content). |
| Pipelines tab | PASS | 1 pipeline deduped, 2 runs; verdict badge `FAIL` on the runs; row expands to gate reason lines and the run's findings. |
| API drift caught by the UI | FIXED | The UI's own traffic exposed two backend contract gaps: (1) `GET /api/v1/findings/{id}` did not exist — added; (2) filtering findings by project without version was a 400 although the platform legitimately supports a project-wide view — now a valid filter (project → all versions' findings; version → `last_seen_version_id` scope). Both re-verified through the browser. |
| Cross-origin posture | FIXED | Settings now document that an empty URL uses the dev proxy (same-origin) and a full URL addresses a remote deployment; the earlier hard requirement of a URL caused CORS failures that the settings panel hid. |

Limits: the console stores its key in the browser's localStorage (single-org POC posture); the disposition flow uses a browser `prompt` as its minimal reason input; no CI-gate override UI; Vite dev server is the F4 delivery shape and production serving stays F5 (documented).

Earlier gates: F3 (2026-10-30), F2 (2026-10-30), F1 (2026-10-30), F0 (2026-10-30), consolidation 2026-10-29.

## 2026-10-30 F3 gate: CI registry with gate verdicts and static scope (fourth milestone)

Deployed stack after migrating 0004. The gate simulates the GitHub Actions context locally (the hosted runner is unavailable in this environment, same limitation recorded on 2026-10-29): the CLI adapter detects `GITHUB_ACTIONS=true` and runs the full CI flow against the deployed API. Record:

| Check | Result | Evidence |
|---|---|---|
| CI flow end-to-end | PASS | `barad run` inside simulated Actions env → adapter registered the run (`POST /api/v1/ci/runs`), pushed findings with `run_id` link (source=ci), then closed the run: `verdict=fail`, `findings_count=5`. |
| Gate verdict correctness | PASS | Verdict `fail` with capped reasons from `GET /api/v1/ci/runs/{id}`: "gate: findings at or above HIGH" + `HIGH misconfiguration DS-0002 Dockerfile` + `HIGH code-weakness python-subprocess-shell-true app.py`. The AWS secret finding (suppressed) is EXCLUDED from the run attachment and from the verdict findings_count — approved suppressions must not fail a gate. |
| Pipeline dedup | PASS | One `ci_pipelines` row for `councilbox/f2-fixture` + workflow identity across 2 registered runs; `GET /api/v1/ci/pipelines` lists it with `retired=false`. |
| One-shot finishing | PASS | Second `finish` on a closed run → 409 "only running runs finish" (backend test). |
| Failed scans fail closed | PASS | Backend test: `finish(status=failed)` → verdict `fail`, "CI run reported failure", regardless of findings. |
| Static scope | PASS | `POST /api/v1/scope/targets` + exclusions (validated types: repository|service|host|domain|api; exclusion requires reason) → `GET /api/v1/scope/resolved` returns only non-excluded entries (2 of 3). |
| Suites | PASS | 36 backend/adapter pytest (11 new F3 tests) plus adapter CI-context path exercised live through the CLI; CLI unittest suite OK. |

Discovered and fixed during this gate:

1. Another model/migration-class pitfall, but at the ORM level this time: models with an explicit `updated_at` column and models relying on nothing (TimestampMixin only provides `created_at`) mixed inconsistently — `CiPipeline`, `ScopeTarget` and `ScopeExclusion` were missing `updated_at`, which 0004 declares NOT NULL; caught by the live 500 on run registration (and by sqlite tests for the scope shorts). All three now declare it.
2. `session_factory(autoflush=False)` swallowed same-request pending inserts: `attach_finding` added the bridge row but the verdict computation in the SAME request saw zero links. `attach_finding` now flushes explicitly — the pattern to copy for every helper that inserts and then chain-queries within one request.
3. The CLI adapter now reads the run detail after finish so verdict reasons reach the Action log through the manifest.

Limits: no OIDC trust (identity fields recorded, but the CI plane trusts the org's API key in the POC); gate policy thresholds are hard-coded (fail at HIGH+) without `ci_gate_policies` rows or overrides; scope is static lists without attestation letters or approvals; findings attach to the run at ingest time only (their fingerprint bridge under asset merging is deferred). A hosted-run execution of the Action remains unverified as on 2026-10-29.

## 2026-10-30 F2 gate: multi-kind findings ingestion and suppression workflow (third milestone)

Second gate fixture `/tmp/barad-f2-fixture` (an `app.py` matching two baseline OpenGrep rules, a `settings.py` with one AWS-format credential, a vulnerable `Dockerfile`), deployed stack fresh from migrations 0001→0003. Record:

| Check | Result | Evidence |
|---|---|---|
| One `barad run` publishes both artifacts | PASS | Manifest sync: `platform_api.status=PUBLISHED (receipt_verified)` + nested `findings.status=INGESTED` with counters `{created: 6, received: 6}` — 1 secret (aws-access-key-id, CRITICAL), 3 misconfigurations (Dockerfile, Trivy DS-*), 2 code weaknesses (OpenGrep). |
| Rescan dedup | PASS | Second consecutive run: `created=0, refreshed=6`. |
| Redaction boundary | PASS | Only rule_id/path/line/severity/title cross the API; adapter tests pin that secret match text and SAST match lines never reach the payload. |
| Suppression workflow | PASS | Rule creation (pending) → requester self-approval refused with 409 ("a requester cannot approve their own suppression rule") → a different reviewer approves → 1 finding suppressed; default view shows 5, full view 6 with the suppressed secret carrying the rule reason. |
| New findings auto-evaluated | PASS | Backend test: an ingest arriving after a rule was approved is suppressed at creation time (`suppressed_by_rule=1`). |
| Manual disposition | PASS | `PATCH /findings/{id}/status` to `acknowledged` with actor+reason; invalid status 422; suppressed findings refuse manual transitions other than reopening. |
| Suites | PASS | 30 backend/adapter pytest (24 backend incl. 9 new F2 tests + 1 mapping/redaction test), CLI unittest suite OK. |

Discovered and fixed during this gate:

1. Model/migration drift again (`finding_suppressions.created_at` from TimestampMixin missing in the hand-written 0003): caught live at the first approval attempt. Since this platform DB is POC-scoped, the schema was dropped and re-migrated 0001→0003 from zero (user-approved), and the API key was re-issued quietly into the gate env.
2. The version filter joined findings to components, which multi-kind findings have none of — listing returned 0 for every secret/misconfig/SAST row. Findings now carry `last_seen_version_id`, stamped at every ingest/analyze that still sees them (the slim equivalent of the reference platform's scan-context occurrence tracking); the version view filters on it.
3. Operational lesson: TWO server processes kept binding 8090 across restarts, so re-verifications kept hitting the stale pre-patch server. The stale listener is discovered with `lsof -nP -iTCP:8090 -sTCP:LISTEN` and killed by PID; future gates check the listener before testing.

Limits: suppression expiry is evaluated at application time (rules never re-trigger for existing findings after their expiry until a new finding matches); the sole-owner cooldown guard of the reference platform is deferred; rule audit trail stays implicit in rule columns until F3.

## 2026-10-30 F1 gate: OSV vulnerability engine (second milestone)

Same gate fixture as F0; the platform API now answers `POST /api/v1/analyze` (normalize inventory → OSV querybatch → per-id detail fetch → catalog upsert → deduped findings). Record:

| Check | Result | Evidence |
|---|---|---|
| Migration 0002 to real PostgreSQL | PASS | `findings` + `vulnerabilities` created; an earlier version of 0002 (missing `vulnerabilities.created_at` vs the model's TimestampMixin) was caught live by the first analyze call and re-applied cleanly after downgrade. |
| Full-chain: manual SBOM upload → analyze | PASS | `POST /api/v1/sbom?source=web&project=…&version=…` (201) then `POST /api/v1/analyze`: 22 advisories found for requests 2.32.3 + urllib3 2.2.1, 22 findings created, 22 detail fetches, `truncated=false`. |
| Findings carry sources | PASS | `GET /api/v1/findings`: CVE list includes CVE-2024-37891 (MODERATE), CVE-2024-47081, CVE-2025-50181/50182, CVE-2025-66418; severity histogram 6 HIGH / 5 MODERATE / 11 unlabeled. |
| Reanalysis idempotency | PASS | Second analyze: `findings_created=0`, `findings_refreshed=22`, `details_fetched=0` — the `modified`-timestamp short-circuit skips detail fetches whose advisory the catalog already holds. |
| Failure containment (tests) | PASS | OSV outage marks the analyze `status=error` with a bounded reason and existing findings survive (stubbed test). |
| Automated suites | PASS | 21 backend/adapter pytest (15 backend incl. 6 new F1 tests, 6 platform_api adapter); CLI unittest suite still OK. |

Discovered and fixed during this gate:

1. OSV `querybatch` answers **only `{id, modified}`** (a change list, not advisory records). The engine therefore fetches full details per id from `GET /v1/vulns/{id}` with a `modified`-stamp short-circuit against the local catalog, and reports `details_fetched`/`detail_errors` honestly. The tests pin at the querybatch shape.
2. Tz-safe timestamp comparison (`same_timestamp`): SQLite stores naive datetimes while OSV stamps carry `Z` — equality needed UTC normalization or the short-circuit refetched everything on every run.
3. Severity labels: 11 of 22 advisories ship no `database_specific.severity`; the finding keeps `severity=None` honestly until a CVSS-vector scorer lands (F2 candidate), rather than guessing.

Limits: analysis runs synchronously on request (POC scale: 2 network calls + 22 detail gets); the same CVE reached through two advisory ids (PYSEC + GHSA) yields two findings sharing a component — a catalog-level reconcile (their `vulnmatch`) is deferred to F2; severity comes only from `database_specific.severity` labels today.

## 2026-10-30 F0 gate: platform API SBOM ingestion (POC first milestone)

Isolated fixture `/tmp/barad-platform-gate` (requirements.txt with `requests==2.32.3`, `urllib3==2.2.1`, `app.py`, version-source pyproject), platform API at 127.0.0.1:8090, database `barad_platform` on the existing Compose PostgreSQL (loopback publish 15443). Record:

| Check | Result | Evidence |
|---|---|---|
| Compose validation with the F0 changes | PASS | `docker compose config --quiet` exited 0 in both the worktree and the live deployment checkout. |
| Migrations to real PostgreSQL | PASS | `barad-platform migrate` applied `0001_core`; seven tables listed via psql. |
| Readiness and auth | PASS | `GET /healthz` → `{"status":"ok"}`; unauthenticated `GET /api/v1/projects` → 401. |
| End-to-end publication | PASS | `barad run` on the fixture: `scan: SUCCESS`, `platform_api: PUBLISHED (receipt_verified)`; manifest sync shows the receipt import id and matched component counts. |
| Inventory via API | PASS | `GET /api/v1/components?project=platform-gate-fixture&version=0.1.0` returns 3 rows (requests, urllib3, the requirements.txt pseudo-component) with purl/version/identity. |
| Rescan stability | PASS | Second consecutive `barad run`: receipt counters `components_created=0`, `links_created=0`; database keeps exactly 3 components and 3 version links after the pre-fix data was truncated (user-approved). |
| Automated suites after the fixes | PASS | 151 CLI unittests; 15 pytest (9 backend acceptance incl. the identity-stability test, 6 adapter contract). |
| Live OpenGrep on macOS | PASS (after fix) | Full-CLI asset produced `sast.json` with exit 0 and 0 findings on the benign fixture; `security.sanitized.json + sbom.cdx.json` written. |

Discovered live and fixed during this gate:

1. `engines.lock.json` pointed macOS/Windows to the `opengrep-core` OCaml asset, which does not accept the runner's full-CLI argv (Linux was already pinned to the full CLI). Both now pin the official full-CLI assets with upstream digests, and `--no-progress-bar` (a semgrep-only flag) was replaced with `--disable-version-check`, keeping the scan boundary credential-free.
2. The CLI's SBOM upload 422ed twice: the SBOM is delivered as raw bytes (`application/octet-stream`) and `project`/`version` travel as query overrides because Trivy SBOMs omit `metadata.component.version`.
3. Trivy mints a random `bom-ref` per run for purl-less pseudo-components; identity is now the documented `nonpurl:sha256(name:version)` recipe instead of the raw bom-ref, so rescans dedup instead of duplicating.

Limits: the platform API runs as a checkout process with a live dev server (container packaging stays F5); Dependency-Track and DefectDojo remain `NOT_CONFIGURED` in this gate (the fixture enables only `platform_api`); the live deployment checkout at `/Volumes/980PRO/.../Barad-d-r` received the compose port publish + edge attachment directly (same change mirrored in this worktree) — the two trees stay in sync only until this branch merges.

## 2026-10-29 consolidation verification

| Check | Result | Evidence |
|---|---|---|
| Compose syntax | PASS | `docker compose config --quiet` exited 0. |
| Persistent services | PASS | `postgres`, `dt-apiserver`, `dt-frontend`, `dojo-nginx`, `dojo-valkey`, and `trivy-server` were running; PostgreSQL, DT API, Dojo nginx, Valkey, and Trivy Server reported healthy. |
| Existing automated tests | PASS | `PYTHONPATH=cli:. .venv/bin/python -m unittest discover -s tests -q` ran 91 tests successfully. |
| External installation | PASS | Built and installed the `barad` wheel into a new virtual environment outside the repository. |
| Read-only diagnostics | PASS | External `barad health --json` reported `HEALTHY` for CLI, Git, Docker Trivy 0.76.1, Dependency-Track, and DefectDojo. |
| Isolated scan | PASS | External `barad scan` against an isolated project containing `requests==2.32.3` completed and wrote `security.json`, `sbom.cdx.json`, and `manifest.json`; the SBOM had 2 components. |
| Dependency-Track publication | PASS | Isolated project `barad-architecture-isolated` version `0.1.0` was published as UUID `516b0f6e-b816-4545-a873-88b836bd835e`; the adapter verified the exported normalized inventory. A second run reported `UNCHANGED: remote_inventory_verified`. |
| DefectDojo import/reimport | PASS | The same isolated project imported through the `Trivy Scan` parser into test `9` with 2 observed findings and `close_old_findings=false`; the second run reimported test `9`. |

## Reproduced and corrected during verification

The first external scan used an intentionally minimal project. Trivy 0.76.1 returned a schema-valid JSON report without `Results`; the CLI had treated it as malformed. `cli/barad/core/trivy.py` now recognizes that output as a successful empty scan and `tests/test_trivy_empty_result.py` covers it.

That project had no components in its CycloneDX SBOM, so the CLI correctly returned an incomplete inventory rather than claiming success. Adding a declared `requests` dependency produced the successful two-component isolated scan above.

## 2026-10-29 clean-architecture follow-up

- Moved the active core from `barad_security/` to `cli/barad/core/` and removed `cli/barad/integrations/` compatibility modules.
- Built a wheel with `pip wheel --no-deps`; it includes `barad/core/` and both `integrations/` adapters, but no `barad_security/` or `barad/integrations/` package paths.
- Reinstalled the wheel from an external directory and completed `barad scan` against the existing isolated dependency project using its warm Trivy cache.
- A fresh isolated cache could not complete the Trivy scan (`exit 1`); this is recorded as a cache/feed limitation, not a successful cold-cache scan.

## 2026-10-29 external-workspace evidence

- Added `--out`/`-O DIR` to `barad scan` and `barad run` (existing `--output` still recognized).
- Default evidence, state, and Trivy cache anchor to the invocation directory, so scanning an external project leaves its tree untouched; a contract test covers it.

## 2026-10-29 per-project evidence layout

- Evidence moved from `.barad/reports/<scan-id>/` to `<reports>/<project>/<version>/<scan-id>/` with an `unresolved` folder when the version cannot be resolved yet.
- Scan ids carry a UTC timestamp plus randomness, so repeated scans of the same project+version append new scan-id folders; the earlier replace/`version_(n)` prompt was removed as unnecessary since scan-id uniqueness already prevents collisions.
- The same behavior applies to `barad run` and its publication records; DefectDojo/Dependency-Track remote logic is unchanged.

## Limits

- The GitHub Actions workflow and composite action were structurally and behaviorally tested locally, but no GitHub-hosted workflow run was available in this environment.
- This ledger does not validate production TLS, SSO, RBAC, backup restoration, image scanning, or JAR scanning.
- The Compose stack remains a loopback-only evaluation environment. Persistent volumes and backup/rollback volumes were not altered.
- The user elected to preserve the pre-existing legacy deletions without committing them. The recorded commits therefore rely on the current worktree deletion set for the 91-test layout; no pre-existing deletion was staged, reverted, or committed by this consolidation.

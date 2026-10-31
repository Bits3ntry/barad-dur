# Verification ledger

This ledger records observed checks for the current architecture. It does not turn unrun checks into claims.

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

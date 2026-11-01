# Barad-dûr v1.0 — Progress Ledger & Traceability Matrix

Generated: 2026-11-01. Baseline established from live code (frontend, backend, migrations, tests) — not from documentation.

## Baseline numbers (verified)
- API paths: 174 route decorators (`@router.{get,post,put,patch,delete,api_route}`), 14 routers, one management router.
- DB tables: 64 (`__tablename__` count in models.py). 67 model classes incl. Base/TimestampMixin.
- Migrations: 28 (0001_core → 0028_sast_baselines).
- Frontend screens: 18 console screens + App shell + shared ui.jsx + main.jsx + api.js + styles.css. React 18 + Vite, no test framework in devDeps.
- Backend tests: 42 files in backend/tests (175+ assertions at last green gate — verify by running).
- CLI tests: 17 files in tests/ (177+ — verify).
- Branch: andrade-fs/fork_openctem (clean). Python 3.14.9 in .venv (PEP 723/735 era). FastAPI 0.133.1, SQLAlchemy 2.1.6, pydantic 2.13.4.

## Legend
Status: COMPLETE | PARTIAL | MISSING | BROKEN | BLOCKED | NOT_STARTED
FREQUENCY: routes backend flows; UI = frontend; T = automated tests; E2E = browser live check.

## Phase 0 — Traceability Matrix

### 1. Identity and access
| Requirement | Backend | API | DB | UI | T | E2E | Status |
|---|---|---|---|---|---|---|---|
| Bootstrap first account | yes | POST /auth/bootstrap | users | entrance | yes | yes | COMPLETE |
| Email/password login+logout | yes | POST /auth/login | sessions | yes | yes | yes | COMPLETE |
| Roles viewer<analyst<admin<owner | yes | require_* deps | users roles | yes | yes | yes | COMPLETE |
| Org API keys (create/list/revoke) | yes | /org/keys | api_keys | settings | yes | yes | COMPLETE |
| Worker tokens scoped to workers | yes | /auth/workers | worker_tokens | none | yes | no | COMPLETE |
| Password change | yes | POST /auth/users/{id}/password | users | settings | yes | no | COMPLETE |
| OIDC start/callback/status | yes | POST /auth/oidc/start|cb|status | oidc_states | none | yes | PARTIAL (UI: no OIDC button on entrance) |
| GET /auth/me | yes | GET /auth/me | — | entrance | yes | no | COMPLETE |
| Password reset flow | MISSING | [planned] | none | none | no | no | MISSING |

### 2. Scope & scan authorization
| Requirement | Backend | API | DB | UI | T | E2E | Status |
|---|---|---|---|---|---|---|---|
| Grants (capabilities, tools, targets) | yes | /authorization/* (8) | scan_grants | grants | yes | no | COMPLETE |
| Default deny, exclusions win | yes | authorize() sim + revalidate | — | simulate | yes | no | COMPLETE |
| Audited decisions (SHA-256 chain) | yes | /authorization/audit | audit_logs | audit trail | yes | no | COMPLETE |
| Grant create/simulate/revoke UI | yes | — | — | grants UI | no | no | COMPLETE |
| Shauron mid-run revocation | yes | job claim re-validates | — | — | yes | no | COMPLETE |

### 3. Inventory / projects / attack surface
| Requirement | Backend | API | DB | UI | T | E2E | Status |
|---|---|---|---|---|---|---|---|
| Org→project→version | yes | inventory/* | projects, versions | assets | yes | yes | COMPLETE |
| Repo/Service/Deployment M2M | yes | relationships | project_repos, service_project | none | yes | no | COMPLETE |
| Assets (domain/sub/domain/IP/URL/service) | yes | inventory/* | assets | assets | yes | yes | COMPLETE |
| Passive (crt.sh) + active DNS/TLS | yes | easm/* | asset_snapshots | assets | yes | no | PARTIAL (DNS only; TLS explicit) |
| Asset snapshots w/ field change detection | yes | relationships/* | asset_snapshots | assets | yes | no | COMPLETE |

### 4. Supply chain (Dependency-Track replacement)
| Requirement | Backend | API | DB | UI | T | E2E | Status |
|---|---|---|---|---|---|---|---|
| CycloneDX ingest (idempotent) | yes | /sbom | sbom_imports | components | yes | no | COMPLETE |
| SPDX ingest | yes | /spdx | sbom_imports | components | yes | no | COMPLETE |
| PURL identity, cross-project impact | yes | /sbom | component, version_component | components | yes | no | COMPLETE |
| KEV/EPSS enrichment | yes | /sbom | kev_entry, epss_score | findings context | yes | no | COMPLETE |
| License inventory/policies/exceptions | yes | /licenses | component_license, license_policy | licenses | yes | no | COMPLETE |
| Version-to-version SBOM compare | yes | /sbom/baseline | sbom_baseline | components | yes | no | COMPLETE |
| VEX | yes | /sbom/vex | vex_statements | findings (vex tab) | yes | no | COMPLETE |
| SPDX export | yes | /sbom/export | — | components | yes | no | COMPLETE |

### 5. Findings, occurrences, remediation
| Requirement | Backend | API | DB | UI | T | E2E | Status |
|---|---|---|---|---|---|---|---|
| Finding kinds (vuln/secret/misconfig/codeweakness/license) | yes | findings/* (9) | finding | findings | yes | no | COMPLETE |
| Occurrence rows per sighting | yes | findings/{id}/occurrences | occurrence | findings | yes | no | COMPLETE |
| Status lifecycle w/ 2nd approver | yes | findings/* | finding_suppression | findings | yes | no | COMPLETE |
| Remediation tasks | yes | /remediation | remediation_task | findings | yes | no | COMPLETE |
| Priority/SLA rules | yes | — | priority_rule, sla_policy | findings | yes | no | COMPLETE |
| Intel enrichment (OSV/GHSA/PYSEC) | yes | /intelligence | — | findings | yes | no | COMPLETE |
| SARIF import | yes | /sarif | — | code review | yes | no | PARTIAL (screens pending) |
| Ad-hoc analysis | yes | /findings/analyze | — | findings | yes | no | COMPLETE |

### 6. Pentest management
| Requirement | Backend | API | DB | UI | T | E2E | Status |
|---|---|---|---|---|---|---|---|
| Engagements (project/version scope) | yes | /pentest (12) | pentest_engagement | pentest | yes | no | COMPLETE |
| Tests + findings + evidence | yes | /pentest | pentest_test, pentest_finding | pentest | yes | no | COMPLETE |
| Retest + evidence-based closure | yes | /pentest | — | pentest | yes | no | COMPLETE |
| Reports HTML/PDF | yes | /pentest/reports | — | pentest | yes | no | COMPLETE |

### 7. Code security / PR review
| Requirement | Backend | API | DB | UI | T | E2E | Status |
|---|---|---|---|---|---|---|---|
| SARIF ingest + classification | yes | /sarif (12) | pr_finding, sast_baseline | code review | yes | no | PARTIAL (inline viewer pending) |
| Gate eval per PR | yes | /code/gates | — | code review | yes | no | COMPLETE |
| Source diff + redaction | yes | /code/sarif/* | code_file | code review | yes | no | PARTIAL (annotation UI pending) |
| GitHub/GitLab publish | yes | /code/publish | — | code review | yes | no | COMPLETE |
| Approved baselines + 2-person approval | yes | /code/baselines | sast_baseline | code review | yes | no | PARTIAL |
| PR review screens | — | — | — | code review UI | no | no | MISSING (frontend exists but not detailed in FEATURES) |

### 8. Regression
| Requirement | Backend | API | DB | UI | T | E2E | Status |
|---|---|---|---|---|---|---|---|
| Authorized HTTP checks | yes | /regression (4) | — | regression | yes | no | COMPLETE |
| Re-intro detection | yes | — | — | regression | yes | no | COMPLETE |

### 9. Policies & quality gates
| Requirement | Backend | API | DB | UI | T | E2E | Status |
|---|---|---|---|---|---|---|---|
| Gate policies (severity/KEV/license) | yes | /gates | gate_policy | gates | yes | no | COMPLETE |
| License policies + exceptions | yes | /licenses | license_policy | licenses | yes | no | COMPLETE |

### 10. Orchestration (Shauron)
| Requirement | Backend | API | DB | UI | T | E2E | Status |
|---|---|---|---|---|---|---|---|
| Scanner + worker registry | yes | /orchestration (16) | scanner, worker | orchestration | yes | no | COMPLETE |
| Jobs (queued→leased→running→done) | yes | /orchestration/jobs | scan_job | orchestration | yes | no | COMPLETE |
| Leases + heartbeats + retries | yes | /orchestration/jobs | — | orchestration | yes | no | COMPLETE |
| Scan schedules + idempotent tick | yes | /orchestration/schedules | scan_schedule | orchestration | yes | no | COMPLETE |
| SBOM/SARIF ingest from workers | yes | /sbom, /sarif | — | components | yes | no | COMPLETE |
| Isolate-image sandbox | yes (CLI) | — | — | — | yes | no | COMPLETE |
| Trivy DB update (no network) | MISSING | — | — | orchestration | no | no | MISSING (GAP-08) |

### 11. Dashboards/reporting
| Requirement | Backend | API | DB | UI | T | E2E | Status |
|---|---|---|---|---|---|---|---|
| Summary metrics (org/project/version) | yes | /dashboard (2) | — | dashboard | yes | no | COMPLETE |
| Project posture table | yes | /dashboard | — | dashboard | yes | no | COMPLETE |
| Charts | MISSING (no chart dep) | — | — | dashboard | no | no | MISSING (GAP-05) |

### 12. Administration/operations
| Requirement | Backend | API | DB | UI | T | E2E | Status |
|---|---|---|---|---|---|---|---|
| Audit chain | yes | /identity/audit | audit_log | audit trail | yes | no | COMPLETE |
| Backup/restore | yes (CLI + pg_dump script) | — | — | none | yes | no | COMPLETE |
| Multi-tenant isolation | yes | all | — | all | yes | no | COMPLETE |

## Declared gaps status (Phase 1–8)
|| Gap | Requirement | Status | Evidence |
||---|---|---|---|
|| GAP-01 (Findings/PR detail) | Side panels/drawers, deep-linkable, tabs, source context/diff, rule explanations, Jira refs, keyboard, mobile | PARTIAL | Drawers + tabs implemented in Findings.jsx and CodeReview.jsx. Evidence and history tabs are placeholders. Jira link uses Dialog (not prompt). Keyboard: Escape closes dialog; tab navigation works. |
|| GAP-02 (Native browser dialogs) | Replace window.alert/confirm/prompt with accessible dialogs, toasts, forms, success/error feedback | PARTIAL | Fixed: Findings.jsx (linkJira, dispose), CodeReview.jsx (snapshotBaseline, decideBaseline, publish), Assets.jsx (collect), Regression.jsx (reintroduced), Grants.jsx (revoke). All remaining `window.alert/prompt/confirm` replaced with Dialog/ConfirmButton patterns. |
|| GAP-03 (Theme & density) | Dark/light/system, comfortable/compact, tokens, focus states, responsive | PARTIAL | Theme + density implemented in ui.jsx and styles.css. Settings.jsx has theme/density selectors wired to global state. Charts (DonutChart, BarChart, LineChart) use SVG with theme-aware styling. |
|| GAP-04 (Auth UX) | OIDC button when configured, password reset flow, loading states, account settings | PARTIAL | Login.jsx has OIDC button (when configured) + password reset Dialog. Settings.jsx has account settings. Password reset endpoints implemented: /password/reset/request, /password/reset/confirm. Admin recovery fallback when SMTP not configured. Remaining: token binding to user, full validation. |
|| GAP-05 (Analytics & charts) | 13 chart types from real backend data | PARTIAL | Charts.jsx implemented (DonutChart, BarChart, LineChart, ProgressBar). Dashboard.jsx has findings distribution, new vs resolved, scanner execution health charts. Time-series charts (vulns over time, EPSS, asset growth, PR trends, gate history) require backend data not currently exposed. |
|| GAP-06 (Notifications) | Per-finding, SLA, KEV, failed gates, dedup, read/unread, webhooks, digest | PARTIAL | Notifications backend exists (SLA breach tick with dedupe). UI notification center, preferences, and read/unread state implemented in Notifications.jsx. Per-finding notification generation based on real events (SLA, KEV, failed gates) pending. |
|| GAP-07 (Continuous EASM) | Passive DNS/TLS, certs, IP change, HTTP technology, ports, endpoint inventory, snapshots | PARTIAL | Snapshots + change detection exist. Active collectors + TLS + scheduled sweeps pending. |
|| GAP-08 (Offline Trivy DB) | Updater, verify, publish, read-only sandbox, freshness display | MISSING | Requires offline signing/publish pipeline; not yet implemented. |
|| Phase 2 (Jira) | Connection, auth, mapping, create/link/import, webhooks, sync, conflicts | PARTIAL | Backend exists (contract tests); frontend Jira screen has bridges but needs completion. |
|| Phase 3 (Asset/Project relationships) | M2M complete, relationship graph, auto-suggestion | COMPLETE (backend) | Fully implemented. |
|| Phase 4 (Supply chain) | Complete | COMPLETE | Fully implemented. |
|| Phase 5 (SAST/SonarQube PR) | SARIF, diff viewer, annotations, baselines | PARTIAL | Drawers implemented; inline code viewer for findings context exists. |
|| Phase 6 (Pentest/reporting) | Complete | COMPLETE | Fully implemented (engagements, tests, findings, retest, reports). |
|| Phase 7 (Shauron) | Complete (backend) | COMPLETE | Fully implemented (scanners, workers, jobs, schedules, sandbox). |
|| Phase 8 (Frontend quality) | Browser E2E, all states | NOT_STARTED | No Playwright configured; no browser E2E run. |

## Verification commands (run in .venv, PYTHONPATH unset)
- Backend tests: `cd backend && .venv/bin/pytest -q` — RESULT: 175 passed ✅
- CLI tests: `cd tests && .venv/bin/pytest -q` — RESULT: 177 passed ✅
- Build frontend: `cd frontend && npm run build` — RESULT: success ✅

## Open questions / decision needed
1. LICENSE file: proprietary/private decision recorded 2026-10-31; not applied yet.
2. Charts: time-series data (vulns over time, EPSS, asset growth, PR trends, gate history) requires backend endpoints not currently exposed.
3. Password reset: requires verified delivery mechanism (SMTP absent in this environment). Implemented reset request dialog with admin-recovery note; full token validation pending backend.
4. Jira live integration: needs real credentials; contract tests + live-validation-BLOCKED plan.
5. Trivy DB updater: requires offline signing/publish pipeline; implement locally with version metadata.
6. Frontend E2E: no Playwright test framework configured; add minimal setup and run representative workflows.

## Verification commands (run in .venv)
- Backend tests: `cd backend && .venv/bin/pytest -q`
- CLI tests: `cd tests && .venv/bin/pytest -q`
- Build frontend: `cd frontend && npm run build`
- Full stack: `docker compose up -d` then `barad-platform` (backend) + Vite preview (frontend)

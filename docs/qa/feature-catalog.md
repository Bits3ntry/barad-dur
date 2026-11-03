# Feature catalogue — what exists, how it works, how to test it

One row per user-facing capability. "Status" is the honest label after the last
pass: **verified** (L1-L4 green), **partial** (works, with a named limitation),
**gap** (not built). Cases live in `test-cases.md`; the seed stack that most of
them assume is `python scripts/e2e_stack.py --port 8099 --seed`.

## General

| # | Feature | What it does | How it works | Test | Status |
|---|---|---|---|---|---|
| G1 | Dashboard counters (v0 block) | assets, projects, open findings, CVEs, exposures, cycles, acceptances, changes 7d — each links to the list it counts | `GET /dashboard/v0`; `V0Overview` in `Dashboard.jsx`; counts scoped to the org, `coverage` note attached | TC-010, TC-011 | verified |
| G2 | Security posture dashboard | severity/priority mix, SLA breaches, new/resolved 7d, exposure flow | `GET /dashboard/summary`, `/dashboard/exposure-flow`, `/dashboard/projects`; charts in `Dashboard.jsx` | TC-010 | verified |
| G3 | My work trays | six trays with counts, 72 h window, acceptances ≤30 d | `GET /my-work?actor=…` (`routers/work.py`), counters = list length; `MyWork.jsx` | TC-012, TC-013 | verified |
| G4 | Work item decisions | approve/reject with reason; request withdraw/remind (1 h rate limit); no self-approval | `POST /my-work/items/{id}/decide` with policy checks in the router | TC-012 | verified |
| G5 | Findings list & filters | search, project/version/kind/status/severity/priority/assignee, suppression toggle | `GET /findings` (`routers/findings.py`), slug-or-name project resolution | TC-014 | verified |
| G6 | Manual finding | create without a CVE (IDOR class), with path/line, CWE, impact, reproduction, recommendation, assignee | `POST /findings` + `findings.manual` fingerprint; `Findings.jsx` dialog | TC-015 | verified |
| G7 | Finding drawer | overview/occurrences/history/remediation/related, comments, attachments, VEX, Jira, task creation | `GET /findings/{id}` (+`/history`, `/comments`, `/attachments`), `Drawer` in `Findings.jsx` | TC-016 | verified |
| G8 | Finding lifecycle | acknowledge/resolve/reopen with reason; backend-enforced permissions and audit | `PATCH /findings/{id}/status` | TC-017 | verified |
| G9 | Vulnerabilities (by CVE) | groups visible findings by advisory, asset/version counts, KEV/EPSS with source+date, bulk preview→apply | `GET /vulnerabilities`, `/{cve}`, `bulk-preview`, `bulk-status`; `Vulnerabilities.jsx` | TC-018 | verified |
| G10 | Dashboard "unknown" honesty | KEV/EPSS/versions show *unknown* with a reason instead of a guess | payload fields `exploit.known=false`, `versions_known=false` | TC-018 | verified |

## Scoping

| # | Feature | What it does | How it works | Test | Status |
|---|---|---|---|---|---|
| S1 | Declarative scope | typed targets (domain/pattern/url/ip/cidr/repo/service/api/cloud account) with reason, owner, validity, capabilities | `POST /scope/targets`, `scoping.py` normalisation | TC-020 | verified |
| S2 | Wildcard semantics | `*.x` covers subdomains at any depth and **not** the apex unless `include_apex` | `scoping.py`, `docs/architecture/scope-semantics.md` | TC-020 | verified |
| S3 | Exclusions win | an exclusion beats any rule; recorded with reason | `POST /scope/exclusions`, effective decision in `/scope/check` | TC-020 | verified |
| S4 | Scope → canonical asset | registering a concrete value links/creates one asset with `source=scope`; a pattern creates none | `routers/scope.py` | TC-021 | verified |
| S5 | Cycles | charter, explicit selection, preview, freeze on activation, candidates, review criteria, close keeps history | `routers/cycles.py`, `Cycles.jsx` | TC-022, TC-024 | verified |
| S6 | Cycle auto-link scope | linking findings respects the frozen selection (asset/group/environment narrow, project does not) | `POST /cycles/{id}/link-findings` + selection logic | TC-023 | verified |

## Discovery

| # | Feature | What it does | How it works | Test | Status |
|---|---|---|---|---|---|
| D1 | Assets inventory | filter/search/paging, ownership, project, classification, certificate state, archive | `GET/PATCH /assets`, archive endpoints, `Assets.jsx` | TC-030 | verified |
| D2 | Needs attention | computed queue with reason codes (`no_owner`, `no_project`, `ownership_unconfirmed`, `stale`, `no_deployment`) | `GET /assets/needs-attention` | TC-030 | verified |
| D3 | Inventory groups | manual N:M collections with notes/tags/stakeholders; removing a member keeps the asset; not an access group | `inventory_groups.py`, `Assets.jsx` Groups tab | TC-031 | verified |
| D4 | Activity ledger | who/what/when per change, import and observation; protected audit | `GET /activity`, `AuditLog` | TC-032, TC-050 | verified |
| D5 | Attack surface — changes | ten categories with before/after, source, equal-coverage rule (failed collection ≠ closed port) | `surface.py`, `GET /attack-surface/changes` | TC-033 | verified |
| D6 | Attack surface — web surface | origins/paths with candidate/observed/confirmed/excluded/not-evaluated; 200 ≠ vulnerable | `attack_surface.py`, `AttackSurface.jsx` | TC-034 | verified |
| D7 | Lookalikes | watched roots, similarity kind, registration state, passive only, decisions with reason | same router/screen | TC-035 | verified |
| D8 | Review queue | ownership confirmation of resolved addresses; ownership ≠ authorization | same router/screen | TC-036 | verified |
| D9 | Components / SBOM | CycloneDX + SPDX import, hashes, per-version usage, direct/transitive, licenses | `routers/sbom.py`, `Components.jsx` import dialog | TC-037 | verified |
| D10 | Artifact chain | version → artifact (digest) → SBOM → deployment; "in production" read from deployments | `routers/artifacts.py`, `GET /artifacts/{id}` | TC-038 | verified |
| D11 | Exposures | condition identity (stable hash), decision with reason/validity, reopen policy, four summaries over findings | `routers/exposures.py`, `Exposures.jsx` | TC-039 | verified |

## Code security

| # | Feature | What it does | How it works | Test | Status |
|---|---|---|---|---|---|
| C1 | SAST import | SARIF 2.1.0 and OpenGrep/Semgrep JSON, code snapshot, diff, coverage full/diff/partial, repository + revision + branch + PR | `sast.py`, `POST /analysis/import`, migration 0041 | TC-040 | verified |
| C2 | Viewer | file tree, line numbers, syntax colour, rule/severity/CWE/message on the line, diff hunks | `Analysis.jsx`, `highlight.jsx`, `/runs/{id}/file`, `/diff` | TC-041 | verified |
| C3 | Classification | new/persistent/resolved only against a comparable base; "on a modified line" ≠ "introduced" | `routers/analysis.py`, `analysis.py:plan_closure` | TC-041 | verified |
| C4 | Deep links | result → finding → same run/line, both directions, survives reload | `#findings::<id>`, `#analysis::run=…&path=…&line=…` | TC-042 | verified |
| C5 | Pull requests | register PR, findings per PR, diff/context, baseline snapshot, publish result | `routers/code_review.py`, `CodeReview.jsx` | TC-043 | partial — no provider sync |
| C6 | Source→sink traces | stored as a `codeFlows` count only | `sast.py` | — | partial (by design) |

## Prioritization

| # | Feature | What it does | How it works | Test | Status |
|---|---|---|---|---|---|
| P1 | Priority rules | ordered first-match-wins rules; reclassify on save; fallback by severity with a stated reason | `routers/lifecycle.py`, `Security`→`Prioritization rules` screen | TC-044 | verified |
| P2 | SLA policies | day buckets per priority class, one default per org | `lifecycle.py`, `/sla/policies` | TC-044 | verified |
| P3 | Business impact | open work per application: priority mix, late, unassigned, CVEs, assets, production deployments; `criticality: not modelled` declared | `routers/impact.py`, `BusinessImpact.jsx` | TC-045 | verified |

## Auth and administration

| # | Feature | What it does | How it works | Test | Status |
|---|---|---|---|---|---|
| A1 | Password login | email+password → session; one message for every failure | `auth_local.verify_password` (scrypt), `POST /auth/login` | TC-046 | verified |
| A2 | Optional TOTP | per-user two-step enrolment, QR + manual secret, 8 single-use recovery codes, challenge login | `app/mfa.py`, `routers/mfa.py`, `Security.jsx` | TC-046 | verified |
| A3 | SSO (OIDC) | Google/Entra/Okta; pre-registered users only unless `OIDC_AUTO_PROVISION=true`; MFA still applies | `auth_local.py`, `routers/accounts.py`, `Login.jsx` | TC-047 | verified |
| A4 | Users, roles, permissions | owner/admin/analyst/viewer; backend enforcement, not hidden buttons | `auth.ROLE_RANK`, `require_*` dependencies | TC-049 | verified |
| A5 | API keys | issue/revoke service keys per org; last key cannot be revoked | `routers/organization.py`, Settings | TC-049 | verified |
| A6 | Audit trail | every privileged mutation with actor and detail | `GET /audit`, `_audit_log` | TC-050 | verified |
| A7 | Notifications (in-app) | tray with unread count, mark read, preferences | `GET/PATCH /notifications/notifications`, `/preferences` | TC-048 | verified |
| A8 | Delivery channels | email / signed webhook / Slack incoming webhook; create, test, pause; deliveries recorded | `routers/notifications.py`, `Notifications.jsx` card | TC-048 | verified |
| A9 | Slack payload | `{text, blocks}` without the HMAC envelope; rejection body surfaced | `_deliver_slack` | TC-048 | verified |
| A10 | Jira outbound | finding → issue via idempotent outbox, update/transition, reconcile | `routers/jira.py`, `jira_client.py` | TC-051 | partial — needs configured Jira |
| A11 | Jira inbound | status/assignee webhook; Done ⇒ `verification_required`, never closes a finding | `POST /jira/webhook` + shared secret | TC-051 | verified |
| A12 | Jira → work items | import issues as work | not built | — | gap (see `docs/planning/jira-inbound-assessment.md`) |
| A13 | Org-wide MFA policy | "everyone must use a factor" | not built | — | gap |

## Delivery and legacy screens

| # | Feature | What it does | How it works | Test | Status |
|---|---|---|---|---|---|
| L1 | CI pipelines/runs | register runs, link findings to a run | `routers/ci.py`, `Pipelines.jsx` | smoke | partial — no runner |
| L2 | Quality gates | gate policies and verdicts | `routers/gates.py`, `Gates.jsx` | smoke | partial |
| L3 | Licenses | inventory, policies, exceptions | `routers/licenses.py`, `Licenses.jsx` | TC-037 | partial — no legal advice |
| L4 | Pentests | engagements, tests, HTML/PDF report | `routers/pentest.py`, `Pentest.jsx` | smoke | partial |
| L5 | Regression | suites and runs | `routers/regression.py` | smoke | partial |
| L6 | Orchestration / scans | jobs, workers, scanners, schedules | `routers/orchestration.py`, `schedules.py` | smoke | gap for real collectors |

## Cross-cutting rules every row inherits

- **Isolation**: every read and write is filtered by `org_id`; a foreign id is a
  404, never a 403 that confirms existence (TC-052).
- **Permissions**: the backend decides; the console only mirrors (TC-049).
- **Honesty of states**: empty ≠ not configured ≠ no permission ≠ error ≠ partial
  coverage (TC-053).
- **Dates** carry timezone; **counters** respect visibility; **archiving** keeps
  evidence.

# Capability matrix — verified 2026-10-31 (post-PR #1, `ef5fd89c`)

Status legend: **COMPLETE** (code + tests + live gate), **PARTIAL** (works with
known gaps), **MISSING**, **BLOCKED** (external dependency). Evidence in
`AUDIT.md` unless noted.

| Area | Status | Evidence / gap |
|---|---|---|
| Org settings + API keys | COMPLETE | `/org` read/rename, key create/list/revoke with last-key guard; legacy `/keys` hardened |
| Users / sessions / RBAC | COMPLETE | BL-`auth`: scrypt passwords, opaque sessions, bootstrap, 4 roles enforced in the auth dependency; OIDC guarded behind the optional crypto extra |
| Multi-tenancy isolation | COMPLETE | every endpoint via `require_org`; isolation tests in bl015/console set |
| Audit hash chain | COMPLETE | full-ledger verification independent of filters |
| Projects / versions / components | COMPLETE | migrations 0001–0002; dedupe invariants tested |
| Repositories / services / deployments / typed links | COMPLETE | BL-010 (0009+0010) |
| Asset inventory (domain/ip/url/cidr) | COMPLETE (v1) | crt.sh sweep, snapshots/change detection, DNS collection (passive) and TLS probe (active, grant-gated) |
| Scan authorization engine | COMPLETE | BL-015; conditions fail closed |
| SBOM ingest (CycloneDX) + receipts | COMPLETE | idempotent by content hash |
| SPDX ingest + export | COMPLETE | export 2.3 + import via the CycloneDX pipeline; component diff between versions |
| Vulnerability matching (OSV) + reconcile | COMPLETE | findings anchored per component/version |
| KEV/EPSS enrichment | PARTIAL | mirrors + UI marker + KEV rule; feeds only, no scoring |
| VEX statements | PARTIAL | statement column + UI; unsigned |
| Finding lifecycle (dedupe, suppressions, priority, SLA) | COMPLETE | B1 + F2 gates |
| Occurrences | COMPLETE | BL-040 |
| Remediation tasks | COMPLETE | one-open-task contract |
| License management | COMPLETE | BL-060 (`9139ecf`): inventory, policies, evaluator, exceptions, console tab, live gate |
| CI registry + fail-closed gate | PARTIAL | runs/verdicts; policies hard-coded threshold |
| Quality Gates / policies engine | COMPLETE (v1) | BL-055: severity/KEV/license rules, org+project scopes, deterministic + audited |
| SAST (OpenGrep) execution | COMPLETE (CLI) | engine pinned |
| SARIF ingest + version diff | COMPLETE | BL-040b part 1; inline viewer/PR status pending |
| PR review / inline code view | PARTIAL | source snapshots, context + base↔head diff, new/existing classification, gate verdict, GitHub commit status + idempotent comment publishing; no GitLab or inline annotations |
| Pentest management | PARTIAL | BL-070 engagements/tests/findings/evidence/retest/report live; no PDF template/Jira link/regression conversion |
| Jira bidirectional | PARTIAL | BL-050 links/outbox/webhook/reconcile live vs stub; no attachment sync or field mapping UI |
| Regression suites | PARTIAL | BL-080 HTTP checks, authorized replay, redaction, reintroduction detection; no scheduler/JSON-path assertions |
| EASM probing (DNS/TLS/tech) | MISSING | BL-090 (crt.sh only) |
| SLA notifications | PARTIAL | signed webhook channels + daily breach tick with dedupe; no email or per-finding push |
| Scanner execution health | COMPLETE | dashboard orchestration block (workers/stale/jobs/24h/avg/failures) + UI cards |
| Cross-project component impact | COMPLETE | `/components/impact` (id/purl/name) with usage + findings; console panel |
| Scan scheduling | COMPLETE | interval definitions for scan **and easm** jobs, idempotent tick (cron), authorization re-checked per fire, console panel with tick-now |
| Pentest report export | PARTIAL | printable self-contained HTML report (escaped); no PDF renderer or template editor |
| Scanner orchestration / Shauron contract | PARTIAL | BL-020 registry/workers/leased jobs/artifacts/revalidation + real `barad worker` execution (OpenGrep+SBOM) live; no worker tokens, scheduler or container isolation |
| Dashboards / reporting | COMPLETE (v1) | BL-110: real-data summary + project posture + console tab |
| Console pages | PARTIAL | 11 tabs; no pentest pages yet |
| Docker deployment | COMPLETE | compose + console service |
| Backups / observability | PARTIAL | migrations yes; no scheduled dumps/metrics |

Priority order for the next rounds (security → model → backend → UI → integrations):

1. BL-060 licenses (this round) — closes supply-chain compliance loop.
2. BL-055 quality gates/policies — deterministic gate outcomes.
3. BL-040b SARIF + PR review — code security first-class.
4. BL-090 EASM snapshots — asset history/change detection.
5. BL-050 Jira — issue tracking bridge.
6. BL-070 pentest — engagements/campaigns.
7. BL-110 dashboards — real-data reporting.
8. BL-025 SPDX, BL-065 signed feeds, BL-080 regression, BL-020 OIDC.

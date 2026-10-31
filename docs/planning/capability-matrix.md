# Capability matrix — verified 2026-10-31 (post-PR #1, `ef5fd89c`)

Status legend: **COMPLETE** (code + tests + live gate), **PARTIAL** (works with
known gaps), **MISSING**, **BLOCKED** (external dependency). Evidence in
`AUDIT.md` unless noted.

| Area | Status | Evidence / gap |
|---|---|---|
| Org / API keys / members / roles | COMPLETE | `identity.py` + tests; no login UI (API-key plane) |
| Multi-tenancy isolation | COMPLETE | every endpoint via `require_org`; isolation tests in bl015/console set |
| Audit hash chain | COMPLETE | full-ledger verification independent of filters |
| Projects / versions / components | COMPLETE | migrations 0001–0002; dedupe invariants tested |
| Repositories / services / deployments / typed links | COMPLETE | BL-010 (0009+0010) |
| Assets inventory (domain/ip/url/cidr) | PARTIAL | stored + crt.sh sweep; no DNS/TLS snapshots/history |
| Scan authorization engine | COMPLETE | BL-015; conditions fail closed |
| SBOM ingest (CycloneDX) + receipts | COMPLETE | idempotent by content hash |
| SPDX ingest/export | MISSING | BL-025 |
| Vulnerability matching (OSV) + reconcile | COMPLETE | findings anchored per component/version |
| KEV/EPSS enrichment | PARTIAL | mirrors + UI marker + KEV rule; feeds only, no scoring |
| VEX statements | PARTIAL | statement column + UI; unsigned |
| Finding lifecycle (dedupe, suppressions, priority, SLA) | COMPLETE | B1 + F2 gates |
| Occurrences | COMPLETE | BL-040 |
| Remediation tasks | COMPLETE | one-open-task contract |
| License management | **IN PROGRESS (BL-060, this round)** | component.license capture exists; no inventory/policies/verdicts yet |
| CI registry + fail-closed gate | PARTIAL | runs/verdicts; policies hard-coded threshold |
| Quality Gates / policies engine | MISSING | BL-055 |
| SAST (OpenGrep) execution | COMPLETE (CLI) | engine pinned; no SARIF ingest/PR view |
| PR review / inline code view | MISSING | BL-040b |
| Pentest management | MISSING | BL-070 |
| Jira bidirectional | MISSING | BL-050 |
| Regression suites | MISSING | BL-080 |
| EASM probing (DNS/TLS/tech) | MISSING | BL-090 (crt.sh only) |
| Scanner orchestration / Shauron contract | PARTIAL | contract drafted; no job queue/workers |
| Dashboards / reporting | MISSING | BL-110 |
| Console pages | PARTIAL | 9 tabs; no licenses/dashboard/pentest pages |
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

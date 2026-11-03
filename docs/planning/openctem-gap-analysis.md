# OpenCTEM gap analysis — matrix KEEP / EXTEND / REPLACE / REMOVE

Audit date 2026-10-31. The local repo is the source of truth: 12 commits ahead
of the POC close, no OpenCTM source files copied (verified per-file during this
audit). "OpenCTEM" below means: concepts audited from the read-only tree at
`/Volumes/980PRO/.../openctem` (GPL-3.0 upstream) — concepts extracted, code
re-implemented in our own stack.

## Matrix

| Area | Decision | Why / notes |
|---|---|---|
| Platform core (org/keys/projects/versions, SQLA+Alemia) | **KEEP** | Ours from F0; 7 gated migrations; already the master inventory. |
| Finding lifecycle (fingerprints, suppressions+approvals, dispositions, priority rules, SLA, remediation) | **EXTEND** | Complete dup recipes exist; occurrence-level evidence (their `finding` × `findinglifecycle`) missing → BL-040. |
| Audit chain | **KEEP** — extend coverage to ingest events | Already hash-chained; note BL-025. |
| CI gate + pipelines runs | **EXTEND** — gate policies out of env defaults → overrides/policies table (BL-055); their OIDC-exchange replaced later (BL-020). |
| Scope model | **EXTEND** — static tables → typed temporal M2M (BL-010/015); their `asset` domain used as reference for typed relations only. |
| SBOM ingest/export | **EXTEND** — add SPDX 2.3 export later (BL-025); their sbomexport is CycloneDX 1.6/SPDX 2.3. |
| Vuln sources | **REPLACE (op route)** | OSV live with collapsed reconcile — our own design, kept; their vulnfeed is signed bundles — modeled later at our own cadence, BL-065. |
| EASM | **EXTEND** | crt.sh TODAY; their sast/codescan separation suggests DNS+TLS jobs later (BL-090). |
| SAST | **EXTEND** | rules baseline checked-in; keep pinned engines; add SARIF ingest + branch baselines + PR review screens per repo/commit — design phase 5 (BL-040b). |
| Findings triad | **EXTEND** | Finding ✓ live; Occurrence/Issue [gap] — filter, CLEANER structures before the triad lands. |
| Pentest mgmt | **BUILD NEW** | No OpenCTM-like campaigns in our code; their findings/histories is a reference APPROACH — own tables per requirements D (BL-070). |
| Jira | **BUILD NEW** | outbox — webhooks after (BL-050). |
| Regression domain | **BUILD NEW** | Own design (requirements I) — BL-080. |
| Shauron contract | **KEEP (platform side)** | barad-findings-v1 envelope + pinned engines already define the pieces; `.barad.yml` gets the new versioned contract. |
| Their observed patterns NOT carried: | — | the `asset`+`assettech` heavy model (needs design first, not loose coupling), `sensor`-sized reference things, their sci lang field & AI triage. |
| Dependency-Track / DefectDojo | **KEEP as engines (phase 9 retire path)** | DT stays read-only; Dojo adapter legacy opt-in already. Re-evaluate at gap maturity of licensepolicy instead. |
| Console | **EXTEND** | 6 tabs; needs: SBOM file drop on components (already in F4), Jira/overview dashboards later. |

## Requirements A–J audit (functional, honest)

| Req | Coverage |
|---|---|
| A Scopes | partial: org/project/version/component ✓; typed M2M, service/deployment/asset aliasing [gap] |
| B Supply chain | partial: CycloneDX ✓, per-version inventory ✓, KEV/EPSS/VEX ✓; SPDX export, licenses, policies, continuous reanalysis [gap] |
| C Vulnerability mgmt | strong: findings dedup, severity/triage/SLA, suppressions, history ✓; occurrences/issues/exceptions ✗ |
| D Pentest | ✗ (backlog) |
| E Jira | ✗ (backlog) |
| F Code security | partial: engine+baseline rules ✓; SARIF, PR screens, inline viewer [gap] |
| G EASM | partial: CT domains ✓; wildcard, DNS/TLS probes, snapshots [gap] |
| H Orchestration | partial: CLI adapters ✓, contract v0 [next] |
| I Regression | ✗ |
| J Operation | partial: multi-tenancy single org, RBAC roles ✓, audit chain ✓; backups/jobs/observability [gap] |

Honest-claim rule: anything above marked [gap] or ✗ is not claimed anywhere as
implemented; the matrix is copy-source for the roadmap statuses.

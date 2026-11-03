# OpenCTEM v0.16.1 — functional inventory and clone parity

Source analyzed: `/Volumes/980PRO/Workspace/Councilbox/CYB/openctem` (git tag `v0.16.1`, commit `a3ab8af`), deployed and healthy as the `openctem-*` Compose stack (gateway, web, console, api, postgres, redis, signer). This document is the reference map for building the clean-room clone on our own stack. Items marked *(inferred)* come from package/route names plus shallow reading; everything else was read in code or in the shipped `web/docs/` catalog and `api/docs/glossary.md`.

## What it is

A multi-tenant, Continuous Threat Exposure Management platform. Monorepo: `api/` (Go server, ~140 domain packages under `internal/app`, three HTTP planes), `web/` (Next.js console, 154 pages, 74 sidebar URLs organized in five CTEM stages), `deploy/` (all-in-one image, air-gap, observability). Released separately: `sensor` (scanner executor), `sdk-go`, `ctis` (shared contract), `ci` (CI runner), `sast-rules` (signed OpenGrep rules), `helm-charts`, `openctem-ansible`, `docs`.

## Feature areas (API `internal/app`, grouped)

### Identity, tenancy and access
- auth: sessions, local + MFA/TOTP, OAuth/OIDC/SAML SSO, per-org SSO enforcement, step-up auth, email verification; domain ownership verification (DNS claim listener).
- accesscontrol: roles (RBAC) + Groups (data scope, membership/expiry); datascope: layer-2 enforcement of which assets/findings a member sees; apikey: user API keys and service accounts; scim: SCIM 2.0 provisioning (tokens, users→members, groups→roles); mcpoauth: MCP server with its own OAuth 2.1 (authorize/consent/token/revocation).
- tenant (orgs, members, invitations, settings), orgtrust (cross-org trusts), accessrequest/signup/signupevent/onboarding (invite + domain join + admin approval), accountdeletion, orgdeletion, suspension, supportaccess (time-boxed support sessions), adminapproval (four-eyes on catastrophic platform actions), rekey (encryption-key rotation), platformmfa/platformsociallogin/platformrole/platformuser (platform operator plane).
- audit: immutable hash-chain audit log with exports, chain replication and API-key actor attribution.

### Assets and inventory
- asset (largest package): inventory CRUD/scoring, asset groups + rules, business units/services, branches/compartments, components + software, identifiers, dedup/merge, relationships and state history, overviews; assettech (technology jobs); assetfreshness (per-attribute last-seen); assetdiscovery (newly internet-facing alerts); webendpoint/webevidence (web-surface inventory and per-fetch evidence); apispec (declared API descriptions vs observed drift); sbomexport (CycloneDX 1.6 / SPDX 2.3 export from stored components); connector (asset-inventory connector contract: AWS/GCP/Azure/K8s/Git).

### Attack surface (EASM)
- easm (summary, attribution, changes, lookalikes, sweeps, suggestions, verified domains, network seeds), easmdns (dangling DNS/subdomain takeover, lame delegations, fingerprints, email security), certmonitor (CT-log polling via crt.sh / Cert Spotter, hygiene, exclusions), exposure + exposurebridge (exposure register and bridge into remediation campaigns).

### Scope and probe authority
- scope (scope targets, exclusions, seeds, bulk ops, approvers, widen moderation, audit trail), scope-letters (owner attestation documents), scopeauth/actscope (active-probe authorization per target), webverify (sensitive web-path verification), scan policy gates (blocked-run classification).

### Scanning and scan governance
- scan (configs, profiles, filters, act-scope gates), scanrun (runs, steps, tasks, dispatch, deadline admission), scanpolicy (platform-level guardrails), scangov (approval governance), scancoverage (license-aware rolling coverage planner), scanwindow, scanzone, proxypool (sensor egress proxies with encrypted creds), tool (tool registry), template (scanner-template validation incl. ReDoS-blocklists for nuclei/OpenGrep), codescan (repo code-scanning settings + branch baselines), assignment (auto-assignment rules for findings).

### Sensors / executors
- sensor (fleet, enrollment, config templates, CA, shared fleet), sensorpairing (Ed25519 pairing), sensorgrant (per-sensor scope grants), command + commandlog (claim/balance, signed custom templates, duration learning), sensor protocol v2 (`/api/v2/sensor`) and v3 (HTTPS/mTLS bridge), sensorrelay, pkg/sensorproto + sensorsig/jobsign.

### Findings and vulnerability management
- finding: single source of truth for findings (kinds: vulnerability, secret, misconfiguration, code weakness, compliance) — dedup by fingerprint, dispositions, comments, transitions, priority classification, verification plans, exports, four-eyes approvals, tags, secret redaction.
- findingimport: file imports from other tools via the ctis contract — verified supported formats: Nessus, Qualys, CycloneDX, SPDX, OSV, CSAF, DefectDojo; async queue with receipts, idempotency, dry-run; importmapping (versioned field mappings).
- ingest + ingestqueue: unified CTIS ingestion (sensors, CI, file imports, connectors) with baseline diff, auto-resolution gates, accept-fast queue and backpressure.
- findinglifecycle, evidence, retest/retestcheck, validation (proof-of-fix runs with coverage gates), reclassify (priority recompute), refingerprint, sla (KEV/ransomware-driven SLA deadlines), ai-triage (AI-assisted triage with masking and egress policy).
- Vulnerability/content intelligence: vulnerabilities catalog, vulnfeed (signed vulnerability bundles from `openctemio/vulnfeed` collector), vulnmatch (inventory matching of CVEs against product ranges, per-org reconcile), vex (VEX statements applied to findings), threat (threat actors, KEV/EPSS bundles), threatalert, threatsource, ctemid (feed-synced catalogue), vulnevent (material vuln-change events), licensepolicy (license compliance per package).

### CTEM cycle, attack graph and compliance
- exposure register (above), attack (attack-surface graph: crown-jewel paths, exposure chains), coverage (asset coverage ledger), threatmodel (continuous threat modeling: crown-jewel resolution, exposure chains per attacker profile), compliance (frameworks, controls, pentest checklists), securityoverview (posture score), simulation + controls/control-testing (attack simulation, compensating controls), bountyprogram/programfeed/programtarget (bug-bounty programs, signed program feeds as assets).

### Remediation, ticketing, integrations
- remediation (tasks, campaigns, exceptions/acceptance), ticketing + ticketbridge + ticketmap (generic providers incl. GitHub), jira (Jira app, project policy, webhook → auto-retest), defectdojo (one-way DefectDojo pull-sync), integration (org integrations: credentials store, SSRF-safe webhooks, notification channels, webhook signing).

### CI/CD
- cirun: CI plane — verified routes: `POST /api/v1/ci/oidc/exchange` (OIDC → short-lived upload token), `POST /api/v1/ci/runs/{id}/results` (+ `baseline-diff`, `evaluate`, `results/{report_id}` status), pipelines list/retire, gate overrides, trust configs, SCM apps (scmapp: GitHub/GitLab installs, PR/MR feedback). SBOM import into the inventory is a console route too (`POST .../components/sbom-import`, 50 MB body limit; `GET .../sbom` export) under `permission.ComponentsWrite/Read`.

### Automation, AI, content packs
- automation: event rules (when/if/then) with action handlers (triage, ticketing, pipeline trigger, notifications).
- AI: platformai/tenantai settings, aitriage jobs, ai agents as service principals, aibundle/aimaskmap (confidential masking), aipolicy (egress decisions), aiprompt (injection defenses).
- contentpack/contentcatalog/contentpin/contentsource: signed scanner-content packs, per-org install/pin/rollback, Git rule sources with lint+sign.

### Platform operations
- module/entitlement/storagequota (licensed modules, limits, quotas), systemstatus, versioncheck (signed release feed), configoverview, deploymentregion, instancezone (shared sensors), lifecycle (idle-org sweep), feedstatus/feedsync, outbox (durable webhook/notification delivery), dashboard/dashboards/savedview/navpin/query (custom dashboards, saved views, query language).

## Ingestion surfaces (how data enters)

1. Console REST `/api/v1/**` (user sessions, API keys, service accounts).
2. Sensor protocol v2/v3 (commands claim, results, heartbeats, fingerprints, evidence).
3. CI plane: OIDC exchange → run result upload, baseline diff, gate verdict.
4. File imports: findings (Nessus/Qualys/CycloneDX/SPDX/OSV/CSAF/DefectDojo), SBOM import (50 MB), asset CSV.
5. Connectors (cloud/git asset inventory), DefectDojo one-way pull, inbound webhooks (Jira, GitHub issues, SCM installs).
6. MCP tools for external AI assistants (OAuth 2.1).
7. Signed external feeds: vulnfeed bundles, KEV/EPSS, CTEM-ID, release feed, program feeds, content packs.

## Web console map (features grouped by CTEM stage)

- Scoping: scoping hub, cycles, business context (crown jewels, services, units), scope (targets/exclusions/seeds), scope letters, threat model, programs, capabilities.
- Discovery: scans, sensors, scan-profiles/windows/zones/workflows, scanner templates, proxy pools, ci-runners, attack-surface (overview/review/lookalikes/changes/web surface), assets inventory (+ inventory tabs, groups, activity, identities, repositories), components (SBOM import/export, vulnerable components, ecosystems, licenses), exposures hub (vulnerabilities/secrets/code weaknesses/misconfigurations), credential leaks, vuln-matching.
- Prioritization: exposure chains, attack paths, threat intel, business impact, findings list (+ approvals queue), AI triage, vulnerability catalog, ticket mapping, license policy.
- Validation: pentest (campaigns/findings/retests/templates/reports/MITRE coverage), attack simulation, control testing, compensating controls.
- Mobilization: remediation (+ Solution Families), remediation hub, workflows, pipelines, SLA, exceptions (suppression rules).
- Insights: executive, CTEM maturity, program health, data quality, compliance, reports (recurring emailed digests).
- Cross-cutting: dashboards, my-work, saved views, notifications/announcements, activity, command palette; Settings (users, roles, access control, modules, priority rules, scoring, SLA policies, asset lifecycle, audit, tenant, integrations: CI/CD, SCM, SIEM, ticketing, notifications, SAML, SCIM tokens, MCP, verified domains); platform console (separate app: operators, shared sensors, SSO, verified domains).
- Auth surface: login (local + OAuth + SSO), register, 2FA, email verification, invitations, tenant switching, request-access, MCP consent.

## Clone status — what already exists in Barad-dûr

Verified (AUDIT.md ledger, 91 passing tests, live publications):
- Compose stack: unified PostgreSQL (dtrack + defectdojo databases/roles), Dependency-Track APIs + frontend, DefectDojo, Valkey, Trivy Server (DT's internal analyzer). Loopback-only evaluation environment.
- CLI (`barad`): `scan` / `run` / `health` — Trivy (SBOM CycloneDX, secrets, misconfig) + OpenGrep SAST with pinned/verified engine and checked-in baseline rules; evidence anchored to the invocation workspace, append-only per project/version/scan-id; target never modified.
- Dependency-Track adapter (project/version/SBOM publication with remote-verified inventory, branch-aware versions, PR-blocked) and DefectDojo adapter (legacy opt-in).
- GitHub Action + workflow: credential-free scan job and trusted publish job sandbox.
- Config: `.barad.yml` (no secrets), workspace `.env`, local profiles (e.g. `councilbox-server.barad.yml`).

Clone gap vs OpenCTM areas: no own dashboard/UI, no own API plane, no multi-tenancy/RBAC/audit chain, no CI-run registry (the Action runs the CLI but reports nothing to a gate/verdict API), no scope model, no finding lifecycle (suppressions/SLA/priority/tickets), no vulnerability matching of own (DT owns CVE matching today), no automation.

## POC scope — vulnerability management (this branch's first milestone)

Mapping the POC use cases onto the inventory:

| POC use case | OpenCTM model to adopt | Barad-dûr present | Missing work |
|---|---|---|---|
| Ingest an SBOM (CI/CD, manual, web, API) | `components/sbom-import` (50 MB), file-import receipts/idempotency, OIDC CI plane | CLI `scan`/`run` → DT publication verified | Own ingest API + queue with receipts; CLI pushes to it as third integration |
| Index list dependencies | asset components inventory + SBOM export (CycloneDX/SPDX) | local inventory normalization in CLI + DT | Own normalized components store + list/export endpoints |
| Analyze vulnerabilities from sources | vulnfeed signed bundles, vulnmatch against inventory, CVE catalog | DT analyzers feed findings | Our own source ingestion (OSV/NVD/Trivy DB) + matcher; DT stays the engine during the POC |
| Trivy config/secrets reports | findings kinds + evidence, secret redaction | CLI produces `security.json`, sanitized report | Shared findings model: persist, list, lifecycle |
| SAST (OpenGrep) incidence management | code weaknesses as findings, suppression rules, remediation | CLI produces `sast.json`, local evidence only | SAST findings ingestion + issue workflow (suppressions, priority) |
| See CI/CD pipelines + workflows | ci-run registry, pipelines, runs, baseline diff, gate | GitHub Action runs the CLI but nothing is registered in a platform | Pipeline/run registry + run reports surfaced via API/UI |
| Scopes for audits/analyses | scope targets/exclusions + act-scope authorization | nothing | Scope model applied to scans/audit scope |
| Audit trail | hash-chain audit log, activity feed | manifest/checksum evidence only | Own audit event log |

Deliberately inherited, not cloned: Dependency-Track and DefectDojo stay as engines during the POC — the clone replaces OpenCTM's *platform layer* (tenancy, findings lifecycle, CI registry, scope, audit, UI), not the scanner internals, exactly like OpenCTM itself delegates sensing to the external `sensor` repo and matching to signed feeds.

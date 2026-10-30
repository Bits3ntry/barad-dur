# OpenCTEM v0.16.1 — data-structure map for the clean-room clone

Derived from `api/migrations/` (baseline `001146` = 228 tables; ~100 later `CREATE TABLE` migrations → ~330 total) and `api/pkg/domain/*` (one aggregate package per domain: `entity.go`, `value_objects_*.go`, `repository.go`). Goal: port the *concepts*, not the code — our backend is Python, our frontend React (JS, no TS). None of their source is copied; everything below is the design we re-implement differently.

## Tenancy and data scope

- Essentially every table carries `tenant_id` (the org is called "tenant" internally; the console says "organization"). Only global catalogs are tenant-free: `vulnerabilities`, `cve_records`, `kev_catalog`, `epss_scores`, `asset_types`, `finding_sources`, `licenses`, tool metadata.
- Identity: `tenants → tenant_members (role) → users / sessions / refresh_tokens`; teams = `groups (tenant_id, group_type)` + `group_members (role)` + `group_role_bindings`. A tenant flag `members_without_group_see` sets default visibility when nobody owns an asset.
- Data scope is enforced relationally — by membership relationships (`asset_owners(group_id)`, `finding_group_assignments`, `group_asset_scope_rules` with tags/logic/priority, `asset_access_grants`, `user_accessible_assets`), not a scope column per business row.

## Findings — the core model

- One table (`findings`, ~170 columns) with a discriminator (`finding_type`, `kind`, `family`, `subcategory`) and **inline column families per kind** rather than per-kind detail tables:
  - `secret_*` (type, service, valid, revoked, entropy, expires_at)
  - `compliance_*` (framework, control id/name, result, section)
  - `misconfig_*` (policy id, resource type/name/path, expected, actual)
  - web3 family (we drop it)
  - code-weakness/SAST lives with `cwe_ids`, `owasp_ids`, `vulnerability_class`
- Lifecycle columns: status, resolution (+method), acceptance_expires_at, duplicate_of/count, reopen_count/is_regression, baseline_state, validation_outcome, VEX status/justification/statement.
- Priority/SLA: `priority_class` (+reason/override columns), `sla_deadline`, `sla_status`; policy tables define per-class day buckets and override rules.
- **Dedup identity (their signature concept):** `fingerprint = sha256(asset_id + ':' + per-kind base)`, plus `fingerprint_version`, `identity_key`, `location_key`, and a JSONB `partial_fingerprints` map with multiple algorithms (namespaced server-only keys). Each kind has its own fingerprint strategy, e.g. SAST hashes asset+rule+filePath+normalized snippet so line shifts do not break dedup; secret identity re-keys a tenant-HMAC of the raw secret (plaintext never stored). Side tables: `finding_fingerprints` (version history), CI runs and audit "still-detected" lists attach findings **by fingerprint, not FK**, which survives asset merges (re-key runs exist for that).
- Side tables: activities, comments, suppressions (application rows), status approvals, evidence, retests, correlations/data-flows.

## Vulnerability catalog vs finding vs components

- `vulnerabilities` is a **global** catalog (cve_id or external advisory id, CVSS, exploit_available, merged_into for dupe advisories; findings reference it via nullable `vulnerability_id`). Enrichment: `kev_catalog`, `epss_scores`, `cve_records`, range-match tables + async `vuln_match_queue`.
- SBOM store = `asset_components` (asset×component join with `purl`, `cpe`, `ecosystem`, `package_manager`, `namespace`, `license`, `manifest_file/manifest_path` provenance, `parent_component_id`, `depth`, `is_direct`, risk columns) over global `components` keyed by `purl` + SPDX `licenses` catalog. SCA findings sit at asset×component×vulnerability.
- They ALSO keep a second, parallel runtime-software inventory (`software_products`/`asset_software_evidence`) — **a dual model we do not need; we take components keyed by purl only.**

## Evidence and secret redaction (migration 001223)

`finding_evidence` (content, `content_sha256`, size, truncated, `masked_count`, `placeholders` JSON) + `finding_evidence_secrets` (evidence_id, placeholder, `secret_kind`, `ciphertext`, `expires_at`): the ingest path redacts evidence bodies into placeholder tokens and stores per-placeholder ciphertext tenant-encrypted with TTL. Plaintext secrets must never sit in a findings row — this is the part worth keeping verbatim as a concept.

## Ingestion and receipts

- Ingest is one queue: `ingest_jobs` (payload + sha, protocol, status, attempts, locker) → `ingest_reports`; per-import receipts in `finding_imports` with counters (assets created/updated, findings created/updated, components, statements, skipped) and `filename_sha256`. Domain model accumulates per-delta counts (created/reopened/closed, still-detected fingerprints, policy decisions, errors) onto one receipt so a multi-batch upload counts each finding once. Idempotency + dry-run + coverage checks live here.
- SBOM import has **no dedicated sbom table** — it rides the generic ingest into `asset_components`.

## CI plane

- Trust: `ci_trust_configs` (provider, OIDC issuer, audience, rules JSON, default-branch flag) + owner pins + `ci_oidc_replay` (replay protection) + tenant flag `ci_require_oidc`.
- Registry: `ci_pipelines` (provider/issuer, repo id, workflow path, asset link, trust config, last-run + median interval, retire/revoked columns).
- Runs: `ci_runs` (repo, ref/branch/commit, event, actor, fork, token_hash+expiry, status, **verdict + verdict_detail**, evaluated_at). Bridge `ci_run_findings (tenant_id, run_id, fingerprint)` — fingerprint-bound, not FK, deliberately merge-tolerant (we start with `finding_id` FK and adopt fingerprint bridging only if asset-merge matters).
- Gates: `ci_gate_policies` (scope repo/business-unit, mode, fail_on_severity, new-findings-only, fail-on-KEV, EPSS threshold) evaluated domain-side with **fail-closed on scan failure** and a capped reason list (verdicts render in public CI logs); overrides are repo+commit-scoped with reason/expires/revoked_by.
- The scanner/orchestration plane (scans, pipeline templates, sensor tables, commands, tool executions) is a separate set we do NOT clone — our scanners are the Barad CLI + engines.

## Suppressions / exceptions

- Two layers: tenant-level `suppression_rules` (criteria: rule id / tool / path glob / asset scope; type `false_positive | accepted_risk | wont_fix`) with the **approval workflow embedded in the row** (status pending→approved/rejected/expired, requested_by, approved_by, rejection_reason, expires_at) + per-finding application rows `finding_suppressions (rule_id, finding_id, applied_at/by)`.
- Four-eyes is domain logic: requester can never approve own rule; a sole-active-owner self-approval is guarded with a cooldown after recent member removal (fail-closed when the checker is unwired).
- Per-finding manual acceptance uses a separate approvals path; scan-tool/source hash changes auto-suspend old decisions (re-decidable on the new baseline).

## Scope

- Positive list `scope_targets` (target_type, pattern, priority, status, tags) **with approval metadata embedded** (reason/expires/Tier 1|2, approvals required, approvals[], attestation for Tier 2, origin). Authorization is chained at read time: source → optional bug-bounty program or authorization letter → tenant trusts.
- Negative list `scope_exclusions` (type, pattern, reason, status, expires, approvals).
- `scope_snapshots` + per-run/per-cycle snapshot tables freeze the resolved scope of each run (auditability of "what was in scope when this ran").

## Audit chain

- `audit_logs` (actor, ip/agent, action, resource, changes JSON, result, request/session ids) + **separate per-tenant chain table** (`audit_log_id, prev_hash, hash, chain_position`), extended inside a per-tenant advisory lock so concurrent writers can never fork the chain. Pruning seals the tail into `audit_chain_anchors` and rebaseline entries. Admin actions have a parallel chain.

## Our keep / drop / simplify (POC)

**Keep (concepts):** composite fingerprint + per-kind recipes + `partial_fingerprints` JSONB + `fingerprint_version`; two-layer suppression rule with embedded approval + application rows; per-tenant audit hash chain in a side table (advisory-lock append, anchors on prune); ingest receipts with counters; `asset_components` keyed by purl with manifest provenance; evidence redaction into placeholders + tenant-encrypted per-secret ciphertext with TTL; CI gate policies separate from pipeline with commit-scoped, expiring overrides; fail-closed gate evaluation with short public reason lists; tenant_id everywhere from day one.

**Drop:** the megatable shape (one slim findings core ~30 columns + `kind` + one JSONB `type_details` per kind — they themselves migrated late-added complexity into extra detail tables, which proves JSONB is the right starting shape); the dual dependency model (components-purl only); web3/ASVS families; the sensor/orchestration tables and generic DAG workflow executor; five alert-state/coverage tables per surface; bounty/SCIM/content-pack tables.

**Simplify:** findings attach to CI runs by `finding_id` FK first (fingerprint bridge only when merge/dedup at scale demands it); scope approval log folded into the targets row (JSONB approvals array like theirs); one shared entity-audit trail instead of audit tables per surface; rows carry `row_version`/`last_seen` for TOCTOU-safe updates; skip their scoring re-queue machinery (priority + policy buckets suffice at POC scale); RLS on tenant_id from day one (cheap, avoids grant sprawl they hit later).

## Carry into our Python schema

1. `organizations`, `memberships`, `groups`, `group_members` (+RLS on org).
2. `findings` (slim core + kind + `type_details` JSONB + fingerprint columns) with per-kind fingerprint strategies implemented in Python.
3. `finding_evidence` + `finding_evidence_secrets` (placeholder redaction + encrypted secrets with TTL).
4. `components` + `asset_components` (purl-keyed, manifest provenance) + `sbom_imports` receipts (no separate queue service needed at POC scale; one table + worker).
5. `suppression_rules` + `finding_suppressions` + no-self-approval guard.
6. `ci_trust_configs`, `ci_pipelines`, `ci_runs`, `ci_gate_policies`, `ci_gate_overrides` (+ run→finding bridge).
7. `scope_targets`, `scope_exclusions`, `scope_snapshots`.
8. `audit_log` + `audit_log_chain` (per-org advisory lock) with anchors.
9. Global ref tables: `vulnerabilities` (+ `kev_catalog`, `epss_scores` optional), `licenses`.

# POC scope — frozen (10-day plan)

This document governs the vulnerability-management POC. Scope is frozen on D1; changes require amending this file. Stack decision (user-agreed): Python backend, React JS frontend (no TypeScript). Reference concepts come from `docs/openctem-data-model.md`; no OpenCTM source is copied.

## What the POC delivers

A mix of Dependency-Track and DefectDojo, ours: SBOM ingestion from the Barad CLI, CI/CD, API and manual upload; a normalized dependency inventory; vulnerability analysis from public sources; and management of Trivy (secrets/misconfiguration) and OpenGrep (SAST) incidents: dedup, dispositions, suppressions.

## Phases and test gates (each gate is a real end-to-end check a human can run)

- **F0 — Contract + core (D1–2):** `backend/` FastAPI service with API-key auth; schema v0 (organizations, api_keys, projects, project_versions, sbom_imports receipts, components by purl, version occurrence rows); `POST /api/v1/sbom` (CycloneDX, 50 MB cap, idempotency on project+version+content-sha256), receipt detail, `GET /api/v1/projects`, `GET /api/v1/components`. CLI gains a third integration `platform_api` publishing the verified SBOM.
  Gate: `barad run` on a test repo → CLI reports PUBLISHED → `curl /api/v1/components?project=…` lists the inventory.
- **F1 — Vulnerability engine (D3–4):** OSV/NVD-based matching of the inventory to CVEs; findings of kind `vulnerability` created from matched components.
  Gate: a pinned dependency with a known CVE appears as a finding with severity and source reference.
- **F2 — Findings ingestion + incident management (D5–6):** sanitized Trivy report (secrets/misconfig) and OpenGrep `sast.json` ingested into the same findings table using per-kind fingerprint strategies; suppression rules (embedded approval, no self-approval) and per-finding dispositions.
  Gate: re-scan does not duplicate findings (fingerprint test); an approved suppression removes a finding from the default view.
- **F3 — CI registry + scope, static (D7–8):** CI pipelines/runs registry (read-only runs, gate verdict text), scope targets without attestation letters.
  Gate: the GitHub Action run of a fixture repo shows up in the registry with its verdict.
- **F4 — Minimal UI (in parallel, D7–8):** React JS four screens only: findings list + detail, components (+ manual SBOM upload), pipelines/runs. One list per domain, no charts.
- **F5 — End-to-end hardening (D9–10):** action integration, docs (5-command quickstart), ingest limits, AUDIT.md ledger update, demo rehearsal.

## Single-org POC

Schema carries `org_id` from day one (cheap, matches their tenancy audit trail); the API and UI expose exactly one organization in the POC. Multi-tenant surfaces come after the POC.

## Explicitly OUT of scope for the 10 days

SLA policies and priority machinery (severity-only ranking), tickets/Jira/GitHub sync, EASM/DNS/CT, attestation letters and scope approvals, audit hash chain (plain audit table only), automation rules, AI triage, MCP, SCIM/SSO, multi-tenancy UI, replacing DT or DefectDojo as engines (they stay running; our API is additive).

## Runtime shape for F0

- PostgreSQL: the existing Compose server gains one database (`barad_platform`) and one role, created by a one-shot init service; the server publishes loopback-only (`127.0.0.1`) for host-side CLI/API development during the POC.
- The platform API runs from `backend/` (installable, entrypoint `barad-platform`); Docker packaging of the service is F5 hardening, not F0.
- Engines unchanged: DT + DefectDojo + Trivy Server keep running as-is; the CLI's existing two integrations are untouched; `platform_api` is additive and disabled by default.

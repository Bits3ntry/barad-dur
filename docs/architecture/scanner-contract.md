# Barad-dûr ↔ Shauron scanner contract (v0 draft)

Shauron is an independent product (CLI, GitHub Action, sensor/worker). This
repo ships the *platform side* of the contract; Shauron's repo (new) builds the
runner. Nothing here couples scanner identity to persistence entities.

## Goals of the contract
1. Same verbs for every engine: sbom, secrets, misconfig, sast, dast-passive,
   auth-analyzed (later pentest), regression (authorized only).
2. Versioned, additive: upload/downgrade of the contract is rejected by the
   platform, not guessed.
3. Ephemeral execution: runner containers isolate per run; the platform never
   trusts "shauron says" — every result carries the run identity + tool version
   + fingerprint recipe id, and dedupes against the same recipes the platform
   already uses.

## Contract v0 (first slice to land in phase 7)

```
POST /api/v1/scanner/v0/begin        -> {run_id, upload_token (short-lived), recipes[]}
POST /bag-digest /api/v1/scanner/v0/findings   (chunked, ≤ 1k/req, barad-findings-v1)
POST /api/v1/scanner/v0/request-authorization {asset_id, profile} -> explicit grant/deny
   (denied for intrusive profiles without scan_authorizations)
POST /api/v1/scanner/v0/finish       {verdict, counters, evidence_refs (redacted)}
```

- Auth: OIDC exchange (action identity) **or** API key for sensors; upload_token
  binds to `run_id` only.
- `barad-findings-v1` stays THE envelope schema; recipes array lets the
  platform confirm which fingerprint kind the scanner used.
- Evidence: never raw secrets; ref-blobs with pre-set redaction — the same
  boundary the CLI already enforces (tests pin it).

## Trivy/OpenGrep today vs Shauron

The `barad` CLI currently runs Trivy + pinned OpenGrep directly and publishes
through its platform/DT/dojo adapters. Shauron keeps that code path but lives
outside: CLI + GitHub Action composite (existing `action/`) becomes a thin
installer, the sensor is the long-running picker for scheduled scans. Migration
order: contract land → CLI delegates its run to the contract → action keeps
local fallback for air-gapped machines.

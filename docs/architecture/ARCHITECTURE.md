# Consolidated Barad-dûr boundaries

The local CLI is a thin consumer of existing scanner, versioning, validation and HTTP modules. Compose owns the persistent services; no server, dashboard, AI worker or new MCP process was introduced. The older `barad_security` runner and CI workflow remain operational while migration is deliberate.

## Execution map

```text
barad (pyproject.toml -> cli/barad/cli.py)
  scan/run -> commands/scan.py -> scan.py -> barad_security.trivy.TrivyRunner
                                  -> barad_security.sbom / sanitize / versioning / gitctx
                                  -> store.py -> .barad/reports + .barad/state
  run -> integrations/dependency_track.py -> barad_security.http.HttpClient -> DT API
      -> integrations/defectdojo.py       -> barad_security.http.HttpClient -> Dojo API
  health -> read-only local subprocess + authenticated GET diagnostics

existing .github/workflows/security.yml -> bin/barad-security -> barad_security/ (preserved)
compose.yaml -> DT API/frontend/PostgreSQL, Dojo nginx/uwsgi/celery/PostgreSQL/Valkey,
                Trivy server, optional scanner tools; named persistent volumes unchanged
```

`pyproject.toml` builds an independent wheel containing both `barad` and the reused `barad_security` package/schema. CLI command names are stable regardless of future API placement. `defectdojo_mcp/` and `scripts/` are preserved, not moved or merged because their consumers and historical data were not proven safe to remove. Existing `_docs/` holds earlier POC notes; current CLI contracts live in [docs/CLI.md](../CLI.md).

## Data contracts and trust

| Boundary | Input | Output and invariants |
|---|---|---|
| Project configuration | Optional `.barad.yml` + environment override | Strict known keys; token values only from env, never persisted. `barad-security.yml` remains a separate legacy runner contract. |
| Scanner | Filesystem directory/JAR or explicit built image | Trivy JSON on **every** scan, CycloneDX JSON on **every** scan; failures never become success. Docker target mounted read-only, evidence directory writable/private. |
| Local evidence | Scanner reports, Git/version context | `.barad/reports/<scan-id>/` immutable per run ID plus `.barad/state/local-inventory.json`. Raw secret evidence owner-only and ignored by Git. Manifest hashes are about artifact bytes; fingerprint is about normalized inventory. |
| Dependency-Track | CycloneDX + exact project/version and event policy | Authenticated lookup, optional creation, remote BOM export comparison, upload only when new/changed/unverifiable. Token completion plus exported inventory comparison needed to claim PUBLISHED. Pending token saved locally only to avoid immediate duplicate submission; it is **not** remote publication proof. |
| DefectDojo | Sanitized Trivy JSON | `Trivy Scan` Import/Reimport into stable Product/Engagement/Test; remote identity and product checked; `close_old_findings=false`; finding count observed. Optional failure cannot destroy scan evidence. |
| Health | Tools, optional service endpoints | Only version probes and authenticated GETs. Missing optional integrations are NOT CONFIGURED, not a standalone failure. |

Inventory fingerprint v4 includes normalized PURL+version or name/type/version fallback, sorted distinct dependency edges, canonical metadata-root edge and target/image reference; nondeterministic CycloneDX metadata is ignored. DT rewrites the root bom-ref to its project UUID on export, so the canonical target-root node is essential for idempotence. The original SBOM SHA-256 remains independent. A local snapshot can tell `scan` what it scanned before, never what a remote API accepted.

## Context and status policy

- PR and non-default branches: scan/report; do not create stable DT project versions. `BARAD_DEFAULT_BRANCH` chooses the trusted development branch; release events require a stable resolved version.
- Default branch/local trusted context: use detected application version, independent of dependency changes. DT creates/updates only with enabled integration and explicit `auto_create` for missing versions. No broad “Latest” promotion.
- DefectDojo: stable test title per Product + version; repeated imports reimport the same Test, not a new historical Test. Old findings are not automatically closed. A successful HTTP POST is not proof of parser completeness.
- A scan can be `completed` while a synchronization is `partial` (exit 4); artifacts and processing token remain traceable. Network errors are sanitized; secrets never appear in the manifest.

## Deployment and migration

`docker compose config --quiet` validates the existing stack, and `docker compose up -d` starts core services with the original `.env` and volumes. Never use `down -v`, rename volumes, rotate DefectDojo's credential-encryption key or overwrite the live `.env` without a backup/restore plan. See [README.md](../../README.md). The CLI uses Docker Trivy on demand; the Compose Trivy **server** is a separate analyzer endpoint for Dependency-Track, not an assumption that scanning a Dockerfile scans a built image.

Future GitHub Action: install the same wheel; on PR call `barad scan`, on trusted default/release call `barad run` with secret env vars, then upload manifest and sanitized report. The current workflow still calls the older `barad_security` entry point; migration needs separate CI validation and should not silently alter working publication behavior. Central API/MCP/dashboard/workers can later consume the manifest and move adapters server-side without changing the three CLI commands.

## Known limitations

Loopback Compose is a POC (no TLS/SSO or production RBAC). A fresh isolated Trivy cache could not refresh its vulnerability DB during this audit because DNS for `mirror.gcr.io` timed out; repository-root scanning used an existing warm cache. Real image and JAR content scans, CI migration, backup/restore drill, and production credential lifecycle remain UNVERIFIED. Existing tracked `tests/`, `examples/`, `docs/` deletions were present before this task; no destructive cleanup was performed. See [audit](AUDIT.md) for observed commands and failures.

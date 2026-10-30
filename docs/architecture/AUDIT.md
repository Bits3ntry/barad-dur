# Verification ledger

This ledger records observed checks for the current architecture. It does not turn unrun checks into claims.

## 2026-10-30 F0 gate: platform API SBOM ingestion (POC first milestone)

Isolated fixture `/tmp/barad-platform-gate` (requirements.txt with `requests==2.32.3`, `urllib3==2.2.1`, `app.py`, version-source pyproject), platform API at 127.0.0.1:8090, database `barad_platform` on the existing Compose PostgreSQL (loopback publish 15443). Record:

| Check | Result | Evidence |
|---|---|---|
| Compose validation with the F0 changes | PASS | `docker compose config --quiet` exited 0 in both the worktree and the live deployment checkout. |
| Migrations to real PostgreSQL | PASS | `barad-platform migrate` applied `0001_core`; seven tables listed via psql. |
| Readiness and auth | PASS | `GET /healthz` → `{"status":"ok"}`; unauthenticated `GET /api/v1/projects` → 401. |
| End-to-end publication | PASS | `barad run` on the fixture: `scan: SUCCESS`, `platform_api: PUBLISHED (receipt_verified)`; manifest sync shows the receipt import id and matched component counts. |
| Inventory via API | PASS | `GET /api/v1/components?project=platform-gate-fixture&version=0.1.0` returns 3 rows (requests, urllib3, the requirements.txt pseudo-component) with purl/version/identity. |
| Rescan stability | PASS | Second consecutive `barad run`: receipt counters `components_created=0`, `links_created=0`; database keeps exactly 3 components and 3 version links after the pre-fix data was truncated (user-approved). |
| Automated suites after the fixes | PASS | 151 CLI unittests; 15 pytest (9 backend acceptance incl. the identity-stability test, 6 adapter contract). |
| Live OpenGrep on macOS | PASS (after fix) | Full-CLI asset produced `sast.json` with exit 0 and 0 findings on the benign fixture; `security.sanitized.json + sbom.cdx.json` written. |

Discovered live and fixed during this gate:

1. `engines.lock.json` pointed macOS/Windows to the `opengrep-core` OCaml asset, which does not accept the runner's full-CLI argv (Linux was already pinned to the full CLI). Both now pin the official full-CLI assets with upstream digests, and `--no-progress-bar` (a semgrep-only flag) was replaced with `--disable-version-check`, keeping the scan boundary credential-free.
2. The CLI's SBOM upload 422ed twice: the SBOM is delivered as raw bytes (`application/octet-stream`) and `project`/`version` travel as query overrides because Trivy SBOMs omit `metadata.component.version`.
3. Trivy mints a random `bom-ref` per run for purl-less pseudo-components; identity is now the documented `nonpurl:sha256(name:version)` recipe instead of the raw bom-ref, so rescans dedup instead of duplicating.

Limits: the platform API runs as a checkout process with a live dev server (container packaging stays F5); Dependency-Track and DefectDojo remain `NOT_CONFIGURED` in this gate (the fixture enables only `platform_api`); the live deployment checkout at `/Volumes/980PRO/.../Barad-d-r` received the compose port publish + edge attachment directly (same change mirrored in this worktree) — the two trees stay in sync only until this branch merges.

## 2026-10-29 consolidation verification

| Check | Result | Evidence |
|---|---|---|
| Compose syntax | PASS | `docker compose config --quiet` exited 0. |
| Persistent services | PASS | `postgres`, `dt-apiserver`, `dt-frontend`, `dojo-nginx`, `dojo-valkey`, and `trivy-server` were running; PostgreSQL, DT API, Dojo nginx, Valkey, and Trivy Server reported healthy. |
| Existing automated tests | PASS | `PYTHONPATH=cli:. .venv/bin/python -m unittest discover -s tests -q` ran 91 tests successfully. |
| External installation | PASS | Built and installed the `barad` wheel into a new virtual environment outside the repository. |
| Read-only diagnostics | PASS | External `barad health --json` reported `HEALTHY` for CLI, Git, Docker Trivy 0.76.1, Dependency-Track, and DefectDojo. |
| Isolated scan | PASS | External `barad scan` against an isolated project containing `requests==2.32.3` completed and wrote `security.json`, `sbom.cdx.json`, and `manifest.json`; the SBOM had 2 components. |
| Dependency-Track publication | PASS | Isolated project `barad-architecture-isolated` version `0.1.0` was published as UUID `516b0f6e-b816-4545-a873-88b836bd835e`; the adapter verified the exported normalized inventory. A second run reported `UNCHANGED: remote_inventory_verified`. |
| DefectDojo import/reimport | PASS | The same isolated project imported through the `Trivy Scan` parser into test `9` with 2 observed findings and `close_old_findings=false`; the second run reimported test `9`. |

## Reproduced and corrected during verification

The first external scan used an intentionally minimal project. Trivy 0.76.1 returned a schema-valid JSON report without `Results`; the CLI had treated it as malformed. `cli/barad/core/trivy.py` now recognizes that output as a successful empty scan and `tests/test_trivy_empty_result.py` covers it.

That project had no components in its CycloneDX SBOM, so the CLI correctly returned an incomplete inventory rather than claiming success. Adding a declared `requests` dependency produced the successful two-component isolated scan above.

## 2026-10-29 clean-architecture follow-up

- Moved the active core from `barad_security/` to `cli/barad/core/` and removed `cli/barad/integrations/` compatibility modules.
- Built a wheel with `pip wheel --no-deps`; it includes `barad/core/` and both `integrations/` adapters, but no `barad_security/` or `barad/integrations/` package paths.
- Reinstalled the wheel from an external directory and completed `barad scan` against the existing isolated dependency project using its warm Trivy cache.
- A fresh isolated cache could not complete the Trivy scan (`exit 1`); this is recorded as a cache/feed limitation, not a successful cold-cache scan.

## 2026-10-29 external-workspace evidence

- Added `--out`/`-O DIR` to `barad scan` and `barad run` (existing `--output` still recognized).
- Default evidence, state, and Trivy cache anchor to the invocation directory, so scanning an external project leaves its tree untouched; a contract test covers it.

## 2026-10-29 per-project evidence layout

- Evidence moved from `.barad/reports/<scan-id>/` to `<reports>/<project>/<version>/<scan-id>/` with an `unresolved` folder when the version cannot be resolved yet.
- Scan ids carry a UTC timestamp plus randomness, so repeated scans of the same project+version append new scan-id folders; the earlier replace/`version_(n)` prompt was removed as unnecessary since scan-id uniqueness already prevents collisions.
- The same behavior applies to `barad run` and its publication records; DefectDojo/Dependency-Track remote logic is unchanged.

## Limits

- The GitHub Actions workflow and composite action were structurally and behaviorally tested locally, but no GitHub-hosted workflow run was available in this environment.
- This ledger does not validate production TLS, SSO, RBAC, backup restoration, image scanning, or JAR scanning.
- The Compose stack remains a loopback-only evaluation environment. Persistent volumes and backup/rollback volumes were not altered.
- The user elected to preserve the pre-existing legacy deletions without committing them. The recorded commits therefore rely on the current worktree deletion set for the 91-test layout; no pre-existing deletion was staged, reverted, or committed by this consolidation.

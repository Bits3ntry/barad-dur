# Verification ledger

This ledger records observed checks for the current architecture. It does not turn unrun checks into claims.

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

## Limits

- The GitHub Actions workflow and composite action were structurally and behaviorally tested locally, but no GitHub-hosted workflow run was available in this environment.
- This ledger does not validate production TLS, SSO, RBAC, backup restoration, image scanning, or JAR scanning.
- The Compose stack remains a loopback-only evaluation environment. Persistent volumes and backup/rollback volumes were not altered.
- The user elected to preserve the pre-existing legacy deletions without committing them. The recorded commits therefore rely on the current worktree deletion set for the 91-test layout; no pre-existing deletion was staged, reverted, or committed by this consolidation.

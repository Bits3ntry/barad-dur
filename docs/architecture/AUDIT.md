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

The first external scan used an intentionally minimal project. Trivy 0.76.1 returned a schema-valid JSON report without `Results`; the CLI had treated it as malformed. `barad_security/trivy.py` now recognizes that output as a successful empty scan and `tests/test_trivy_empty_result.py` covers it.

That project had no components in its CycloneDX SBOM, so the CLI correctly returned an incomplete inventory rather than claiming success. Adding a declared `requests` dependency produced the successful two-component isolated scan above.

## Limits

- The GitHub Actions workflow and composite action were structurally and behaviorally tested locally, but no GitHub-hosted workflow run was available in this environment.
- This ledger does not validate production TLS, SSO, RBAC, backup restoration, image scanning, or JAR scanning.
- The Compose stack remains a loopback-only evaluation environment. Persistent volumes and backup/rollback volumes were not altered.

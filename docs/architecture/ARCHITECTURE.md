# Barad-dûr architecture

The repository has four active runtime boundaries: root Docker Compose, the installable CLI, reusable remote integrations, and a local GitHub Action adapter. Everything else is intentionally out of scope.

## Execution map

```text
barad (pyproject.toml -> cli/barad/cli.py)
  scan/run -> cli/barad/scan.py -> barad.core.trivy.TrivyRunner
                                  -> barad.core.sbom / versioning / inventory
                                  -> cli/barad/store.py -> workspace .barad/reports + .barad/state							  (workspace anchors evidence; the scan target is never written)
  run -> integrations/dependency_track -> Dependency-Track API
      -> integrations/defectdojo       -> DefectDojo API
  health -> local tool checks + authenticated GET diagnostics

action/action.yml -> installs this checkout -> barad scan | run | health
.github/workflows/security.yml -> same CLI, with separate scan and trusted publish jobs
compose.yaml -> unified PostgreSQL, Dependency-Track, DefectDojo, Valkey, Trivy Server
```

`cli/barad/core/` holds the single CLI implementation of scanning, SBOM validation, versioning, evidence, inventory, and HTTP. `integrations/` holds the only remote adapters; no compatibility wrapper or second implementation remains.

## Boundaries

| Boundary | Owns | Does not own |
|---|---|---|
| `compose.yaml` | Persistent service topology and volumes. | CLI scans, application API, dashboards. |
| `cli/barad/core/` | Trivy mechanics, SBOM validation, identity/version resolution, safe HTTP, inventory normalization, evidence hashing. | CLI command parsing and remote workflow orchestration. |
| `cli/barad/` | Three commands, local evidence layout, scan/run orchestration, read-only health checks. | Remote adapter implementations. |
| `integrations/` | Dependency-Track and DefectDojo API adapters. | Trivy execution or CLI argument parsing. |
| `action/` | GitHub Actions dispatch to the installable CLI. | A separate scanning engine. |

## Data and safety contracts

- PostgreSQL remains one server with separate `dtrack` and `defectdojo` databases and roles. Existing backup and rollback volumes are external and are never removed by Compose.
- Raw Trivy reports and execution logs are private evidence. The manifest, sanitized report, SBOM, and checksums are suitable for controlled sharing.
- Evidence, state and the Trivy cache anchor to the invocation workspace (or the `--out`/`-O` directory for reports). Reports nest one level per project and one per resolved version; each run appends a timestamped scan-id folder and never replaces prior evidence. Scanning a target never writes into the target; explicit `--out` inside the target remains possible by user choice.
- `scan` creates artifacts but has no remote mutation. `run` preserves scan evidence if either adapter is unavailable or partial. `health` issues no writes.
- Dependency-Track publication is verified by an exported normalized SBOM, not inferred from HTTP success.
- DefectDojo reimport is bound to a stable test and Product; it never auto-closes historical findings.
- The workflow has a credential-free scan boundary and a trusted publish boundary. It never uploads the raw report.

## Verification boundary

Unit and contract tests are rooted at `tests/`. Compose syntax is validated with `docker compose config --quiet`. Operational tests must create explicitly named isolated targets and record the actual remote identifiers and outcomes in [AUDIT.md](AUDIT.md). A test or document must not claim live service behavior without that record.

## Excluded components

No dashboard, custom API, MCP, AI worker, Syft, or CycloneDX CLI is part of this architecture.

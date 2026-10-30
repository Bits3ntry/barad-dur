# BARAD-DÛR

Barad-dûr is a local security-analysis foundation: one persistent Docker Compose stack, an installable Trivy and OpenGrep CLI, and a reusable Dependency-Track adapter. It is a loopback-only evaluation environment, not a production deployment.

## Quick path

```sh
# Validate the existing persistent stack without changing it.
docker compose config --quiet

# Install and use the three-command CLI.
python3 -m venv /tmp/barad-venv
/tmp/barad-venv/bin/python -m pip install .
/tmp/barad-venv/bin/barad health
/tmp/barad-venv/bin/barad scan .
/tmp/barad-venv/bin/barad run .
```

`barad scan` writes Trivy `security.json`, `sbom.cdx.json`, OpenGrep `sast.json`, and `manifest.json` into `.barad/reports/<project>/<version>/<scan-id>/` anchored to the directory where you run it, so a scanned project is never modified; `--out`/`-O DIR` chooses the reports directory. Scan ids carry a UTC timestamp, so re-scanning the same project+version simply adds a new scan-id folder; no evidence is ever replaced. Raw `security.json` and `sast.json` are private evidence; do not upload them. Trivy checks secrets and misconfigurations, Dependency-Track owns dependency vulnerabilities from the SBOM, and OpenGrep owns SAST. `barad run` uses the same scan and synchronizes only enabled integrations. `barad health` is read-only.

## Architecture

| Boundary | Location | Responsibility |
|---|---|---|
| Infrastructure | `compose.yaml` | Unified PostgreSQL, Dependency-Track, DefectDojo, Valkey, Trivy Server, and on-demand Trivy. |
| CLI | `cli/barad/` | The only command surface: `scan`, `run`, and `health`. |
| CLI core | `cli/barad/core/` | Trivy invocation and SBOM validation, OpenGrep SAST execution, versioning, evidence identity, inventory normalization, and HTTP safety. |
| Integrations | `integrations/dependency_track/` | Reusable remote adapter for project/version/SBOM. |
| GitHub Action | `action/action.yml` | Composite adapter that installs the CLI; its EngineManager resolves the same pinned OpenGrep engine as local execution. |
| Platform POC | `backend/` + `frontend/` + `compose.yaml` (`platform-api`) | The vulnerability-management POC: FastAPI service, React (JS) console and CI registry; see [docs/PLATFORM.md](docs/PLATFORM.md) for the 5-command quickstart and [architecture/AUDIT.md](docs/architecture/AUDIT.md) for the gate ledger. |
| Tests | `tests/` | CLI, integration, workflow, evidence, and architectural contracts. |
| Documentation | `docs/` | Current usage, architecture, and verification ledger. |


## Compose and data safety

The root Compose file is the owner of the single PostgreSQL service. It keeps Dependency-Track and DefectDojo in separate databases and roles, retains named volumes, and adopts the existing backup and rollback volumes as external resources. Do not run `docker compose down -v`.

Start the existing services only with their existing `.env` and persistent volumes:

```sh
docker compose up -d
docker compose ps
```

Trivy Server is an internal Dependency-Track analyzer. The `trivy` service is an on-demand scanner profile, not a long-running UI or a replacement for the CLI.

## Configuration

Project configuration is optional `.barad.yml`; credentials are environment variables, never YAML. For local CLI use, Barad also reads the invocation workspace's `.env` without modifying the scanned target. See [CLI usage](docs/CLI.md) for the supported configuration and [architecture](docs/architecture/ARCHITECTURE.md) for publication invariants.

## Verification

```sh
PYTHONPATH=cli:. .venv/bin/python -m unittest discover -s tests -v
docker compose config --quiet
```

The verification ledger records checks actually performed and any remaining limits: [docs/architecture/AUDIT.md](docs/architecture/AUDIT.md).

## Out of scope

This repository does not implement a dashboard, custom API, MCP server, AI worker, Syft, or CycloneDX CLI.

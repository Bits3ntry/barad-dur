# BARAD-DÛR

Barad-dûr, Fortress of Sauron.

Self-hosted application-security POC in **one Docker Compose stack**. **Not production-ready**: loopback HTTP, no TLS, no SSO, no per-team authorization.

`One Eye to Scan Them All.`

## CLI v0.1 quick path

The installable `barad` CLI runs independently of Compose. Existing `barad_security` and the Compose services are preserved; the CLI reuses the scanner and HTTP contracts instead of replacing the legacy CI runner.

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/barad --help       # scan, run, health
.venv/bin/barad health       # read-only; optional remotes can be NOT CONFIGURED
.venv/bin/barad scan .       # real JSON + CycloneDX, local evidence only
.venv/bin/barad run .        # same scan; syncs only enabled integrations
```

Reports: `.barad/reports/<scan-id>/{security.json,sbom.cdx.json,manifest.json}`; the raw report can contain secrets and is owner-only. Settings live in optional `.barad.yml`, credentials in environment variables, never YAML or Git. `barad scan` does not require DT, Dojo or a Barad API. See [CLI usage and publication policy](docs/CLI.md), [architecture](docs/architecture/ARCHITECTURE.md) and [current audit/evidence](docs/architecture/AUDIT.md).

## What runs

| Service | Image | URL (loopback only) | Interface |
|---|---|---|---|
| `dt-apiserver` | `ghcr.io/dependencytrack/apiserver:5.2.1` | http://127.0.0.1:18080 | API |
| `dt-frontend` | `ghcr.io/dependencytrack/frontend:5.2.1` | http://127.0.0.1:18081 | **Web UI** |
| `dojo-nginx` | `defectdojo/defectdojo-nginx:3.4.202` | http://127.0.0.1:18082 | **Web UI** |
| `dt-postgres` | `postgres:18-alpine` | — | internal only |
| `trivy-server` | `aquasec/trivy:0.76.1` | `http://trivy-server:4954` (internal) | **API** for Dependency-Track |
| `dojo-postgres` | `postgres:18.6-alpine` | — | internal only |
| `dojo-valkey` | `valkey/valkey:9.1.2-alpine` | — | internal only |
| `dojo-uwsgi`, `dojo-celeryworker`, `dojo-celerybeat`, `dojo-initializer` | `defectdojo/defectdojo-django:3.4.202` | — | internal |

Scanners are **not** permanent services and have **no web UI**. They are profile-gated tools in the same stack:

| Tool | Image | Purpose |
|---|---|---|
| `trivy` | `aquasec/trivy:0.76.1` | vulnerabilities, misconfigurations, secrets |
| `syft` | `anchore/syft:v1.55.0` | SBOM generation |
| `cyclonedx` | `cyclonedx/cyclonedx-cli:0.33.1` | SBOM validation (no network) |

## Start

Requires Docker Compose, ≥8 GiB for the whole stack, and a `.env` with the secrets. **Never commit `.env`.**

```sh
docker compose config --quiet      # validates without starting
docker compose up -d               # core platform only
docker compose ps
```

If `.env` is missing, generate fresh secrets once (first boot only — an existing database needs its original values):

```sh
umask 077
cat > .env <<EOF
DT_DB_PASSWORD=$(python3 -c 'import secrets;print(secrets.token_hex(24))')
DD_DB_PASSWORD=$(python3 -c 'import secrets;print(secrets.token_hex(24))')
DD_SECRET_KEY=$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')
DD_CREDENTIAL_AES_256_KEY=$(python3 -c 'import secrets;print(secrets.token_hex(16))')
TRIVY_SERVER_TOKEN=$(python3 -c 'import secrets;print(secrets.token_urlsafe(32))')
EOF
```

`DD_CREDENTIAL_AES_256_KEY` encrypts stored credentials: changing it silently breaks access to them. Losing `DD_DB_PASSWORD` means losing the database. Keep all five values in a password manager.

## First login

- **Dependency-Track** (`:18081`): change the initial admin password immediately, then create a **dedicated API key** limited to BOM upload/project creation. Export it only in your shell as `DTRACK_API_KEY` for `barad` (`DT_API_KEY` belongs to older scripts).
- **DefectDojo** (`:18082`): local credentials are in `.secrets/defectdojo-admin.txt` (mode 600, gitignored). Change the password before any non-local use.

## Trivy as Dependency-Track's vulnerability analyzer

Dependency-Track 5.2.1 does not bundle Trivy: it uses **client/server mode** against an external server, and the integration is disabled by default. `trivy-server` therefore always runs, has no published port, and requires a token. Dependency-Track sends that token in the `Trivy-Token` header (verified inside `vuln-analyzer-trivy-5.2.1.jar`), which is Trivy's default `--token-header`.

Configure it in Dependency-Track under **Administration → Analyzers → Trivy**:

| Field | Value |
|---|---|
| Enabled | checked |
| API URL | `http://trivy-server:4954` |
| API Token | contents of `.secrets/trivy-server-token.txt` |
| Ignore Unfixed | `false` — `true` hides vulnerabilities that have no fix yet, which reads as "clean" when it is not |
| Scan Library | `true` — matches SBOM components by PURL, which is the point of using it with Dependency-Track |
| Scan OS | `true` only if your SBOMs list OS packages; otherwise it adds noise |

Verified: `GET /healthz` reachable from the Dependency-Track container; an unauthenticated request returns `401`; the token is accepted; and a scan **run through the server** (`trivy image --server … --token … alpine:3.19`) returned 10 vulnerabilities. Rotating `TRIVY_SERVER_TOKEN` requires recreating both the server and the Dependency-Track analyzer configuration.

## Scanners

```sh
# Historical POC tooling; validate availability before using these optional profiles.
docker compose --profile tools run --rm syft dir:/scan -o cyclonedx-json=/output/sbom.cdx.json
docker compose --profile tools run --rm cyclonedx validate \
  --input-file /output/sbom.cdx.json --input-format json --input-version v1_7 --fail-on-errors

# Vulnerabilities + misconfig + secrets over the repository (read-only mount)
sh scripts/scanners/trivy.sh fs . artifacts/trivy/repository

# Container image: immutable digest required, mutable tags refused
sh scripts/scanners/trivy.sh image 'registry.example.com/app@sha256:<64-hex>' artifacts/trivy/image
```

Results land in `artifacts/` (gitignored) as JSON, SARIF and CycloneDX. They are not evidence of safety: an unreachable advisory feed produces zero findings too. Never scan a tree containing real credential files.

## Historical SBOM import and catalog

The older `scripts/sbom/upload.py` references `catalog/schema`, which is missing in the current dirty working tree; the documented catalog validation command is unavailable. Do **not** use these historical commands without restoring their dependencies deliberately. For a working CLI-to-Dependency-Track workflow, configure `barad run` as described in [CLI.md](docs/CLI.md). Older procedures and their original validation assumptions remain in [feeding Dependency-Track](_docs/operations/dependency-track-feeding.md).

See [catalog and import](_docs/architecture/catalog.md). The real OVAC 8.7.2 SBOM is **not** in this repository; nothing is invented in its place.

## DefectDojo MCP server

A configurable MCP server lets an LLM client or BARAD-DÛR itself read and write DefectDojo over the REST API v2 (never the database). Read-only by default; write tools are not even registered until enabled.

```sh
.venv/bin/python -m pip install -r requirements-mcp.txt
export DEFECTDOJO_URL=http://127.0.0.1:18082
export DEFECTDOJO_API_TOKEN_FILE=$PWD/.secrets/mcp-token.txt
export DEFECTDOJO_ALLOW_WRITE=false        # true only for supervised data entry
.venv/bin/python -m defectdojo_mcp         # speaks JSON-RPC over stdio; Ctrl-C to stop
```

16 read tools by default (v2 stable + v3 nested reads), 23 with writes enabled. Configuration, tool catalogue, client wiring and verified integration notes: [DefectDojo MCP architecture](_docs/architecture/defectdojo-mcp.md).

## Operate

```sh
docker compose logs -f dt-apiserver        # or any service
docker compose stop                        # keeps data
docker compose down                        # removes containers + networks, keeps volumes
docker compose --profile tools run --rm …  # one-off scanner job
```

**Never run `docker compose down -v`** unless you intend to destroy the databases and have a verified backup. Volumes are adopted by explicit name, so `up` fails loudly instead of starting empty databases. Backup uses `pg_dump` per database plus the media volume; a restore drill is still pending.

## Current status

| Area | Observed state (this consolidation) |
|---|---|
| Docker Compose | `docker compose config --quiet` passed; ten core services were up locally. Named persistent volumes untouched. Not production-ready: loopback HTTP, no TLS/SSO. |
| CLI scan | `barad scan .` completed using Docker Trivy 0.76.1; JSON + CycloneDX and fingerprinted manifest saved privately. 64 CLI tests passed after the release-policy regression. |
| CLI run | A designated `barad-cli-poc-20261028` project/version was created in Dependency-Track; token completed and subsequent remote-export comparison skipped redundant upload. DefectDojo POC Product 7, Engagement 8, Test 8 imported and reimported findings; changed dependency produced two new findings while historical entries remained active. Initial async runs correctly returned partial. |
| CLI health | Standalone and configured DT/Dojo diagnostics returned HEALTHY without writing remote data. Missing optional services are NOT CONFIGURED. |
| Older runner, CI and MCP | Preserved; existing GitHub workflow still calls `barad_security`, not the new CLI. The old `tests/`, `examples/`, `docs/` trees are currently deleted in the pre-existing dirty working tree; `_docs/` holds historical POC documentation. |
| Limits | Real JAR/image scans and production deployment are unverified; fixture-only Trivy DB refresh failed on DNS, while the repository-root cache worked. No dashboard, AI worker or MCP replacement was built. |

See [current audit](docs/architecture/AUDIT.md) for exact commands, failures and classification. Historical evidence: [POC validation](_docs/operations/poc-validation.md), [ADR 0001](_docs/decisions/0001-local-poc.md).

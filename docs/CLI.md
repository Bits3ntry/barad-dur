# Barad CLI v0.1

`barad` scans locally without starting Compose. `run` adds optional publication; `health` never writes to remote services. Install with Python 3.10+ and Docker with the pinned Trivy image, or configure a local Trivy binary.

## Quick path

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/barad --help
.venv/bin/barad health
.venv/bin/barad scan .
.venv/bin/barad scan . --output ./reports
.venv/bin/barad run .
.venv/bin/python -m unittest discover -s cli/tests -v
```

Only three public subcommands exist: `scan`, `run`, `health`. The older `./bin/barad-security` entry point is legacy scaffolding for local hooks only; CI no longer calls it, and it is not the new CLI. The installable wheel includes `barad_security` and its schema. No Barad server is required.

## Target and evidence

| Target | Invocation | Boundary |
|---|---|---|
| Repository | `barad scan .` or `barad run /path/to/repo` | Trivy `fs`, JSON security report **and** CycloneDX on every run. |
| Java JAR | `barad scan path/to/app.jar` or `scan.target: lib/app.jar` in `.barad.yml` | Trivy `fs` against the file; no build script executed. Tested command construction, but real JAR analysis is unverified in this session. |
| Built image | `.barad.yml`: `scan.target_type: image`, `scan.target: registry/app@sha256:...`; then `barad scan` | Trivy `image`, remote image source; a Dockerfile is **not** an image scan. Use an immutable digest. |

Default evidence lives in `.barad/reports/<scan-id>/`: `security.json` (raw, private), `security.sanitized.json` (outbound), `sbom.cdx.json`, `manifest.json`, `execution.log`, `checksums.sha256`. `--output ./reports` changes only the reports root and must remain inside the scan root; state stays in `.barad/state/`. The default raw-evidence directory is owner-only (0700 on POSIX), files are tightened to 0600 where possible, and `.barad/` is ignored by Git. Treat raw reports as sensitive because secret matches can include credential material. Custom `--output` directories (such as `./reports`) are **not automatically Git-ignored**; add their path to `.gitignore` before using them. Never upload `security.json`; DefectDojo receives only the sanitized copy.

A failed Trivy process, malformed JSON or invalid/empty CycloneDX inventory is not a successful scan. Evidence produced before failure remains on disk. A report with zero findings is not a security assurance or proof of a fresh vulnerability database.

The manifest records project name, ecosystems, version source/value, Git commit/branch when available, target, timestamps, Trivy version, findings counts, scan status, artifact paths/SHA-256, normalized inventory fingerprint, local comparison, and optional sync status. The original SBOM SHA-256 is always separate from the inventory fingerprint.

## `.barad.yml` configuration

Optional in the project root; without it the CLI derives a name from the Git root or directory, version from `package.json`/`pyproject.toml`/tag, scans with Docker Trivy 0.76.1, and leaves integrations off. It never runs project scripts. For an isolated integration-test project:

```yaml
version: 1
project:
  name: my-test-project
  version:
    source: pyproject
scan:
  target_type: fs
  runner: docker
  scanners: [vuln, secret, misconfig]
output:
  directory: .barad/reports
integrations:
  dependency_track:
    enabled: true
    endpoint: http://127.0.0.1:18080
    auto_create: true
    wait_timeout_seconds: 30
  defectdojo:
    enabled: true
    endpoint: http://127.0.0.1:18082
    product_name: my-test-project
    product_type_name: CLI test
    engagement_name: my-test-project isolated
    auto_create_context: true
```

Supported `project.version.source`: `auto`, `package-json`, `pyproject`, `file`, `literal`, `env`, `git-tag` (same semantics as the existing runner). `scan.target` can select a relative subdirectory or JAR; `scan.target_type: image` selects an image reference. `scan.runner: local` uses an installed Trivy executable. Invalid keys, path escapes, direct secret fields and malformed types fail before scanning. The configured `output.directory` and CLI `--output` must stay inside the scan root and cannot overlap `.barad/state`.

Credentials are **environment variables**, never YAML values: `DTRACK_API_KEY`, `DOJO_TOKEN`; endpoints default to `DTRACK_URL`/`DOJO_URL` when set, overriding YAML `endpoint`. `BARAD_DEFAULT_BRANCH` defaults to `main`. The optional Barad API uses `BARAD_DUR_URL` and `BARAD_DUR_TOKEN` only when actually configured. The environment denied `.env.example`; the user chose documentation-only variable names, so no template file is delivered. Do not commit populated `.env` or `.secrets`.

## Inventory and publication policy

`scan` always produces both Trivy artifacts. Its fingerprint hashes sorted normalized component identities **and versions**, dependency edges (including canonicalized metadata root), and target/image identity. It ignores timestamps, serial numbers and tool-generation metadata; original SBOM byte SHA-256 is retained separately. `scan` compares only to a **local scanned** snapshot; this is never proof that Dependency-Track published it.

`run` uses the same scan engine. When Dependency-Track is enabled it resolves the exact project name + version, creates only if `auto_create: true`, exports the server's CycloneDX BOM, and compares the normalized graph. New version or changed/unverifiable remote inventory uploads; a remotely verified unchanged inventory skips upload. A processing token is recorded and polled up to `wait_timeout_seconds`; `PUBLISHED` requires token completion **and** a matching exported inventory. A pending token makes the run partial, and a repeated run checks that token before attempting another upload. No upload is triggered just because vulnerability intelligence changed. PRs and non-default branches are skipped for Dependency-Track; the local/default branch uses the detected application version, and release events require an explicit stable version. Do not set `BARAD_DEFAULT_BRANCH` to a feature branch except for a clearly named, isolated test project.

DefectDojo uses the supported `Trivy Scan` parser and Import/Reimport API. It selects a stable test title derived from product + version, resolves an existing test remotely, verifies its engagement belongs to the configured Product, then reimports to the same Test; otherwise it imports. It passes `close_old_findings=false`. A successful POST alone is insufficient: it checks the Test and Product relationship and reads the findings count. It does not auto-close old findings; historical findings can stay active after removal from a new scan. Test-level finding counts are not a full parser completeness proof; inspect the UI/API for important imports.

The isolated POC config is `cli/tests/fixtures/representative/.barad.yml`; never substitute a production Product/Engagement for that experiment. No cleanup deletes historical findings or project data.

## Health and exit codes

`barad health [--config .barad.yml]` checks CLI, Git, Trivy version, config, and **only configured** DT/Dojo/API endpoints via authenticated GET. It never creates projects/tests, uploads a BOM or imports a scan. Optional unconfigured services show `NOT CONFIGURED` and do not degrade a healthy standalone installation.

| Exit | Meaning |
|---|---|
| 0 | Scan completed; run completed or skipped optional integrations; health healthy. |
| 1 | Technical scan/tool failure or unavailable required local tool. |
| 2 | Invalid arguments or configuration; scanning did not start. |
| 4 | Partial synchronization or degraded optional health. Artifacts remain available. |

## CI adapter: `.github/workflows/security.yml`

`.github/workflows/security.yml` now installs this wheel (`pip install .`) and calls `barad` directly. It keeps two jobs and two trust boundaries.

| Job | Trigger | Command | Credentials |
|---|---|---|---|
| `scan` | every trigger, including pull requests and forks | `barad scan . --config <config-file>` | none; `barad scan` does not read integrations |
| `publish` | release event, or the repository default branch only | `barad run . --config <config-file>` | `DTRACK_URL`, `DTRACK_API_KEY`, `DOJO_URL`, `DOJO_TOKEN`, inside the publish step only |

Both jobs read `config/ci.barad.yml`, which enables Dependency-Track and DefectDojo while holding no credential and no endpoint: the environment supplies both. The workflow passes the repository root positionally (`barad run . --config config/ci.barad.yml`) because a config file under `config/` would otherwise be taken as the project root and scan only that directory.

`barad run` **rescans** inside the publish job; it does not resume the scan job's artifacts. The publish job therefore has its own evidence, and neither job uploads the raw `security.json` because secret matches can contain credential material. Artifacts keep `manifest.json`, `security.sanitized.json`, `sbom.cdx.json` and `checksums.sha256` per job, plus `publication.json` for publish.

When any publish credential is absent, the publish step prints a GitHub notice naming the missing variables and exits 0 without invoking `barad`: a missing optional service is visible and skips only publication. A publication that does run and fails fails the job — there is no `|| true`. Because both integrations are enabled, the gate requires all four variables; a deployment that publishes to only one service must supply placeholder values for the other, or override `config-file` and the gate together.

Reusable-workflow changes (`workflow_call` is preserved):

| Input or secret | Change |
|---|---|
| `config-file` | Default changed to `config/ci.barad.yml`. |
| `python-version` | Unchanged. |
| `trivy-runner` | Removed; `scan.runner` in the configuration file selects Docker or a local Trivy. |
| `BARAD_DUR_URL`, `BARAD_DUR_TOKEN` | Removed; the CLI has no Barad API synchronizer, so declaring them promised publication that never ran. |
| `DTRACK_URL`, `DTRACK_API_KEY`, `DOJO_URL`, `DOJO_TOKEN` | Kept, all optional. |

Local verification of this workflow is structural and behavioral only (`python -m unittest discover -s cli/tests -p test_ci_workflow.py`); GitHub-hosted execution was not available here, so a green hosted run is still unproven. No dashboard, AI worker, MCP replacement or new server API was implemented. The Compose stack remains a loopback-only POC without TLS/SSO, and the local-only fixture scan could not refresh its vulnerability DB because `mirror.gcr.io` DNS timed out; a repository-root scan with a warm cache was validated instead.

# Barad CLI v0.1

`barad` is installable from the repository and exposes exactly three commands. It uses Trivy for SBOM, secrets, and misconfiguration evidence plus OpenGrep for SAST; it does not require a dashboard, API, MCP server, Syft, or CycloneDX CLI.

## Quick path

```sh
python3 -m venv /tmp/barad-venv
/tmp/barad-venv/bin/python -m pip install .
/tmp/barad-venv/bin/barad health
/tmp/barad-venv/bin/barad scan /path/to/project     # evidence in ./.barad/reports
/tmp/barad-venv/bin/barad scan /path/to/project -O /tmp/evidence
/tmp/barad-venv/bin/barad run /path/to/project
```

| Command | Result | Remote effects |
|---|---|---|
| `barad scan [path]` | Creates Trivy `security.json` and `sbom.cdx.json`, OpenGrep `sast.json`, and `manifest.json` in `.barad/reports/<scan-id>/` inside the invocation directory. Use `--out DIR` / `-O DIR` to choose the directory. | None. |
| `barad run [path]` | Performs the same scan and synchronizes configured adapters. Same `--out`/`-O` handling. | The CI profile creates or updates only the configured Dependency-Track SBOM. |
| `barad health` | Checks local tools, configuration, and configured endpoints. | Authenticated GET requests only. |

`security.json` can contain matched secrets and `sast.json` can contain source excerpts. Both remain owner-only, are not Git evidence, and are never sent to a remote integration. The manifest contains only OpenGrep counts and version metadata.

Evidence is anchored to the directory where you invoke `barad` (the workspace), not to the scanned target: scanning another project never writes into that project. Reports live in `<workspace>/.barad/reports/<project>/<version>/<scan-id>/` (or inside the `--out` directory with the same layout), state in `<workspace>/.barad/state/`, and the Trivy cache in `<workspace>/.barad-dur/cache/trivy/`.

Scan ids embed a UTC timestamp plus a random suffix, so re-scanning the same project+version simply adds another `<scan-id>/` folder next to the previous one. No scan evidence is ever replaced or deleted by a later run.

## Configuration

`.barad.yml` is optional. Without it, the CLI derives project identity, scans the supplied filesystem target with Docker Trivy and Barad's managed OpenGrep engine, writes `.barad/reports`, and leaves integrations disabled. On first SAST use, the CLI downloads only the host's exact OpenGrep asset from its packaged version/hash lockfile into a per-user cache, verifies the SHA-256, and then re-verifies it on every use. OpenGrep uses Barad's checked-in baseline rules unless `sast.rules` names a repository-relative replacement.

```yaml
version: 1
project:
  name: isolated-test-project
  version:
    source: pyproject
scan:
  target_type: fs
  runner: docker
  scanners: [secret, misconfig]
sast:
  # rules: security/opengrep.yml  # Optional repository-relative replacement.
output:
  directory: .barad/reports
integrations:
  dependency_track:
    enabled: true
    endpoint: http://127.0.0.1:18080
    auto_create: true
```

Credentials for the CI publication profile are `DTRACK_URL` and `DTRACK_API_KEY`. Endpoint environment variables override YAML endpoints. Tokens and secret values are rejected in `.barad.yml`.

For the local CLI, `barad` automatically reads `<workspace>/.env` before it resolves a command. Explicit shell environment variables win over `.env`; `.env` values are never printed or written to evidence. The parser accepts only plain `KEY=VALUE` assignments (optional surrounding quotes and comments), deliberately without shell expansion or command substitution.

### Local external repositories

Keep local profiles in this Barad workspace and pass them explicitly; do not add `.barad.yml` or any Barad state to the repository being scanned. `config/local/councilbox-server.barad.yml` is the ready-to-use profile for Councilbox Server. Append the non-secret defaults from `config/local/barad.env.example` to this workspace's `.env`, then fill in only `DTRACK_API_KEY`. Existing local DefectDojo profile settings are legacy opt-in and are not used by the GitHub Action.

```sh
barad health --config config/local/councilbox-server.barad.yml
barad run /absolute/path/to/councilbox-server \
  --config config/local/councilbox-server.barad.yml
```

When invoked from the Barad workspace, reports and sync state remain under its `.barad/` directory. The external target is read-only. This profile is local CLI configuration; it does not configure the GitHub Action.

The Councilbox Server profile enables `dependency_track.publish_branches`. A local non-default branch is published as a separate, deterministic version such as `21.7.7-branch-feature-security-hardening-<hash>`; the branch slug plus hash prevents it from overwriting the stable `21.7.7` inventory. Pull-request events remain blocked from Dependency-Track publication.

## Publication invariants

Dependency-Track uses the exact project name and version. It creates a missing project/version only when `auto_create: true`, compares the exported remote CycloneDX inventory, and requires processing completion plus a matching export before reporting `PUBLISHED`. A local inventory snapshot is never remote-publication proof.

## GitHub Actions

The repository workflow uses the same CLI. The CLI EngineManager downloads and verifies the same checksum-pinned OpenGrep binary used locally; the credential-free scan job runs `barad scan`, while the trusted publish job runs `barad run` and exposes only Dependency-Track credentials in that step. OpenGrep reports remain local evidence and are never sent to DefectDojo. The reusable composite action is available at `action/action.yml`:

```yaml
- uses: actions/checkout@v4
- uses: ./action
  with:
    command: scan # scan, run, or health
    target: .
    config: config/ci.barad.yml
```

For `run`, provide the integration environment variables only in a trusted workflow step or job. `barad health` reports the pinned OpenGrep engine version and cache integrity without downloading it. GitHub-hosted execution requires a real hosted run; local structural tests do not prove it.

## Tests

```sh
PYTHONPATH=cli:. .venv/bin/python -m unittest discover -s tests -v
```

The representative isolated configuration is `tests/fixtures/representative/.barad.yml`. Never use a production Dependency-Track project for operational verification.

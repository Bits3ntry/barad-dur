# Barad CLI v0.1

`barad` is installable from the repository and exposes exactly three commands. It uses Trivy directly; it does not require a dashboard, API, MCP server, Syft, or CycloneDX CLI.

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
| `barad scan [path]` | Creates `security.json`, `sbom.cdx.json`, and `manifest.json` in `.barad/reports/<scan-id>/` inside the invocation directory. Use `--out DIR` / `-O DIR` to choose the directory. | None. |
| `barad run [path]` | Performs the same scan and synchronizes configured adapters. Same `--out`/`-O` handling. | Creates or updates only the configured Dependency-Track/DefectDojo records. |
| `barad health` | Checks local tools, configuration, and configured endpoints. | Authenticated GET requests only. |

`security.json` can contain matched secrets. It remains owner-only, is not Git evidence, and is never sent to DefectDojo. The sanitized report is the only Trivy report the DefectDojo adapter imports.

Evidence is anchored to the directory where you invoke `barad` (the workspace), not to the scanned target: scanning another project never writes into that project. It writes reports to `workspace/.barad/reports/<scan-id>/`, state to `workspace/.barad/state/`, and the Trivy cache to `workspace/.barad-dur/cache/trivy/`. `--out`/`-O` overrides the reports directory only; state stays in the workspace unless you point `--out` inside the workspace tree.

## Configuration

`.barad.yml` is optional. Without it, the CLI derives project identity, scans the supplied filesystem target with Docker Trivy, writes `.barad/reports`, and leaves integrations disabled.

```yaml
version: 1
project:
  name: isolated-test-project
  version:
    source: pyproject
scan:
  target_type: fs
  runner: docker
output:
  directory: .barad/reports
integrations:
  dependency_track:
    enabled: true
    endpoint: http://127.0.0.1:18080
    auto_create: true
  defectdojo:
    enabled: true
    endpoint: http://127.0.0.1:18082
    product_name: isolated-test-project
    product_type_name: Barad CLI test
    engagement_name: isolated-test-project isolated
    auto_create_context: true
```

Credentials are environment variables: `DTRACK_URL`, `DTRACK_API_KEY`, `DOJO_URL`, and `DOJO_TOKEN`. Endpoint environment variables override YAML endpoints. Tokens and secret values are rejected in `.barad.yml`.

## Publication invariants

Dependency-Track uses the exact project name and version. It creates a missing project/version only when `auto_create: true`, compares the exported remote CycloneDX inventory, and requires processing completion plus a matching export before reporting `PUBLISHED`. A local inventory snapshot is never remote-publication proof.

DefectDojo imports the sanitized report through its `Trivy Scan` parser. It resolves the stable test title, verifies its Product ownership before reimporting, and always sends `close_old_findings=false`. The adapter treats parser visibility and observed findings as verification, not merely a successful POST.

## GitHub Actions

The repository workflow uses the same CLI. Its credential-free scan job runs `barad scan`; its trusted publish job runs `barad run` and exposes credentials only in that step. The reusable composite action is available at `action/action.yml`:

```yaml
- uses: actions/checkout@v4
- uses: ./action
  with:
    command: scan # scan, run, or health
    target: .
    config: config/ci.barad.yml
```

For `run`, provide the integration environment variables only in a trusted workflow step or job. GitHub-hosted execution requires a real hosted run; local structural tests do not prove it.

## Tests

```sh
PYTHONPATH=cli:. .venv/bin/python -m unittest discover -s tests -v
```

The representative isolated configuration is `tests/fixtures/representative/.barad.yml`. Never use a production Dependency-Track project or DefectDojo engagement for operational verification.

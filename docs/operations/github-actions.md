# Security runner — GitHub Actions

The workflow is a thin shell around the same CLI. Nothing about Trivy, change
detection, the SBOM rule, evidence or publication is reimplemented in YAML.

## Structure

```text
.github/workflows/security.yml
├── scan     (no secrets) checkout · setup-python · run CLI · upload evidence
└── publish  (trusted contexts only) download evidence · barad-security sync --pending
```

Two jobs, on purpose:

1. **scan** runs with an empty secret environment. A pull request from a fork, or
   any code that runs in that job, therefore cannot read a token. It produces the
   evidence contract and uploads `.barad-dur/security` as an artifact.
2. **publish** is skipped for `pull_request` events whose head repository is a
   fork, and for `pull_request_target` callers whose head repository is a fork. It downloads the same evidence and runs `sync --pending`, which reuses
   the finished run instead of scanning again. Credentials exist only here.

The evidence artifact also carries `state/inventory.json` and
`state/publications.json`, so the publish job keeps release idempotency across
workflow runs.

## Triggers

| Event | `--event` | Notes |
|---|---|---|
| `pull_request` | `pr` | `fetch-depth: 0` so the merge base and every commit of the branch are visible |
| `push` to `main`/`master` | `push` | development inventory only if `update_development_project: true` |
| `release: published` | `release` | SBOM is mandatory; Dependency-Track gets the versioned project |
| `workflow_dispatch` | `dispatch` | manual re-run |

## Reusing it from another repository

```yaml
jobs:
  security:
    uses: councilbox/barad-dur/.github/workflows/security.yml@main
    with:
      config-file: barad-security.yml
      trivy-runner: docker
    secrets:
      DTRACK_URL: ${{ secrets.DTRACK_URL }}
      DTRACK_API_KEY: ${{ secrets.DTRACK_API_KEY }}
      DOJO_URL: ${{ secrets.DOJO_URL }}
      DOJO_TOKEN: ${{ secrets.DOJO_TOKEN }}
      BARAD_DUR_URL: ${{ secrets.BARAD_DUR_URL }}
      BARAD_DUR_TOKEN: ${{ secrets.BARAD_DUR_TOKEN }}
```

Declared `workflow_call` inputs: `config-file`, `trivy-runner`, `python-version`.

Caller responsibility: do not forward secrets to a caller-side job that runs
untrusted code. This workflow keeps the scan job secret-free, but a caller that
injects secrets into its own steps is outside its control. On `pull_request_target`,
remember that `actions/checkout` defaults to the **base** branch; set the ref
explicitly if the pull-request tree must be scanned (it is scanned without secrets
either way).
Unused secrets may be omitted; an adapter that is enabled but has no endpoint
records `PENDING` / `not_configured` instead of failing the analysis.

## Trivy in Actions

`trivy-runner: docker` uses the pinned image `aquasec/trivy:0.76.1` that is
already required by `compose.yaml`; no third-party action and no floating version
is involved. `trivy-runner: local` expects Trivy on `PATH` (install it in a step
before the run step in that case).

## Self-hosted runner

This project's Dependency-Track and DefectDojo are loopback-only, reachable only
from this host. If a workflow must publish to them, it has to run on a
self-hosted runner on this machine; GitHub-hosted runners cannot reach
`127.0.0.1:18080`. Nothing in the workflow assumes either; only the endpoint and
token secrets change.

## Validating the wiring locally with `act`

```sh
sh examples/act/run.sh
```

`examples/act/run.sh` calls `act pull_request` with
`examples/act/pull_request.json` and `--container-architecture` mapped from the
host. Scope: it proves that the workflow receives the repository, sets up Python,
passes the event and preserves artifacts. It does **not** prove GitHub-hosted
infrastructure, secrets injection or fork semantics.

Status on this host: **not executed** — `act` is not installed. The payload,
invocation and required image are provided so the check is one command away.

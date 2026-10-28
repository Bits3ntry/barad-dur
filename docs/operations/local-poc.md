# Security runner — local POC

The runner is one Python process. It needs a Git repository, a `barad-security.yml`
configuration and Trivy (a local binary or the pinned container image). It needs
no service, no database and no network service of our own: BARAD-DÛR,
Dependency-Track and DefectDojo are optional adapters.

Why Python: the repository already ships a Python toolchain (`.venv`,
`requirements.txt`, `unittest`, `PyYAML`, `jsonschema`) and every existing
operator command is a Python script. The runner reuses that environment and the
same `urllib` conventions (no proxy, no redirects) instead of adding a Node
toolchain next to it for a single CLI.

## 1. Prerequisites

```sh
.venv/bin/python -m pip install -r requirements.txt   # PyYAML + jsonschema
docker image inspect aquasec/trivy:0.76.1 >/dev/null   # default engine (container)
# optional: trivy --version                           # only for trivy.runner: local
```

`trivy.runner` chooses how Trivy is invoked:

| Value | Meaning | When |
|---|---|---|
| `docker` (**default**) | `aquasec/trivy:<pinned tag>`, target mounted read-only, evidence dir writable | always; it is also what CI runs |
| `local` | the `trivy` binary from `PATH` or `trivy.executable` | a host or runner that already ships the binary |

The default is the container on purpose: the local CLI and GitHub Actions execute
the **same Trivy build**, so a difference in results cannot come from a different
scanner installation. What changes between environments is the mode, never the
engine. You can override it without editing the file, because the example
configuration reads `${BARAD_TRIVY_RUNNER:-docker}`:

```sh
BARAD_TRIVY_RUNNER=local ./bin/barad-security run --event local   # host binary
```

## 2. Where the configuration lives

`barad-security.yml` belongs to the repository that is **scanned**, never to the
runner: the runner is one program that reads a different file per project. This
repository therefore has its own `barad-security.yml` at its root (service
`barad-dur-security-runner`), so you can exercise the workflow on the tool itself:

```sh
./bin/barad-security run --event pr --base-ref main     # scans this repository
```

Scanning another project means pointing `--repository` at *its* root, which must
contain its own configuration:

```sh
./bin/barad-security run --repository /path/to/ovac-backend --event push
```

If the directory has no configuration, the CLI says exactly which example file to
copy. In a monorepo you can also keep the configuration inside the service folder
and pass that folder as `--repository`; the manifest records
`git.repository_offset` and change attribution stays Git-root relative, so a
sibling service is never blamed.

`trivy.exclude_paths` keeps tooling out of the inventory (`.venv`, `node_modules`,
generated evidence). Paths are relative to the scan target.

## 3. Two commands

```sh
./bin/barad-security validate-config --repository examples/node
./bin/barad-security run --event local --repository examples/node
```

`validate-config` never scans: it validates structure, semantics and path
containment, then prints the effective project, Trivy settings, SBOM source and
evidence directory. Environment expansion is limited: `${VAR}` works for switches
such as `${BARAD_TRIVY_RUNNER:-docker}`, but expanding an integration endpoint or any
`*_TOKEN` / `*_SECRET` / `*_API_KEY` variable is refused, because a repository file
must never be able to pull a runtime credential into evidence.

A run prints a short summary and writes the evidence contract described in
[the artifact contract](../architecture/artifact-contract.md):

```
run local-20261028T100000Z-ab12cd: completed
  evidence: /path/to/repo/.barad-dur/security/runs/local-20261028T100000Z-ab12cd
  trivy: SUCCESS (vulns=6 secrets=0 misconfigs=0)
  sbom: SUCCESS
  dependency_track: SKIPPED (not_a_release)
```

`--json` prints the whole manifest instead, which is what CI consumes.

## 4. The five acceptance scenarios, by hand

Use `examples/node` as the demonstration repository (it is a real Git-tracked
project with a Node manifest, a lockfile and a Dockerfile). Copy it to a scratch
directory first so the POC leaves the repository clean:

```sh
demo=$(mktemp -d)/ovac-backend
cp -R examples/node "$demo"
cd "$demo" && git init -q && git add -A && git commit -qm "initial"
```

Run everything with `--repository "$demo"` from the repository that contains the
runner, or install the runner on `PATH` there.

### Scenario 1 — code change runs Trivy, skips the SBOM

```sh
../bin/barad-security run --event push --base-ref HEAD   # first run: builds the inventory
echo 'export const health = () => ({ ok: true });' > src/index.ts
git commit -qam "code only"
../bin/barad-security run --event push --base-ref HEAD^
```

Expected: `steps.trivy.status = SUCCESS`, no `steps.sbom`, and
`decisions.sbom_reason = "no_inventory_change"`. The manifest states why the
inventory was not regenerated. The first run did generate it, because
`initial_inventory_missing` was true — that is the documented conservative case,
not an inconsistency.

### Scenario 2 — dependency change regenerates the SBOM

```sh
# edit package-lock.json: axe 1.6.0 -> 1.7.0 (or any dependency bump)
git commit -qam "bump axios"
../bin/barad-security run --event pr --base-ref HEAD^
```

Expected: `changes.dependency_changed = true`, `decisions.sbom_reason =
"dependency_changed"`, both `trivy-report.json` and `sbom.cdx.json` in the new run
directory, linked to `git.commit_sha` in the manifest.

### Scenario 3 — a release publishes inventory to Dependency-Track

```sh
export DTRACK_URL=http://127.0.0.1:18080
read -rs DTRACK_API_KEY && export DTRACK_API_KEY
# barad-security.yml: integrations.dependency_track.enabled: true
../bin/barad-security run --event release --version 8.9.0
```

Expected: project `OVAC-Backend` version `8.9.0` is looked up, created when
`auto_create` is on, and the SBOM is uploaded. A second run of the same release
does not upload twice. A release whose SBOM differs from the one already recorded
for that version is classified (`identical_reimport`, `inventory_correction`,
`distinct_rebuild`) and **not** overwritten unless `allow_release_overwrite` is
true.

### Scenario 4 — BARAD-DÛR down: evidence preserved, sync later

```sh
export BARAD_DUR_URL=http://127.0.0.1:9      # nothing listens there
read -rs BARAD_DUR_TOKEN && export BARAD_DUR_TOKEN
../bin/barad-security run --event release --version 8.9.0   # exit code 0
```

Expected: `steps.barad_dur.status = PENDING`, reason `unreachable`, exit code 0,
the analysis intact, and a queue entry in `.barad-dur/security/pending/<run-id>.json`.
When the platform is back:

```sh
export BARAD_DUR_URL=http://127.0.0.1:8080
./bin/barad-security sync --run-id <run-id>   # or: sync --pending
```

`sync` republishes from the preserved evidence. It does **not** rescan.

## 5. Git hooks

```sh
cp examples/hooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

Husky variant: `examples/hooks/husky-pre-commit` → `.husky/pre-commit`.

The hook calls the same CLI. It never blocks a commit on findings; a technical
failure is reported and only blocks when `BARAD_SECURITY_BLOCK_ON_ERROR=1`, so a
broken scanner cannot stop ordinary work without an explicit decision.

## 6. Exit codes

| Code | Meaning |
|---|---|
| 0 | run completed; findings allowed; every required step succeeded |
| 1 | technical failure (Trivy, SBOM, required publication) |
| 2 | usage or configuration error; nothing was scanned |
| 3 | the configured findings gate tripped (`execution.fail_on_findings: true`) |

A finding is never a technical failure, and `0 findings` is never presented as
"clean": `security.scan_successful` reflects Trivy's exit code and the parsed
report, not the absence of findings.

## 7. Verified on this host / not verified

Verified by the test suite and by hand on 2026-10-28 (macOS arm64, Python 3.13.7,
Trivy 0.76.1 via Docker, Dependency-Track 5.2.1 and DefectDojo 3.4.202 available
locally):

- real Trivy scan through the pinned container: JSON report parsed, CycloneDX 1.7
  inventory generated, validated and recorded; code-only change skipped the SBOM;
- change detection for code, lockfile, version declaration, Dockerfile, release,
  monorepo scoping and PR-with-many-commits;
- Deferred publication: run with an unreachable BARAD-DÛR, then `sync` against a
  local HTTP double;
- credential-expansion refusal, option-shaped base reference rejection and the
  `pull_request_target` fork gate, each with its own regression test;
- Dependency-Track and DefectDojo request shapes against HTTP doubles, including
  duplicate suppression and release-history protection.

Not verified (no credentials or no running instance with an API key):

- real Dependency-Track upload and real DefectDojo import — no API key exists in
  this project, and both are adapters exercised only against mocks;
- the real BARAD-DÛR endpoints, which do not exist yet (the contract is
  [proposed](../architecture/artifact-contract.md#barad-dûr-publication-contract));
- `act` execution of the workflow (the `act` binary is not installed here);
  the payload and invocation are provided in `examples/act/`.

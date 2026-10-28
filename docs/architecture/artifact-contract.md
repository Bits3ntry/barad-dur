# Evidence and artifact contract

One run, one directory, one manifest. The contract is versioned
(`schema_version: "1.0"`) and is what BARAD-DÛR will consume later. It is produced
identically by the local CLI, a Git hook, `act` and GitHub Actions.

## Layout

```text
.barad-dur/security/
├── runs/<run-id>/
│   ├── manifest.json                structured result, always written
│   ├── decisions.json               why each step ran or was skipped
│   ├── trivy-report.json            Trivy JSON report (always)
│   ├── trivy-report.sanitized.json  outbound copy with secret matches redacted
│   ├── sbom.cdx.json                CycloneDX inventory (conditional)
│   ├── execution.log                JSON Lines log
│   ├── publication.json             publication outcome per integration
│   └── checksums.sha256             SHA-256 of every evidentiary file
├── state/
│   ├── inventory.json               last known inventory per service + version
│   └── publications.json            idempotency ledger
└── pending/<run-id>.json            evidence waiting to be published later
```

`git.repository_offset` is the path from the Git top level to the configured
repository root (`""` at the root, `services/api` for a service-level
configuration); diff paths in `changes.files_changed` are always Git-root
relative.

`run-id` is `<source>-<UTC yyyymmddThhmmssZ>-<6 hex>`, e.g.
`local-20261028T100000Z-ab12cd`. `source` is `local`, `github` or `act`. A caller
may pin it with `--run-id` (CI does not), and `sync` never creates a new one.

Files are written with a temporary file plus `os.replace`, so an interrupted run
never leaves a truncated manifest or ledger.

## manifest.json

```json
{
  "schema_version": "1.0",
  "run_id": "local-20261028T100000Z-ab12cd",
  "source": "local",
  "event": "pr",
  "project": "OVAC",
  "service": "OVAC-Backend",
  "application_version": "8.9.0",
  "repository": "ovac-backend",
  "git": {
    "event": "pr", "branch": "feature/update-axios",
    "commit_sha": "abc123…", "base_sha": "def456…", "head_sha": "abc123…",
    "base_ref": "main", "base_resolution": "merge_base_of_explicit_base_ref",
    "repository_offset": "", "pull_request": "12", "tag": null
  },
  "timestamps": {"started_at": "2026-10-28T10:00:00Z", "finished_at": "2026-10-28T10:01:30Z"},
  "changes": {
    "base_available": true, "dependency_changed": true, "version_changed": false,
    "build_context_changed": false, "code_changed": false,
    "files_changed": ["package-lock.json"], "files_ignored": 0,
    "previous_version": "8.8.0", "current_version": "8.9.0",
    "version_comparison": "compared", "problems": []
  },
  "decisions": {
    "run_trivy": true, "generate_sbom": true, "sbom_reason": "dependency_changed",
    "triggers": {"dependency_changed": true, "application_version_changed": false,
                  "build_context_changed": false, "release_event": false,
                  "initial_inventory_missing": false, "base_reference_unavailable": false},
    "publications": {"dependency_track": {"action": "skip", "reason": "pull_request_is_temporary"}},
    "reasons": [{"code": "dependency_changed", "detail": "dependency inventory changed: package-lock.json"}]
  },
  "steps": {
    "trivy": {"status": "SUCCESS", "duration_ms": 45000, "artifact": "trivy-report.json",
               "version": "0.76.1", "target": ".", "parameters": {}, "counts": {}},
    "sbom": {"status": "SUCCESS", "duration_ms": 12000, "artifact": "sbom.cdx.json",
              "validation": {"ok": true, "summary": {}, "warnings": []}},
    "dependency_track": {"status": "SKIPPED", "reason": "pull_request_is_temporary",
                          "required": false, "external_ids": {}, "attempts": []},
    "barad_dur": {"status": "PENDING", "reason": "unreachable", "detail": {"deferred": true}}
  },
  "security": {"scan_successful": true, "findings_detected": true, "counts": {},
                "trivy_version": "0.76.1", "scan_type": "fs", "target": ".",
                "outbound_redaction": {"redacted_fields": 0}},
  "publications": {"_state": {"published_any": true, "failed": false, "deferred": false,
                                "required_failed": false}},
  "artifacts": {"trivy-report.json": {"sha256": "…", "size_bytes": 1234}},
  "environment": {"runner": "local", "ci": false, "python": "3.13.7", "platform": "Darwin",
                   "trivy_runner": "docker", "trivy_image": "aquasec/trivy:0.76.1"},
  "config": {"fingerprint": "…", "source": "barad-security.yml", "effective": {}},
  "problems": [],
  "tool": {"name": "barad-security", "version": "1.0.0"}
}
```

Written unconditionally, including when Trivy fails or a publication does not
complete: that is the point of the contract.

## Step states

`PENDING`, `RUNNING`, `SUCCESS`, `FAILED`, `SKIPPED`, plus `DUPLICATE` for a
publication already recorded in the ledger. `result.status` is one of
`completed`, `partial` (a publication did not finish) or `failed` (technical
failure). A security result **with vulnerabilities can still be `completed`**.

## decisions.json

The same `decisions` object, standalone, so a reviewer can read *why* nothing was
generated without parsing the whole manifest. Every trigger carries a `code` and
a human `detail`; suppressed triggers appear as `<trigger>_suppressed` with the
configuration key that suppressed them.

Reasons produced by the engine: `base_reference_unavailable`, `release_event`,
`dependency_changed`, `application_version_changed`, `build_context_changed`,
`initial_inventory_missing`, `no_inventory_change`, `sbom_disabled`.

## publication.json

Per integration: `status`, `reason`, `required`, `external_ids`, `attempts`
(HTTP attempt trace: attempt number, status, duration), `detail`, `message`.
`attempts` is the retry trace the contract requires. A `PENDING` or `FAILED`
publication also queues `.barad-dur/security/pending/<run-id>.json`.

## checksums.sha256

`<sha256>  <filename>` per line, compatible with `sha256sum -c`, over every file
present at the end of the run (the manifest included). Verify with:

```sh
cd .barad-dur/security/runs/<run-id> && sha256sum -c checksums.sha256
```

## Inventory index and ledger

`state/inventory.json`:

```json
{"services": {"OVAC-Backend": {"8.9.0": {
  "sbom_sha256": "…", "component_fingerprint": "…", "components": 42,
  "run_id": "…", "recorded_at": "…"}}}, "updated_at": "…"}
```

It answers `initial_inventory_missing` and protects release history: a new SBOM for
an already-recorded version is classified, never silently overwritten.

`state/publications.json` is the idempotency ledger, keyed by
`<service>:<service-name>:<target>:<version>:<artifact-sha256-16>`. Repeating a run
that already published identical evidence returns `DUPLICATE` and sends no
request.

## Retention flags

| Setting | Effect |
|---|---|
| `artifacts.preserve_reports: false` | reports are deleted **after** a fully resolved run; kept when anything is pending |
| `artifacts.preserve_logs: false` | `execution.log` is deleted at the end |
| `artifacts.create_manifest: false` | `manifest.json` is not written (checksums and decisions still are) |

`trivy.exclude_paths` is recorded in `steps.trivy.parameters.exclude_paths` and
passed to Trivy as `--skip-dirs` for each entry, relative to the scan target.

## Secret handling

`trivy-report.json` is the analyst's evidence and keeps everything, because it
stays on the runner/host. Every outbound copy (`trivy-report.sanitized.json`,
Dependency-Track SBOM, DefectDojo import, BARAD-DÛR artifacts) redacts only
`Secrets[].Match`, `Secrets[].Code`, `Secrets[].Layer` and `Secrets[].Content`.
Vulnerability and misconfiguration findings keep full fidelity: redaction can
never hide a finding. Logs are scrubbed of every configured token/env value and of
`Authorization` / `X-Api-Key` header values before they are written.

`barad-security.yml` may use `${VAR}` / `${VAR:-default}` for non-sensitive
switches (a runner mode, a base reference, an enable flag). Expanding a variable
that the configuration declares as an integration endpoint, or any variable whose
name ends in `token`, `secret`, `password` or `api_key`, is **refused** with a
clear configuration error: a repository file must never be able to copy a runtime
secret into a manifest, an outbound payload or a log line. Credentials are read by
the adapters at run time and never appear in `config.effective`.

## BARAD-DÛR publication contract

Proposed, not implemented on the platform side. The adapter calls exactly:

```text
POST /api/v1/security-runs                     Authorization: Bearer <token>
                                               Idempotency-Key: <run-id>
POST /api/v1/security-runs/{id}/artifacts      multipart: name, sha256, run_id, artifact
POST /api/v1/security-runs/{id}/complete       {status, run_id, artifacts, checksums, result}
```

Client-side guarantees: idempotency key on create and per artifact, SHA-256 sent
with every artifact, artifacts skipped when the ledger already recorded the same
digest, transport/5xx deferred as `PENDING` with the queue entry kept, and 4xx
reported as `FAILED` with a bounded body snippet and no credential.

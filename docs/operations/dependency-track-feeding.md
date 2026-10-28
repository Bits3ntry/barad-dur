# Feeding Dependency-Track (local, before any CI exists)

How the portfolio gets an inventory today: by hand, from this host, over loopback.
CI/CD reuses the same command later — see [Wiring CI later](#wiring-ci-later); nothing
here has to be rewritten for it.

Scope warning: everything below proves **source or image inventory**, never what is
deployed in production. A repository SBOM labelled as a deployed artifact is a false
claim, not evidence.

## 1. Prerequisites — what only a human can do once

Dependency-Track 5.x changed the key model: **API keys belong to a Team**, not to a
user. Skipping the team step is the usual cause of a `403` on the first subida.

1. Open http://127.0.0.1:18081 and change the initial admin password. The first-boot
   password is printed only in `dt-apiserver` logs of that boot
   (`docker compose logs dt-apiserver | grep -i password`). Never paste it in chat.
2. **Administration → Access Management → Teams → Create Team**, e.g. `ci-metering`.
3. Add a user to that team. A team without members cannot own a usable key.
4. Grant the minimum permissions on that team:

   | Permission | Why |
   |---|---|
   | `BOM_UPLOAD` | `PUT /api/v1/bom` |
   | `PROJECT_CREATION_UPLOAD` | `autoCreate` when the project does not exist yet |
   | `VIEW_PORTFOLIO` | read back projects, metrics and findings |
   | `VULNERABILITY_ANALYSIS` | only if a human will triage/annotate; not needed to feed |

5. **API Keys → Create Key** on that team. The value is shown once.
6. **Assign the portfolio to the team**: the team's *Projects* tab, either "access all
   projects" or the explicit projects. Without assignment the upload succeeds and every
   read returns `403`.
7. Export the key only in the shell that runs the upload, and keep a copy in your
   password manager:

   ```sh
   read -rs DT_API_KEY && export DT_API_KEY   # no history, no arguments
   ```

   One key per pipeline/environment, rotatable, revocable. It must never appear in Git,
   in `compose.yaml`, in process arguments or in logs.

## 2. Produce the SBOM

Source inventory (what the repository vendors) — never label it as deployed:

```sh
docker compose --profile tools run --rm syft dir:/scan -o cyclonedx-json=/output/repo.cdx.json
```

Image inventory (what a release actually ships) — immutable digest only:

```sh
docker compose --profile tools run --rm syft \
  registry:registry.example.com/app@sha256:<64-hex> -o cyclonedx-json=/output/image.cdx.json
```

Validate before touching Dependency-Track:

```sh
docker compose --profile tools run --rm cyclonedx validate \
  --input-file /output/image.cdx.json --input-format json --input-version v1_7 --fail-on-errors
```

The CLI repeats the same schema check locally, so an invalid SBOM cannot mutate
portfolio state.

## 3. Upload and wait for the analysis

```sh
.venv/bin/python scripts/sbom/upload.py \
  --file artifacts/image.cdx.json \
  --project-name councilbox_ovac --project-version 8.7.2 \
  --wait --wait-timeout 600
```

Identity rules the CLI enforces before the request: `projectName` is the stable service
(`councilbox_ovac`), `projectVersion` is an immutable release. `latest`, blank values and
leading/trailing whitespace are rejected; `--api-url` must stay loopback
(`http://127.0.0.1:<port>`).

Exit contract:

| Code | stdout | Meaning |
|---|---|---|
| `0` | `upload accepted: <token>` (+ `analysis complete: <token>` with `--wait`) | accepted, and with `--wait` also analysed |
| `1` | — | invalid SBOM or identity, HTTP error, or `--wait` timed out (`analysis incomplete: no completion within <n>s`) |
| `1` | — | `DT_API_KEY` unset: `DT_API_KEY is required; …` |

Without `--wait` the returned token only confirms **queue acceptance**. Analysis is
asynchronous, so "exit 0" alone is not "there are no vulnerabilities" — it is "the file
was queued". That is the whole reason `--wait` exists.

Re-submitting the same `(name, version)` is idempotent: it replaces that version's
inventory and re-analyses it. It does not create a second project.

## 4. Verify the result by reading, not by believing exit codes

```sh
curl -s -H "X-Api-Key: $DT_API_KEY" \
  "http://127.0.0.1:18080/api/v1/project/lookup?name=councilbox_ovac&version=8.7.2"
curl -s -H "X-Api-Key: $DT_API_KEY" \
  "http://127.0.0.1:18080/api/v1/project/<uuid>" | head -c 400
curl -s -H "X-Api-Key: $DT_API_KEY" \
  "http://127.0.0.1:18080/api/v1/finding/project/<uuid>" | head -c 400
```

What to look at: `components` > 0 (the inventory landed), `metrics.critical` /
`metrics.high`, and the `finding/project` list. A project with zero components and zero
findings means the SBOM was empty or unparsed, not that the software is clean.

Cross-check the global feed is alive, otherwise "zero findings" is meaningless:

```sh
docker compose exec dt-postgres psql -U dtrack -d dtrack -c \
  "select count(*) from \"VULNERABILITY\";"
```

## 5. Wiring CI later

No new endpoint and no new script: the pipeline runs exactly the four steps above.

- **Runner placement**: `dt-apiserver` publishes only on `127.0.0.1:18080`. A
  cloud-hosted runner cannot reach it. The chosen path for this POC is a **self-hosted
  runner on this host**, so nothing new is exposed. Any alternative (LAN binding, tunnel,
  TLS publication) is a separate decision that must go through an ADR.
- **Trigger**: a release or an immutable tag, one SBOM per `(service, version)`. Not
  every commit: inventory changes with the release, not with the commit.
- **Do not re-upload for new CVEs.** Dependency-Track re-analyses the portfolio when its
  advisory mirror updates. Uploading more often does not add vulnerability knowledge; it
  only burns runner time.
- **Gating**: upload is asynchronous, so a build cannot fail on findings at upload time.
  Gate later by reading `finding/project/<uuid>` after `--wait` and filtering by severity
  yourself — Community Edition has no policy engine (`/api/v1/violation` is a Pro
  feature). The key needs `VIEW_PORTFOLIO` for that read.
- **Secrets**: the key goes into the CI secret store per pipeline, injected as
  `DT_API_KEY`, never on a command line.

## 6. Known limitations

- Loopback HTTP only: no TLS, no SSO, no per-team authorization beyond the team model.
- One advisory source mirrored (NVD). GitHub Advisories / OSV require their own tokens
  and are not configured; a CVE that exists only in GHSA is invisible here.
- No scheduled scans, no notifications/webhooks, no CI pipeline: all three are still
  "implemented nowhere".
- No gate: nothing blocks a build or a deploy on findings.
- Manual key rotation; no audit trail of who uploaded what.
- SBOMs above the CLI's 20 MiB cap need Dependency-Track's multipart upload variant and a
  raised request limit on the API server; verify against your version's API documentation
  before raising the limit.

# Local POC evidence log

This log separates **implemented**, **observed**, **pending**, **blocked**, and **known limitations**. Never treat proposed examples as security findings or live integration evidence.

## Phase 0 — diagnosis

Observed: repository initially had `README.md` only (plus empty `.atl/`); `git status --short --branch` clean on `master`. Host arm64, Docker Engine/CLI 29.8.2, Compose v5.5.0, OrbStack Linux VM with 8 GiB; other project's Dependency-Track containers own 127.0.0.1:8080/8081. No Trivy or Syft CLI on host. Disk had ample free space. Read official dependencytrack.org Compose and DefectDojo CE installation; see ADR 0001.

## Phase 1 — Dependency-Track

Implemented: isolated `compose.yaml`, separate volumes/network, operator-supplied database password, local-only HTTP, upstream images 5.2.1. `DT_DB_PASSWORD=validation-placeholder docker compose config --quiet` exited 0 (structural check; placeholder was **never used to launch** the service). Runtime observed: `docker compose up -d` exit 0; `dt-db` and `dt-api` healthy, GET `http://127.0.0.1:18080/api/version` HTTP 200 with application version `5.2.1`. First frontend attempt returned connection refused: OrbStack did not publish a host port for a container attached only to an `internal: true` network, despite HostConfig.PortBindings. Fixed declaratively by attaching `dt-web` to both networks and recreating only that container; GET `/` on 127.0.0.1:18081 returned HTTP 200. Subsequent check: Compose config exit 0, API HTTP 200, frontend HTTP 200, database/API healthy; frontend health was still `starting` immediately after recreation. Restart check: own DT database/API/frontend and Dojo database/Valkey/app/workers/nginx containers were restarted without `down -v`; GETs returned HTTP 200/200/302, respectively. DT database retained 105 public tables and Dojo retained 208 public tables before/after. This demonstrates schema/volume continuity, **not** persistence of user-created findings or SBOMs. UI sign-in, project creation, SBOM upload, feed analysis and application-data persistence: **pending observation**. Do not infer these from successful config parsing.

## Subsequent phases

Catalog: `catalog/examples/fictional.yaml` validation exit 0 and 7 black-box CLI/config tests pass (3 catalog, 2 importer, 2 local services). Independent read-only verifier ran 6/6 before two identity regression checks were added; it found the whitespace-split DT project identity and `latest` release acceptance. Both defects had focused RED failures then GREEN. Final check: `.venv/bin/python -m unittest discover -s tests -v` exit 0 (7/7); fictional catalog exit 0; both Compose configs exit 0 with placeholder env values; `git diff --check` exit 0. CycloneDX 1.6/1.7 official schemas are vendored; Trivy-generated repository SBOM version 1.7 validated against the matching schema. Real OVAC 8.7.2 SBOM is **not** in the repository: import and DT project/query are blocked on its actual file and a dedicated API key. Mock HTTP uploads in CLI tests prove request structure, not live DT ingestion.

Trivy: `docker run --rm aquasec/trivy:0.76.1 --version` returned `Version: 0.76.1` on ARM64 (pinned image pulled, digest `sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c`). `sh scripts/scanners/trivy.sh fs . artifacts/trivy/repository` exited 0 and wrote `scan.json` (1517 B), `scan.sarif` (589 B), `sbom.cdx.json` (2297 B), all ignored by Git. Scan JSON contains one pip result with `PyYAML 6.0.3` and `jsonschema 4.25.1` PURLs and no reported vulnerabilities, misconfigurations or secrets **in this scan**; not proof of overall safety. Trivy warned that it could not find Python `site-packages` for license detection; those licenses are not verified by this scan. Generated SBOM is source inventory, not deployed artifact.

DefectDojo CE: `docker manifest inspect` confirmed linux/arm64 variants for Django/nginx 3.4.202; `docker compose -f infrastructure/defectdojo/compose.yaml config --quiet` exited 0 with operator-generated secrets and exited 1 without them (that path was later consolidated into the root stack — see the consolidation section). `up -d --no-build` exited 0, initializer completed, postgres/valkey healthy, nginx bound only to 127.0.0.1:18082; GET `/` returned HTTP 302 to login while uwsgi, worker and beat ran. Authenticated local session using the initializer-generated admin password (never printed or stored in Git); a first POST with the pre-login CSRF token failed HTTP 403 without mutation, then the rotated post-login cookie enabled API writes. `POST /api/v2/product_types/`, `/products/`, `/engagements/` and `/tests/` each returned HTTP 201 and created IDs 2/1/1/1 respectively. Every object is named **BARAD-DUR POC SYNTHETIC** and explicitly says no assessment occurred. There is **no finding, auditor evidence, import, closure or retest**; those must not be inferred. No password, finding or scan report was copied into Git. After restarting Dojo database/Valkey/app/workers/nginx, an authenticated GET of `/api/v2/products/`, `/engagements/`, `/tests/` still returned the synthetic IDs 1/1/1: **Dojo application-data persistence demonstrated for those records only**. Authenticated real finding workflow, issue/PR linkage, deployed releases and backup restore: **pending**. A 302 alone was not treated as proof of this API behavior.

No simulated CVE or pentest report is evidence.

## Re-validation — second pass (2026-10-26)

Full re-run on request, read-only except the Trivy job writing to ignored `artifacts/`. Nothing was deleted or reconfigured.

| Check | Result |
|---|---|
| `git diff --check` / tree state | exit 0; same 1 modified + 8 untracked paths as before; no file removed |
| `.venv/bin/python -m unittest discover -s tests -v` | **7/7 OK**, exit 0 (re-ran, not cached) |
| `catalog/validate.py catalog/examples/fictional.yaml` | `valid catalog`, exit 0 |
| DT Compose config (dummy password) | exit 0; **without** `DT_DB_PASSWORD` exit 1 |
| Dojo Compose config (dummy secrets) | exit 0; **without** the three secrets exit 1 |
| Containers | DT db/api/web healthy (38 min up); Dojo postgres/valkey/nginx healthy, uwsgi/worker/beat up; initializer `Exited (0)` |
| `GET :18080/api/version` | HTTP 200, `{"application":"Dependency-Track","version":"5.2.1"}` |
| `GET :18081/` | HTTP 200 |
| `GET :18082/` → `/login` | HTTP 302; `/login` HTTP 200 |
| Off-loopback reachability | LAN `11.11.11.209` ports 18080/18081/18082 all refused (`000`); bindings remain `127.0.0.1:*`. A first attempt produced a misleading 302 because the LAN address resolved empty; the corrected test is the one recorded |
| Schema integrity | `bom-1.6` `3e92dd…fb93`, `bom-1.7` `df472e…4221` — unchanged |
| Trivy repeat scan (`artifacts/trivy/revalidate`) | exit 0; `sbom.cdx.json` specVersion 1.7, 3 components, schema-valid; `scan.json` 0 findings; `scan.sarif` 0 — identical to first run, so the scan is reproducible on this tree |

Dependency-Track advisory mirror is populated in the local database: `VULNERABILITY`=414,161 (all `SOURCE`=NVD), `VULNERABLESOFTWARE`=497,666, `EPSS`=395,308, max `UPDATED`=2026-10-26 11:16:39Z, newest advisories published that same day. This is genuine feed evidence. It is **not** vulnerability analysis of our software: `PROJECT`=0 and `COMPONENT`=0, confirming no SBOM has been imported and the 414k rows are DT's global advisory database, not per-project findings.

DefectDojo authenticated read-only re-check: `product_types` total 2 (synthetic `2`), `products` total 1 (synthetic `1`), `engagements` total 1 (synthetic `1`), `tests` total 1 (synthetic `1`), `findings` **total 0**. Records persisted again across restarts, and still no finding exists.

Unchanged blockers: real OVAC 8.7.2 SBOM and a dedicated limited DT API key (case A), a genuine auditor report plus supervised finding lifecycle (cases D–F), and a restore drill.

## Acceptance cases A–H

| Case | Honest POC result |
|---|---|
| A — OVAC inventory in Dependency-Track | Blocked: real SBOM and limited API key absent |
| B — compare two service releases | Implemented catalog shape; no real two-release evidence |
| C — verifiable advisory affects component | Advisory feed mirrored and verified (414,161 NVD rows, current to 2026-10-26); still pending because no project/component exists to match against |
| D — pentest scoped finding | Synthetic Product/Engagement/Test created through authenticated CE API; finding and genuine report pending |
| E — issue/PR remediation link | Mechanism documented; no authenticated live link |
| F — shared-component impact | Shared-service relationship demonstrated in explicitly fictional YAML; real component impact pending |
| G — persistence | Both schemas survived restart (105/208 tables); synthetic Dojo Product/Engagement/Test IDs 1/1/1 survived a second Dojo restart; DT SBOM persistence remains untested |
| H — reproduce from clean host | Install/start instructions implemented; no separate clean-host execution |

## Known limitations and next step

HTTP only on loopback; no SSO, product/team RBAC, managed secrets, TLS, audited restore or hardened Azure setup. Compose images plus HTTP readiness are not end-to-end acceptance. Dojo ARM64 image integration tests are not upstream-certified. No real image/system/scheduled scan, CI or Github/Slack/SAURON integration. Credentials generated for local runtime must be privately retained; losing them prevents reliable recreation. Git-versioning is not met until the user explicitly authorizes a commit; the files are untracked. Next step: provide the actual OVAC 8.7.2 SBOM path and provision a dedicated DT API key through the local UI, then perform the authenticated import/project query and a supervised Dojo test finding/retest. Do not supply passwords in chat.

## Consolidation into a single stack (2026-10-26)

The earlier two-project layout (`barad-dur` + `barad-dur-dojo`) was merged into one project, `barad-dur`, in the root `compose.yaml`. Reason: a single published stack to operate by hand, and the subdirectory project silently ignored the root `.env`, so any `docker compose` call there failed on missing secrets.

What changed:
- `infrastructure/defectdojo/compose.yaml` removed; its 7 services now live in the root file as `dojo-*`, renamed to avoid collision with Dependency-Track.
- Networks collapse to `edge` (published UIs + egress), `dt-internal` and `dojo-internal`, both `internal: true`.
- All 6 pre-existing volumes are adopted **by explicit name**, so consolidation cannot silently start empty databases.
- Trivy, Syft and CycloneDX CLI added as `profiles: [tools]` services with pinned tags: `aquasec/trivy:0.76.1`, `anchore/syft:v1.55.0`, `cyclonedx/cyclonedx-cli:0.33.1`. All three have linux/arm64 manifests (`docker manifest inspect`). They have no UI; `docker compose up -d` does not start them.
- `cyclonedx` runs with `network_mode: none`.
- Secrets preserved by extracting them from the running containers into a gitignored `.env` (mode 600) instead of regenerating them. Values were never printed.

Verified after consolidation:
- `docker compose config --quiet` exit 0; `canonical project name = barad-dur`; default `up` starts 10 services, `--profile tools` adds the 3 scanners.
- Endpoints: `:18080/api/version` 200 (`5.2.1`), `:18081` 200, `:18082` 302 → `/login`.
- Data preserved: DT `VULNERABILITY`=414,161 and `VULNERABLESOFTWARE`=497,666 (the NVD mirror survived, no re-download), DT `PROJECT`=0 and `COMPONENT`=0 (still no SBOM). Dojo `dojo_product`=1, `dojo_engagement`=1, `dojo_test`=1, `dojo_finding`=0, `dojo_product_type`=2.
- Scanners executed for real inside the stack: Trivy `Version: 0.76.1`, Syft `Version: 1.55.0`, CycloneDX `0.33.1`. Syft generated a 42,009-byte CycloneDX SBOM from the repository and `cyclonedx validate --input-version v1_7 --fail-on-errors` reported `BOM validated successfully` (exit 0).
- Test suite rewritten to assert the new contract (single project, every secret required, only the three UIs publish and only on `127.0.0.1`, scanners opt-in). First run was RED (1 failure: the removed subdirectory file); after the rewrite **10/10 pass**.

Incident found and fixed during consolidation: the DefectDojo admin password existed only in the previous initializer container's logs, which were deleted with that container. It was reset deliberately through `manage.py shell` with the new value piped on stdin (never in shell history or process arguments) and stored in `.secrets/defectdojo-admin.txt`, mode 600, gitignored. `DD_ADMIN_PASSWORD` was added to `.env` so a future fresh initialization reuses it; it does not retroactively apply to an existing database.

Still absent: any UI for Trivy/Syft/CycloneDX, the custom BARAD-DÛR application, correlation of projects/releases/deployments/merges, SAURON, Slack, dashboards, CI/CD wiring and Azure hardening.

## Re-observation — Dependency-Track feeding prerequisites (2026-10-26)

Read-only inspection before wiring any upload, so the status table stops claiming `PROJECT=0`.

Observed in the live `dt-postgres`: `PROJECT`=3 — `OVAC` (no version), `OVAC-Backend` 8.8, `OVAC-Frontend` 8.8 — all with `LAST_BOM_IMPORTED` null and `COMPONENT`=0 across the whole portfolio; `TEAM`=3 (Dependency-Track's own defaults) and **`APIKEY`=0**. So the UI side was started by hand, but no upload credential exists yet: every non-interactive feed attempt would fail with `DT_API_KEY is required`.

Consequence for identity: the upload CLI's `--project-name`/`--project-version` must match those existing names exactly (`OVAC-Backend` / `8.8`), otherwise `autoCreate` produces parallel duplicate projects instead of filling the ones already in the portfolio.

Negative-path check, no mutation: `env -u DT_API_KEY .venv/bin/python scripts/sbom/upload.py --file artifacts/trivy/revalidate/sbom.cdx.json --project-name smoke_no_key --project-version 9.9.9 --wait --wait-timeout 5` exited 1 with `DT_API_KEY is required; create a limited BOM_UPLOAD key in Dependency-Track`. `PROJECT` stayed 3 afterwards, confirming the key check runs before any state-changing request.

Not claimed: any SBOM ingestion, analysis, finding or feed correlation. `COMPONENT`=0 and null `LAST_BOM_IMPORTED` mean "never analysed", not "clean".

## Jira COUNCILBOX import (2026-10-26)

Source: a Jira HTML export the operator placed at `/Users/saf/Downloads/COUNCILBOX.html` (read explicitly by user instruction; 1.9 MB, 108 issues, project `Cybersecurity`, 158 columns).

Parsed with a new stdlib-only parser (`scripts/importer/jira_export.py`); no `bs4`, `lxml` or `pandas` was installed, and none was added.

### Classification rules from the operator

| Asset | Rule |
|---|---|
| Shutter | tag `SHT-*`, or a `*shutter*` host |
| REU | tag `REU-*`, `*.pre.councilbox.com`, or epic scope "Reuniones" (operator: REU = Reuniones) |
| OVAC | tag `OVAC`, `ovac` in a host, or epic scope OVAC |
| CBX | tag-only `CBX-*`, or a shared generic `councilbox.com` host (corporate WordPress/VPN) |
| GISS | explicit operator assignment for the INSS/TGSS audit scope |

Explicit operator overrides: `CY-88`, `CY-89`, `CY-83` → OVAC; `CY-61` → CBX; `CY-81`, `CY-82`, `CY-30`, `CY-32`, `CY-43` → GISS.

A shared host (`api.councilbox.com`) does **not** decide the asset: epic scope wins, otherwise the nine `#REUNIONES v11.4.2` subtasks would have been misfiled under CBX.

### Result

| Product | Findings | Severity mix |
|---|---|---|
| OVAC | 45 | Medium 30, Info 6, Low 5, Critical 2, High 2 |
| REU | 20 | Medium 9, Critical 5, Info 3, High 3 |
| Shutter | 15 | Medium 7, Info 5, High 2, Low 1 |
| CBX | 13 | Medium 9, Info 3, Critical 1 |
| GISS | 5 | Medium 5 |
| **Total imported** | **98** | plus 1 earlier synthetic smoke finding = 99 |

10 issues were excluded as non-findings (epic containers, meeting notes, procurement, housekeeping): CY-14, CY-58, CY-59, CY-60, CY-68, CY-80, CY-85, CY-86, CY-93, CY-95.

Containers created: products for REU (4), CBX (5), GISS (6) under product type `CBX`; OVAC (2) and Shutter (3) already existed. One engagement `Import Jira COUNCILBOX` and one test per product, test type `Pen Test`.

Honest data limits: **36 of 98** findings carry an *inferred* severity (the Jira `Severity` column is empty for all 108 rows; the value was read from the summary text and the finding description says so). Only **2 of 108** issues contained a CVE; `CY-44` kept `CVE-2012-2292` in `vuln_id_from_tool`. No CVE was invented for the other 96. 90 issues were `Cerrada` in Jira and were imported with `active=false`; nothing was marked `verified` because no retest evidence exists.

### Incident: duplicate findings, and the fix

The first `--apply` created 98 findings. A re-run to check idempotency created **67 more** instead of skipping: the importer compared titles exactly, while DefectDojo rewrites them (titlecase and whitespace collapse), so `"... de seguridad incorrecta"` on disk became `"... De Seguridad Incorrecta"` and never matched.

Fix: `title_key()` normalises with casefold + whitespace collapse on both sides, and the set is updated after each creation. The 67 duplicates were then removed by `scripts/importer/dedupe_findings.py`, which keeps the lowest id per group inside a test; dry run listed all 67 first, `deleted=67 failed=0`. Post-cleanup: 99 findings, 0 duplicate titles.

Re-running the importer afterwards reported `created=0 skipped=98 failed=0`, so the import is now idempotent.

Second defect found by the same work: the package was first named `scripts/import/`, which cannot be imported because `import` is a Python keyword (`from scripts.import.x import y` is a syntax error). Renamed to `scripts/importer/`.

### Verified through the MCP

`list_assets` shows 6 assets (synthetic, OVAC, Shutter, REU, CBX, GISS) and `list_products`/`list_findings` confirm the per-product counts above. `list_findings_with_context` (v3) resolves test, engagement and asset inline for the imported findings. 41 automated tests pass.

## Lifecycle replication (2026-10-26)

OVAC was the only asset with a declared lifecycle. Read from the API rather than assumed: `product.lifecycle = 'production'` and `asset.lifecycle = 'production'` (the models agree). The value was copied from OVAC at run time — not hard-coded — and refused if OVAC's two surfaces disagreed.

Applied to Shutter (3), REU (4), CBX (5) and GISS (6) on **both** models, because DefectDojo stores lifecycle twice: `PATCH /api/v2/products/{id}/` and `PATCH /api/v3/assets/{id}`. The synthetic product/asset was deliberately left alone.

Verification (product vs asset, per name):

| Asset | product (v2) | asset (v3) | coherent |
|---|---|---|---|
| BARAD-DUR POC SYNTHETIC | None | None | yes |
| CBX | production | production | yes |
| GISS | production | production | yes |
| OVAC | production | production | yes |
| REU | production | production | yes |
| Shutter | production | production | yes |

Required a new capability: there was no way to update a product, so `update_product` was added to the client (field allowlist, write gate) and exposed as an MCP tool. Tool surface is now 16 read / 24 with writes; 41 tests pass.

Note: lifecycle is a declarative label, not evidence. Declaring GISS `production` says where the assessed system runs, not that its five findings were fixed.

Still open in this area: deduplication policy (`enable_deduplication` is still `false`) and the finding-state policy for retest evidence.

## Deduplication investigation (2026-10-26)

`enable_deduplication` was switched on through the Django ORM, because `/api/v2/system_settings/` is **read-only** (`Allow: GET, HEAD, OPTIONS`) and does not expose the dedup fields. `delete_duplicates` was deliberately left `false`: automatic deletion of real findings is not something to enable without an explicit decision.

State before and after enabling: 99 findings, 0 duplicates, 14 active — unchanged. A batch run (`manage.py dedupe --dedupe_sync`) computed all 99 hashes (0 null) and reported 0 duplicates.

### It had no effect, and the reason is structural

1. **`POST /api/v2/findings/` never schedules deduplication.** `dojo/finding/services.py:create_finding` dispatches only `async_create_notification`. Deduplication is triggered by the importer path and by the `manage.py dedupe` batch command. The worker log confirms which tasks actually run: 150 × `update_watson_search_index_for_model`, 132 × `async_create_notification`, 58 × `async_dupe_delete` — no dedupe task.
2. **Every Test uses `deduplication_algorithm='legacy'` with `hash_code_fields=None`.** `get_matches_from_legacy_candidates` only yields a candidate when `(flag_locations or flag_line_path) and flag_hash`. With no locations and no `file_path` on a dynamic finding, both flags stay `False`, so the condition can never hold.
3. **Proof by experiment:** two findings with an *identical* `hash_code` (`f3e486e3cd70e4f93564589473da0a72223b905798498617e5b920597989b7ff`) were created and were **not** flagged `duplicate` — neither by the API path nor after a synchronous batch dedupe. Both probes were deleted afterwards; the synthetic test is back to 1 finding.

### What would actually make it work

Switch each Test to `deduplication_algorithm='hash_code'` and give it `hash_code_fields`. `are_locations_duplicates()` returns `True` when both findings have no locations, so location-less findings can be deduplicated — unlike the legacy algorithm.

Two constraints found:

- These fields live on the **Test** model, not on `Test_Type` (`Test_Type` only has `static_tool`, `dynamic_tool`, `active`, `dynamically_generated`). So it is per-test configuration, 7 tests today.
- `HASHCODE_ALLOWS_NULL_CWE` has **no entry for "Pen Test"**, and `compute_hash_code` falls back to the legacy algorithm whenever `cwe == 0`. **90 of 99 findings have `cwe = 0`**, so hash-based dedup would still skip them unless null CWE is permitted for the parser or CWE data is populated.

Conclusion: enabling the switch is a prerequisite, not a fix. The import remains safe regardless — it is idempotent by canonical title, verified with `created=0 skipped=98`.

Open decision (not taken unilaterally, because it redefines what counts as a duplicate in real data): which fields define a duplicate, and whether a null CWE may satisfy it.

## Enriched findings (2026-10-26)

The first import used `"<Jira key> - <summary>"` as the title. Rewritten to a readable vulnerability title and enriched in place with PATCH (ids, notes and history preserved), not by deleting and recreating.

New scheme, applied to all 98 findings:

```
CY-44 - CBX-Q324-8 [MEDIUM] - Permissive Cross-Domain Policy with Untrusted Domains
  -> Permissive Cross-Domain Policy with Untrusted Domains (CVE-2012-2292)
CY-69 - CY-68 [FORENSIC&SECURITY] - VULN-01 - Unauthenticated Local File Inclusion [CRITICO - 10.0]
  -> Unauthenticated Local File Inclusion
```

Implementation: `scripts/importer/finding_enrichment.py` (title normalisation, vulnerability-class detection, labelled-block parsing) and `scripts/importer/update_findings.py` (in-place update). 17 tests in `tests/test_finding_enrichment.py`.

### What the export actually contains

| Field | Rows with content |
|---|---|
| `Workaround`, `Root cause`, `Test plan`, `Implementation plan`, `Comentarios`, `Last Comment`, `Entorno`, `Environment`, `Acceptance Criteria` | **0** |
| `Impact` | 33 |
| `Descripción` | 102 (256,733 chars) |
| `Resolución` | 108 |

So **steps to reproduce and notes have no source data** and were left empty with an explicit line in the body saying they are absent from the export. Nothing was invented.

Final coverage over the 98 findings: `references` 98/98 (Jira URL), `impact` 80/98, `cwe` 74/98, `mitigation` 73/98. Impact and mitigation come from the auditor where available (`Impacto`/`Recomendaciones` inside the description, or the `Impact` column) and are otherwise **derived from the vulnerability class and labelled as derived in the finding body**.

### Two defects found by verification, both fixed

1. **Derived context was wrong because the description classified the finding.** The first pass searched `summary + description`; long OWASP reference lists matched stray keywords, so "Exposure of Administrative Routes" received `CWE-434` (unrestricted file upload) and a file-upload impact/mitigation. Fixed to classify from the **title only** and to leave the fields empty when the title says nothing. Coverage dropped (93→80 impact) and became correct.
2. **The updater only added fields, never cleared them.** After fixing the classifier, the previously written wrong values would have survived. Fixed to write empty/`0` when the target has no value; verified `CY-35`, `CY-45` and `CY-94` now carry `cwe=0` and empty impact.

Also corrected: DefectDojo re-cases titles (`CY-25` is stored as `Cy-25`), so key matching from the title prefix failed for 7 findings — matching now reads the key from the `references` URL, and title comparisons are canonical to avoid rewriting the same title every run.

### Residual data-quality issue

7 of the 98 are administrative tasks rather than vulnerabilities and are currently stored as findings: `CY-61` (attack-vector analysis), `CY-64` to `CY-67` (IT-SEC inventory: form design, mass mailing, reminders, gap report), `CY-15` (Event Hub to SIEM connection) and `CY-91` (plan to hide client URLs in the VPN). They were classified as findings because they are tasks with a security topic, not because they describe a vulnerability. Removing them is a decision for the operator; no deletion was performed.

Idempotency re-checked after all rewrites: `created=0 skipped=98 failed=0`.

## Hosts, locations and endpoints (2026-10-26)

DefectDojo has two parallel models for "where":

| Model | Fields | Scope |
|---|---|---|
| v3 `locations` | `protocol`, `host`, `port`, `path`, `query`, `fragment`, `type`, `tags` | asset |
| v2 `endpoints` | `host`, `path` | product |

Findings reference locations/endpoints through a relation that **parsers populate at import time**. The public write API does not expose attaching one to an existing finding: `GET/POST /api/v3/findings/{id}/locations` only offers `get`, and `FindingCreateRequest` has no endpoints field. Verified additionally that `dojo_endpoint` is empty, so nothing has created endpoints so far.

The generic parser used for bulk imports does **not** create locations either (`grep unsaved_endpoints` → 0 matches), although ~190 other parsers do (ZAP, Trivy, Burp, Nuclei, SARIF…). Building a scanner-format report just to smuggle host strings would be a hack.

Measured over the 91 surviving findings: **59 mention an attributable host**, 32 do not. Most cited: `api.shutter.pre.councilbox.com` (13), `api.councilbox.com` (11), `councilbox.com` (10), `app.pre.councilbox.com` (10), `api.ovac.dev.councilbox.com` (5). One host is misspelled in the source (`api.ovac.dev.counxilbox.com`, 4 findings) — a naive import would create a separate location for the typo, which is an argument for normalising hosts before storing them.

Consequences: findings imported through `POST /api/v2/findings/` cannot gain locations afterwards, so legacy deduplication (which requires shared locations) also stays inert for them. Host tracking is therefore better placed in the BARAD-DÛR catalog, which is already the declared source of truth for product/service/release/deployment, with Dojo holding findings.

No locations or endpoints were created: this needs an operator decision on which model to populate and how to normalise hosts.

## Trivy as a permanent analyzer (2026-10-26)

Dependency-Track 5.2.1 needs an **external** Trivy server in client/server mode; the integration is disabled by default. The token header was not guessed: `vuln-analyzer-trivy-5.2.1.jar` (from the running apiserver image) contains `TOKEN_HEADER` = `Trivy-Token`, which matches Trivy's own `--token-header` default, so the two agree without extra flags.

Added an always-on `trivy-server` service (not under the `tools` profile): `trivy server --listen 0.0.0.0:4954 --token …`, own cache volume `barad-dur-trivy-server-cache`, healthcheck on `/healthz`, `mem_limit: 1g`, `restart: unless-stopped`, and **no published port** — only containers on `edge` (Dependency-Track) can reach it.

Verified:

| Check | Result |
|---|---|
| Container health | `healthy`; DB downloaded from `mirror.gcr.io/aquasec/trivy-db:2` |
| Reachability from the Dependency-Track container | `wget http://trivy-server:4954/healthz` → `ok` |
| Unauthenticated request | `HTTP/1.1 401 Unauthorized` |
| Request carrying `Trivy-Token` | no 401 (auth accepted; a 404 simply meant the guessed twirp path was wrong) |
| Scan **through the server** | `trivy image --server http://trivy-server:4954 --token … alpine:3.19` → 10 vulnerabilities |

Two self-inflicted errors worth recording: the Trivy image has **no shell**, so `docker run … sh -c` fails with `unknown command "sh"`; and passing `-e TT=…` sets the variable *inside* the container, so `--token "$TT"` expanded to an empty string on the host and produced a misleading `invalid token`. The correct form is `--token "$TRIVY_SERVER_TOKEN"` evaluated on the host.

The `trivy` CLI service (profile `tools`) is kept for ad-hoc scans and uses a separate cache, so a one-off scan cannot corrupt the server's database.

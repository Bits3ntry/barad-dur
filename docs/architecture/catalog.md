# Catalog v1 and SBOM evidence

Validate a Git-versioned YAML document (no database/UI yet):

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python catalog/validate.py catalog/examples/fictional.yaml
.venv/bin/python -m unittest discover -s tests -v
```

The example is **fictional**, not a claim about OVAC. `catalog/schema/catalog.schema.json` is the JSON Schema. Stable IDs identify products and services. A product explicitly lists service IDs that it consumes; merely registering a service or a relationship does not imply usage. Services can belong to several products without duplication. Relationships specify origin, destination, kind, optional environment, required/optional, criticality and evidence. A release is service-local and keyed by version with a 40-character commit SHA (and image digest when available); a deployment references a recorded release and records environment/time/infrastructure. `sboms` carry source/image/deployed-artifact origin, path and SHA-256. Record *actual* historical knowledge of CVEs in Dependency-Track, not as fabricated catalog flags. Neither a commit tag nor `latest` is accepted as sole release identity. The example's empty releases/deployments mean **unknown/not recorded**, not safe/unused.

## Import an existing OVAC SBOM

The actual `councilbox_ovac@8.7.2` SBOM is **not** present here. Obtain its original CycloneDX 1.6 JSON from your build artifact store (do not commit confidential inventory or invent one), then provide its path explicitly. Do not label a source-tree SBOM as a deployed image. Verify file hash and provenance independently. In Dependency-Track, change the first-login admin password and create a dedicated key with BOM upload/project creation permission. Use a trusted shell to export `DT_API_KEY` without storing it in Git:

```sh
.venv/bin/python scripts/sbom/upload.py \
  --file /path/to/actual/councilbox_ovac-8.7.2.cdx.json \
  --project-name councilbox_ovac --project-version 8.7.2
```

The CLI first checks the **vendored official CycloneDX 1.6 or 1.7 schema** selected by the file's exact version (Trivy v0.76.1 emits 1.7), refuses unsupported versions, oversize files, non-loopback API URLs and redirects, rejects project names/versions with leading or trailing whitespace and mutable `latest` versions, then submits to DT's `PUT /api/v1/bom` with `autoCreate=true`, stable name/version and original file bytes. A repeated submission targets the same project identity, but DT's actual project/component counts and completed processing must be inspected through its API/UI; the returned token only confirms queue acceptance, **not** vulnerability analysis. Keep that token for polling. Do not put the API key on the command line. If the API returns 403, inspect the key's dedicated permissions; do not use the admin password in scripts. No actual OVAC import is claimed without its file.

DefectDojo findings/triage are a separate source of truth; no automatic equality between a DT vulnerability and a Dojo finding. GitHub issues/PRs are references, deployments must be reported by the deployment pipeline, and the catalog remains canonical for product-service mapping. This prevents treating Git `HEAD` as deployed production state.

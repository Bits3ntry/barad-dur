The software inventory answers "what do we ship, and what is inside it". It is built from documents a scanner produced, never typed by hand.

### The chain

`project → component → version → build`, and inside a build: `package → advisory → finding`.

- A **project** is the application.
- A **component** is a deliverable inside it (`backend`, `web`, `mobile`, `api-image`). Components carry the repository binding, so they are also the thing a pipeline attaches to.
- A **version** groups builds by a label people recognise — `1.8.0`, `main`, a commit sha.
- A **build** is one CycloneDX document. Re-uploading the same document to the same project+version is a no-op: ingestion is idempotent on the content hash.

### Creating a project and its parts

**Projects → new project** asks for name, group, owner, slug and a description, and creates the project together with its first component. From the project's own page you add:

| Thing | Why it matters |
|---|---|
| another **component** | monorepos ship several artefacts; each one builds separately |
| a **repository** | the authorization a CI run relies on; without it no pipeline file can be generated |
| a **version** | groups builds; a version with no build is a version nobody has scanned |
| an **environment** | where it runs — production, staging |
| a **domain** or an **endpoint** | the application's own view of where it is exposed |

The same actions exist over the API; the console is a client, not a second source of truth. `POST /api/v1/projects/{slug}/components` adds a component, and the slug is what every other call addresses.

### Getting a build in — three doors, one result

**1. From CI (the normal path).** Build a pipeline, commit the generated file, push. The CI announces the commit, mints a ticket, scans the checkout and uploads the SBOM and its evidence. See *Pipelines and delivery*.

**2. From a laptop, local evidence only.** The repository ships a small CLI:

```sh
python3 -m venv /tmp/barad-venv
/tmp/barad-venv/bin/python -m pip install .
/tmp/barad-venv/bin/barad health
/tmp/barad-venv/bin/barad scan /path/to/project
```

`barad scan` writes into `<workspace>/.barad/reports/<project>/<version>/<scan-id>/`: a Trivy CycloneDX SBOM, a `security.json`, an OpenGrep `sast.json` and a manifest. It never modifies the scanned project, and it never uploads — `security.json` and `sast.json` can contain secrets and source excerpts and stay owner-only.

**3. Directly against the API.** A CycloneDX JSON document is the body, sent as raw bytes:

```sh
curl -sS -X POST \
  -H "X-API-Key: $BARAD_API_KEY" \
  -H "Content-Type: application/octet-stream" \
  --data-binary @sbom.cdx.json \
  "http://127.0.0.1:8090/api/v1/sbom?project=aurea&component=backend&version=1.8.0"
```

The body is **not** JSON-encoded — the route takes `bytes`, and an `application/json` request is parsed as JSON and rejected. `component` may be omitted for a product-wide release. The answer is a receipt: `201` for new content, `200` when that exact content already landed.

**Runtime versions are their own document.** `trivy fs` only sees lockfiles; the interpreter is declared, not installed. `shauron runtime --path . --out runtime.cyclonedx.json` reads what the tree declares — `engines.node`, `.nvmrc`, `requires-python`, `go.mod`, `.ruby-version`, `Dockerfile FROM` — and writes `pkg:generic/node` or `pkg:docker/node@22-alpine`. Import it against the same project/version/component and the runtime's CVEs arrive alongside the packages'. A declared range stays a range; a tag names a line (`22-alpine` → the 22 line); neither is turned into an invented version, and the confidence says which it is.

### Reading a build

A build screen answers, in this order: how many components, how many advisories by severity, what the licenses say, and what the code analysis found (SAST and secrets, including the ones someone dismissed — a settled finding is still a fact about that build, and hiding it made a scanned build read as unscanned).

Three details that save arguments:

- **A finding is keyed by CVE, not by advisory id.** Trivy names `CVE-2021-23337`, OSV names `GHSA-…` for the same defect; the platform resolves both to one row.
- **Optional peer edges are not provenance.** `vite` declaring `@types/node` as a peer does not mean the build pulled it in. Rows marked `direct` must not print "via X".
- **Scoped packages keep their scope.** If a table shows `node` where you expected `@types/node`, that is an ingestion identity bug, not a display choice.

### Components vs Builds

Both are in the sidebar and they are not redundant:

- **Components** is the catalogue across projects: which components exist, their versions, their license groups and their risk, filterable by name, group, license or purl. It is where you ask "who uses this library?".
- **Builds** is one artefact in detail: this build's packages, advisories, code findings and secrets.

### Licenses

**Licenses** groups what the builds contain by license and flags the ones policy forbids, per project. It reads the same documents; nothing extra needs to be uploaded.

### When the data looks wrong

Order of checks, cheapest first:

1. **Is a filter applied?** The table prints `N of M`; a paste of six rows from a 140-row build is a filter, not a bug.
2. **Read the import receipt.** Every ingestion records what it processed — source, counts, whether it was `unchanged`.
3. **Open the raw document.** The uploaded artefact is stored; if a package is not in the document, ingestion could not invent it.
4. **Check the identity.** Same package under two names (scoped vs bare, tag vs digest) is two rows and always was.

The advisory clock is a *second* clock on top of all this: after a build lands, a background sweep re-asks OSV about the newest builds, refreshes KEV and EPSS, and matches runtimes against NVD. Settings → Intelligence owns its interval and sources; Orchestration shows the sweeps and their logs. A CVE published after your scan appears because of that clock, not because the build changed.

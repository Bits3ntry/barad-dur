# Deployment health probes — feature design

Status: design approved for implementation planning; no runtime code has changed.

## 1. The problem

A deployment tells us where a component should be running, but it does not prove
that it is reachable or which release is actually serving traffic. Teams often
already expose a safe operational endpoint, for example:

```json
{
  "status": "ok",
  "postgres": true,
  "externalCache": true,
  "version": "21.7.8"
}
```

For a deployment such as `AUREA backend / dev / aurea.dev.bitsentry.xyz`, an
operator must be able to declare that endpoint once and have Barad-dûr:

1. make an authorised `GET` request;
2. show the facts it observed: reachability, application status, version and
   selected metadata/checks;
3. retain the evidence and the time of observation;
4. update the deployment's observed version; and
5. create the project version when it does not exist yet.

It must not call arbitrary URLs, infer a healthy system from one HTTP 200, or
claim a version/artifact it cannot prove.

## 2. User flow

### 2.1 Configure on a deployment

In the deployment detail/edit panel the owner or admin sees a **Runtime probe**
section:

| Field | Example | Meaning |
|---|---|---|
| Endpoint | `https://aurea.dev.bitsentry.xyz/health` | exact URL to query |
| Version field | `version` | dot path in the JSON response |
| Status field | `status` | dot path in the JSON response |
| Healthy value(s) | `ok, healthy` | case-insensitive values that mean application healthy |
| Required checks | `postgres`, `externalCache` | JSON paths that must be truthy for the configured application health |
| Display metadata | `build.commit → commit`, `region → region` | safe JSON paths shown as facts, not used for health |
| Refresh behaviour | `on authorised collection` / `manual only` | default is collection-triggered after preview/save |

The form includes **Test and preview**. It performs one request but does not
change a deployment version. Its preview says exactly what will be persisted:

```text
reachable       yes · HTTP 200 · 84 ms
application     healthy · status = "ok"
required checks postgres ✓ · externalCache ✓
version         21.7.8 → will link/create AUREA@21.7.8
metadata        commit = 9c1a… · region = us-east-1
```

If `status` is missing or no healthy-value mapping exists, the result is
**reachable — application health not configured**, not "healthy". If `version`
is missing, it says **version not reported** and makes no version row.

### 2.2 Normal operation

- **Run now** requests the probe and records an observation.
- An authorised active collection of an asset linked to this deployment requests
  the probe once after the collection. A deployment linked to several assets is
  still probed only once per collection run.
- A failed attempt keeps the last successful version and marks the latest
  observation failed/stale. It never clears a known version and never creates a
  fake rollback.
- The deployment row shows: `healthy / degraded / unreachable / unknown`,
  observed version, last success, last attempt, and the data source.

## 3. Data model

The existing relations remain the source of truth:

- `Deployment` already identifies an environment-specific running unit
  (`models.py:639`) and can point at an explicitly known `Artifact`.
- `Artifact` is an exact build, normally evidenced by a digest/SBOM
  (`models.py:1477`). A health response without a digest **must not** overwrite
  it.
- `ProjectVersion` is the product-version inventory identity
  (`models.py:75`). It is what an endpoint response may create/link.
- `AssetLink(entity_type="deployment")` identifies assets that expose the
  deployment (`models.py:667`). It limits where an automatic probe may go.

Additive records proposed:

### `deployment_health_probes`

One active configuration per deployment.

| Field | Notes |
|---|---|
| `id`, `org_id`, `deployment_id` | tenant isolation and one-to-one relationship |
| `url` | exact configured HTTPS URL |
| `version_path`, `status_path` | nullable dot paths; no code/expression evaluation |
| `healthy_values` | JSON array of normalized strings |
| `required_check_paths`, `metadata_fields` | JSON configuration; metadata fields map path → UI label |
| `mode` | `collection` or `manual` |
| `enabled`, `created_by`, `updated_at` | operational control and audit |

### `deployment_health_observations`

Append-only evidence; never just a mutable status column.

| Field | Notes |
|---|---|
| `id`, `org_id`, `deployment_id`, `probe_id` | tenant + traceability |
| `trigger` | `manual` or `collection` |
| `started_at`, `finished_at`, `latency_ms` | timing evidence |
| `outcome` | `healthy`, `degraded`, `unreachable`, `unknown` |
| `http_status`, `error_code` | HTTP fact or bounded safe error (`timeout`, `invalid_json`, …) |
| `reported_version`, `project_version_id` | raw reported value plus the linked/created ProjectVersion |
| `status_value`, `checks`, `metadata` | normalized selected facts only, not the whole response |
| `response_sha256` | optional correlation without retaining sensitive response bodies |

Add summary columns to `deployments` for fast inventory reads:
`health_state`, `health_checked_at`, `health_last_success_at`,
`observed_version_id`, `observed_version_source="runtime_probe"`.

`observed_version_id` points to `ProjectVersion`; it is intentionally separate
from `artifact_id`. The UI can say:

```text
runtime reports 21.7.8 (checked 2026-11-03 14:20 UTC)
artifact unknown — no digest/build evidence was supplied
```

## 4. Version pinning rules

The runtime response is a declaration of what the application reports, not SBOM
or provenance evidence.

1. Resolve the deployment's project through its `application_component_id`; if it
   is absent, fall back only to a uniquely linked project. If neither is
   unambiguous, record the version as observed but do not create a project version:
   `version_not_linked: deployment has no unique project`.
2. Trim the discovered scalar value; reject objects, arrays, blank strings and
   values longer than 255 characters.
3. Find `ProjectVersion(project_id, version)`. If present, link it.
4. If absent, create it atomically with provenance `runtime_probe`, then link it.
   A repeated observation is idempotent: it creates neither another version nor
   another deployment relationship.
5. Never create/replace an `Artifact`, SBOM, component usage, digest, deployment
   timestamp or findings from the health response.
6. A later observed version changes only `observed_version_id`; history remains in
   observations, so rollback from `21.7.8` to `21.7.7` is visible.

The implementation will add explicit `source`/`observed_at` provenance if the
current `ProjectVersion` schema cannot carry it without ambiguity. It will not
rewrite migration 0042 or any applied migration.

## 5. Health semantics

There are three independent facts; the UI must not merge them:

| Fact | Rule | Example |
|---|---|---|
| Reachability | request completed and returned a 2xx response | `HTTP 200` |
| Application health | status matches configured healthy values and every required check is truthy | `status=ok`, `postgres=true`, `externalCache=true` |
| Runtime metadata | selected values exist in the response | `version=21.7.8`, `region=us-east-1` |

Outcome precedence:

1. network failure, TLS failure, timeout, non-2xx or invalid body ⇒ `unreachable`;
2. configured status/check explicitly fails ⇒ `degraded`;
3. all configured application criteria pass ⇒ `healthy`;
4. otherwise ⇒ `unknown` (reachable does not equal healthy).

Missing optional metadata is simply `not reported`. Missing required checks is
`unknown`, unless an explicit false value is returned, which is `degraded`.

## 6. Security and authorization

A health endpoint is an active request. The server — never the browser — performs
it, so CORS, credentials and the response cannot be forged by the client.

Before every request:

1. caller needs owner/admin/analyst permission **and** the active-verification
   grant for its recorded principal;
2. the endpoint host/port must match an active asset linked to the deployment;
3. the asset must be in declared scope and the scope must allow
   `active_verification`;
4. only `https` is allowed, with `http` limited to `localhost`/`127.0.0.1` for
   test harnesses; redirects are disabled;
5. resolve and reject loopback, link-local, private/reserved addresses unless the
   configured linked asset is explicitly a local test target;
6. request method is GET only, timeout is ≤5 seconds, response is capped at
   256 KiB, and only JSON responses are parsed;
7. no request/response secrets, authorization headers, cookies or unselected
   response keys are stored in the observation/audit log.

Phase 1 accepts public operational endpoints only. A future authenticated probe
must use an explicit sealed secret reference, never a raw header field in the
console or database.

## 7. API proposal

All routes use the deployment's org scope and return the existing `{data: …}`
envelope.

```text
GET    /api/v1/deployments/{id}/health-probe
PUT    /api/v1/deployments/{id}/health-probe
DELETE /api/v1/deployments/{id}/health-probe
POST   /api/v1/deployments/{id}/health-probe/preview
POST   /api/v1/deployments/{id}/health-probe/run
GET    /api/v1/deployments/{id}/health-observations?limit=50
```

`preview` accepts an unsaved configuration and returns a normalized evaluation;
`run` uses the saved configuration and writes the observation/version link.
`PUT` must test syntax and asset ownership but must not make a network request;
that is why preview is a separate explicit action.

The collection router calls an internal `run_probe(...)` only after its own
observation is stored successfully. A probe failure is recorded separately and
does not turn a successful DNS/TLS collection into a failed collection.

## 8. UI proposal

Place the capability on a deployment detail, not on the generic asset row: a
single domain may expose several deployment environments and a probe belongs to
the environment/application relationship.

- **Deployments table**: environment, runtime health, observed version, last
  checked, `configure probe`/`run now`.
- **Probe drawer**: endpoint, mapping fields, preview, save/pause.
- **Deployment detail**: latest observation, required check chips, selected
  metadata, version history and an explicit `runtime-reported` provenance badge.
- **Projects/Applications**: latest selected product version can show
  `reported by dev/prod deployment`; it must not replace an artifact's digest or
  SBOM provenance.
- Empty state: `No runtime probe configured`; not `healthy` or `not monitored`.

## 9. Acceptance tests before implementation

Backend/API:

1. config can only target a same-org asset linked to the deployment; a foreign or
   unlinked URL is 404/422 and causes no request;
2. no active-verification grant ⇒ 403; excluded/out-of-scope asset ⇒ 403;
3. successful example payload produces `healthy`, version `21.7.8`, both required
   checks pass, selected metadata is retained and no raw response is stored;
4. `status="ok"` with `postgres=false` produces `degraded`;
5. HTTP 200 without configured status/checks is `unknown`, not healthy;
6. non-JSON, redirect, timeout, 500 and oversized response leave the last known
   version untouched and write a bounded failed observation;
7. first `21.7.8` creates exactly one project version; second run is idempotent;
   `21.7.7` links/creates it and preserves `21.7.8` history;
8. an unlinked deployment records the raw version but cannot create a project
   version; it explains why;
9. a runtime version never creates an artifact/SBOM or changes `artifact_id`;
10. cross-org reads for configuration, observation and deployment all return 404.

UI/browser:

1. preview translates the example payload into reachability, health, version and
   metadata without saving it;
2. save → run now updates the row after reload;
3. timeout/error, no permission, no probe configured and unknown health have
   distinct messages;
4. deployed `dev` and `production` can report different versions; neither is
   silently presented as the other;
5. the auto-created version appears in the project version selector with
   `runtime probe` provenance and no invented SBOM/findings.

## 10. Delivery slices

1. **Foundation**: migration, models, safe JSON-path evaluator, SSRF/scope/grant
   guard, manual run/preview APIs, tests with a local mock server.
2. **Inventory UI**: deployment probe form, preview and history; browser
   walkthrough on a fresh isolated stack.
3. **Automatic refresh**: invoke once after an authorised asset collection,
   dedupe per deployment/run and test failed-probe isolation.
4. **Optional later**: sealed authenticated headers, schedules, richer health
   expressions, Prometheus/OpenTelemetry adapters.

No external scheduler, automatic active collection, artifact inference or secret
management is smuggled into this first feature slice.

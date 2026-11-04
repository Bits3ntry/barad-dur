# Project runtime graph — feature design

Status: planned after deployment health probes. This is the **project summary /
Running now** view: a reader sees what is connected to a project, what is
actually running, and later where findings and registered endpoints belong.

## 1. Intent

The graph in the supplied reference is useful for its interaction model, not its
visual styling:

- one meaningful central entity;
- connected evidence radiating from it;
- hover isolates one branch;
- click opens the entity sheet;
- a scope switch changes the graph rather than duplicating the page.

We keep Barad-dûr's light, monochrome document language. We do **not** copy the
dark background, dense unlabeled cloud, or a graph that forces someone to guess
what each edge means.

The graph answers:

```text
Project
  → application component
    → code repository / analysis
    → product version
      → exact artifact (when evidenced)
        → deployment by environment
          → linked asset / registered endpoint
            → runtime probe observation
            → exposure / finding (when observed)
```

It is an evidence graph, not an architecture diagram inferred from names.
Missing links render as explicit gaps, never invented nodes.

## 2. Where it lives

`Projects` gains two clearly separate modes:

```text
Portfolio      Running now
```

- **Portfolio** remains the current group → project → version accounting table.
- **Running now** is selected per project. It opens from a project row or from a
  direct route such as `#projects::graph=<project-slug>`.
- The view defaults to the selected project, not the entire organisation. A
  controlled `all projects` switch is useful later, but must warn that it is
  aggregate context rather than a single runtime chain.

The opening summary is textual before the graph:

```text
AUREA · 3 components · 2 active deployments · 4 linked assets
production reports 21.7.8 · checked 4 min ago
1 deployment has no runtime probe · 2 assets are not linked to a deployment
```

That summary makes the page usable even with a narrow screen or an empty graph.

## 3. Node and edge vocabulary

Every graph object has one type, one label and one evidence state. Edge labels
appear on focus/hover and in the right-side inspector; they are not permanently
printed across the canvas.

| Node | Existing / planned source | Meaning |
|---|---|---|
| Project | `Project` | product/application boundary |
| Application component | `ApplicationComponent` | backend, frontend, worker or other code unit |
| Repository | `Repository` + `ProjectRepository` | source-code origin; repository may be shared |
| Analysis run | `AnalysisRun.repository_id` | an observed analysis of that repository/revision |
| Product version | `ProjectVersion` | a release identity, not proof of deployment |
| Artifact | `Artifact` | exact build/digest/provenance, when supplied |
| Deployment | `Deployment` | component/artifact in one environment |
| Asset | `Asset` + `AssetLink` | domain, host, URL or address exposing a deployment |
| Registered endpoint | `WebEndpoint` / future endpoint link | discovered or declared HTTP/API surface |
| Runtime probe | planned `DeploymentHealthProbe` + observation | actual reachability, health and reported version |
| Finding / exposure | `FindingContext`, exposure events | security evidence attached to a concrete context |

Canonical edges:

```text
project --contains--> component
project --uses--> repository
repository --analysed by--> analysis run
component --builds--> artifact
artifact --is build of--> version
artifact --runs as--> deployment
deployment --runs in--> environment
deployment --is exposed by--> asset
asset --has registered--> endpoint
deployment --is checked by--> runtime probe
finding/exposure --observed in--> repository | deployment | asset | endpoint
```

Important constraints:

- The current `ProjectVersion` is project-level. The graph may show it adjacent
to its artifact/component, but must not assert a component-version relationship
unless the data has it.
- An artifact without digest/SBOM remains an artifact with limited evidence; it
is never presented as verified production provenance.
- An asset can expose more than one deployment. This is represented by two edges,
not by cloning the asset.
- A web endpoint is not automatically a finding. A 200 response is an endpoint
observation, not proof of weakness.

## 4. Layout and interactions

### Default layout: readable runtime flow

The graph is a directed left-to-right flow with a project card anchored at the
left, not a force-directed random cloud:

```text
Project → Components → Code / Versions → Artifacts → Deployments → Assets → Endpoints
                                                   ↘ Runtime probes
                                                   ↘ Findings / exposures
```

The visual uses a simple SVG layout with stable columns. Nodes do not move on
reload, so a person can build a mental map and screenshot evidence is comparable
between passes. A later global graph may use a radial layout; the project view
must privilege explanation over visual drama.

### Interaction contract

- Hover a node or edge: fade unrelated branches; highlight the whole path to the
  project; show edge verb and evidence timestamp.
- Click a node: pin its branch and open its current detail drawer. Clicking a
  finding opens the existing finding drawer; clicking an endpoint opens its
  endpoint sheet; clicking a deployment opens runtime probe history.
- Click canvas background or press Escape: clear the pin.
- Keyboard: Tab reaches nodes in reading order; Enter opens the drawer; focus
  draws the same branch highlight as hover.
- Filter chips: `production`, `dev`, `active only`, `health degraded`, `has
  findings`, `unlinked`. Filters hide only the view; the header says `showing
  3 of 5 deployments` so hiding is never mistaken for absence.
- A compact table/list fallback appears below the graph and is the mobile default.

## 5. States and visual language

Use shape + label + restrained severity colour, never colour alone.

| State | Presentation |
|---|---|
| evidenced / current | normal node, observation time |
| stale | dashed border + `last seen …` |
| unknown | neutral border + explanation (`no probe configured`) |
| degraded/unreachable | severity accent + explicit cause |
| missing relationship | small gap card (`asset not linked to a deployment`) |
| partial coverage | note on the node (`SBOM linked at version level; per-artifact usage unknown`) |

The graph starts with an honest empty state:

```text
No runtime relationships are recorded for AUREA yet.
Start by adding a component, a deployment and the asset that exposes it.
```

It never starts as a decorative empty network.

## 6. API contract proposal

One read model prevents the UI from reconstructing cross-table joins and getting
permissions/tenant filtering wrong:

```text
GET /api/v1/projects/{project_ref}/runtime-graph
  ?environment=production
  &health=degraded
  &include=findings,endpoints,analysis
```

Response:

```json
{
  "data": {
    "project": {"id": "…", "slug": "aurea", "name": "AUREA"},
    "summary": {
      "components": 3,
      "active_deployments": 2,
      "linked_assets": 4,
      "registered_endpoints": 7,
      "open_findings": 5,
      "coverage": ["1 deployment has no runtime probe"]
    },
    "nodes": [
      {"id": "deployment:…", "type": "deployment", "label": "backend dev",
       "environment": "dev", "health": "healthy", "observed_at": "…"}
    ],
    "edges": [
      {"from": "component:…", "to": "deployment:…", "relation": "runs_as",
       "evidence": "declared"}
    ]
  }
}
```

Every node carries only display-safe fields. It does not leak raw health response
payloads, credentials, hidden assets or foreign-organization identifiers.
Unknown `project_ref` and cross-org references return 404, exactly like existing
project readers.

The first implementation returns only facts already stored. `registered_endpoints`
remains zero/unknown until the endpoint model is explicitly linked; it is never
backfilled from guessed URL strings.

## 7. Delivery sequence

1. **Graph read model, no new collection**
   - project/components/repositories/versions/artifacts/deployments/assets;
   - stable SVG + accessible list fallback;
   - `Running now` summary and empty/gap states;
   - tenant/permission/404 tests.
2. **Runtime evidence**
   - add the deployment-health-probe feature from
     `deployment-health-probes.md`;
   - show probe state, reported version and observation history on deployment
     nodes; no automatic endpoint inference.
3. **Endpoints and security context**
   - expose registered/discovered endpoints as explicit nodes;
   - link endpoint/deployment/asset findings with relation provenance;
   - filters for finding severity and exposure state.
4. **Optional global graph**
   - organisation mode only after project mode proves its vocabulary and
     performance; aggregate nodes by project/environment, never a raw cloud.

## 8. Acceptance criteria

1. A fresh project with no inventory shows an actionable empty state.
2. A project with backend/frontend components, two versions, one artifact, dev
   and production deployments, and linked assets produces deterministic node and
   edge counts after reload.
3. A selected `dev` deployment highlights only its component/artifact/asset path;
   it does not hide the fact that production exists.
4. A runtime probe can display `reported 21.7.8` while the artifact is unknown;
   those labels remain distinct.
5. A cross-org project id/node id cannot be read or opened.
6. A finding linked to an asset/deployment appears in the correct branch with its
   existing status/severity; an unlocated finding stays in the project summary
   under `findings without runtime context`.
7. At 1280×720 the graph remains readable; on mobile the same relationships are
   available as an ordered list.
8. The graph makes no network request itself. It reads stored evidence only;
   `Run now` stays an explicit deployment action with authorization.

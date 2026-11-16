# Findings & inventory — information architecture

Status: **design only, no code**. Written after reading the screens, the routers and
the live stack; every number below was read from `barad_platform` on 2026-11-11.

## The ask, in the operator's words

The flow must be readable as one line:

```
projects / components / version / assets  --TRIVY-SCANS-ETC-->  findings  <--  cycles / pentest
```

and the findings area must stop mixing three different objects: the **vulnerability**
(what the world published, and how it reaches us through the dependency chain), the
**dependency/version** (what we ship, and which advisories and projects it touches),
and the **finding** (our instance of it, with a status and an owner).

## What the data says (live)

| query | value |
|---|---|
| findings by kind | vulnerability 843 · code-weakness 16 · secret 5 · misconfiguration 2 |
| findings with an advisory / a package / a build / a project | 836 / 836 / 857 / 865 of 866 |
| findings by project | AUREA 577 · OVAC 280 · Juice Shop 8 · none 1 |
| findings under version label `main` alone | 572 (AUREA) |
| catalog | 633 vulnerabilities · 1597 packages · 1787 build↔package links · 14 builds · 3 projects · 274 assets · 679 occurrences |

97% of this estate is supply chain. The console's shape does not say so: it shows a
generic "Findings" queue where 843 dependency rows and 21 code/secret/config rows
share one set of columns.

## The four nouns

The database already has the separation. The UI does not.

| object | table | identity | page | question it answers |
|---|---|---|---|---|
| **Advisory** (CVE/OSV) | `vulnerabilities` (global, no org) | `source_id`, `cve_id` | `/cve/:cve` | what is this, how bad, does it reach me |
| **Package** | `components` (org-wide) | `org_id + identity_key` | `/package/:id` | what is this thing we ship, who pulls it in, what do I fix |
| **Build** (version) | `project_versions` (+ `version_components`) | project × component × version | `/build/:project/:component/:version` | what ships in this release |
| **Finding** | `findings` | `org_id + fingerprint` | `/findings/:id` | our instance: subject, evidence, status, owner, SLA |
| Asset | `assets` | org + value | `/asset/:id` | what is exposed on this host |

`Vulnerability` has **no org scope** and no status; `Finding` has both. That is the
whole difference, and no screen currently says it.

## Diagnosis — six defects, with evidence

**1. The global queue opens pre-filtered to one build.**
`Findings.jsx:46-55` seeded `project = projects[0].name` and `version =
projects[0].versions[0]` whenever the filters were empty. Measured on the live
console: the rail's door printed **576 hallazgos en alcance** over an estate of 866,
and the 576 was two different builds merged — AUREA ships two components as `main`,
one carrying 345 findings and the other 227 (345 + 227 = 572, plus four rows without a
build). The reader had no way to know that 290 rows lived outside the slice, and the
two `<select>`s were the only clue. A queue is the whole estate until the reader
narrows it.

**2. One finding appears as four different tables.**
The same `findings` row is rendered as: a row in **Findings** (per instance), a row
in **Vulnerabilities → Estate** (grouped by signature, `Vulnerabilities.jsx:118`), a
row in the **build's Vulnerabilities tab** (`Sbom.jsx:1432 VulnerabilitiesTab`), and
a row in **PackageDetail's advisories** (`ComponentDetail.jsx:131`). Four column sets,
three groupings, no shared component, and no two of them cross-link. This is the
"popurrí": not wrong data, but four renderings of one fact with different vocabularies.

**3. The two entity pages the operator is asking for already exist and have no door.**
`CveDetail.jsx` (advisory → packages, builds, projects, assets, findings) and
`ComponentDetail.jsx` (package → where it ships, direct/transitive, its advisories)
are exactly the two screens described in the ask. Both are `HIDDEN_SCREENS`
(`App.jsx:148-177`): no rail row, no link from the project page, no link from a
build — reachable only by clicking a row inside the Vulnerabilities list, or through
⌘K. The information is built; the navigation never points at it.

**4. The chain is only inside the build's dependency graph.**
`version_components.parent_purl` is populated and `sbom.py:1011 _ancestry()` already
walks it, but only `/api/v1/sbom/version` exposes it, so "why do I have this package"
can only be answered inside one build's Graph/Packages tab. The advisory page lists
affected packages and the fix version, never *how the package got in*; the package
page lists builds and direct/transitive, never *who requires it*.

**5. Assets have no leg into findings.**
`AssetDetail.jsx` fetches only `/assets/{id}` and `/assets/{id}/geo` — the host page
never shows the findings attached to it, although `findings.asset_id` exists and the
advisory page already renders per-asset rows. In the requested flow the `assets →`
leg is missing entirely.

**6. Provenance is not a facet anywhere.**
`/api/v1/findings` already accepts `cycle`, `version_id`, `vector`, `status` and
`origin` (`findings.py:305-337`), and `CycleFinding` exists, but no screen builds a
link *into* the queue from the thing that produced the finding: a scan run, a cycle, a
CI run, a pentest engagement. Orchestration, Cycles, Pentest and Pipeline each own a
list of work and none of them can say "these are the findings I produced".

## Target shape

One grammar, three questions:

```
                  ┌──────────────────────────── the inbox (what do I fix) ──────────┐
 projects ──▶ project ──▶ build ──▶ package ──▶ advisory         findings (queue)
    │            │          │          │            │                   ▲
    │            │          │          └── chain ───┘                   │
    └────────────┴──────────┴── assets ──────────────────────────────────┤
                                                                        │
            scans / trivy / ci  ──── run ────┐                           │
            cycles (select, validate) ──────┼── provenance facet ────────┘
            pentest (demonstrate) ──────────┘
```

Rules that make the flow linear:

1. **Entity pages answer "what is this"; the queue answers "what do I fix".** No
   entity page grows its own findings table with its own columns — it embeds the one
   queue component, scoped.
2. **Every count is a door.** A printed `N findings` / `N advisories` is always a link
   into the queue or the advisory list with that facet applied; a dead number is a
   defect.
3. **The crumb carries the facet.** Landing in the queue from a build shows
   `Findings › AUREA / main › supply chain` with an `×` on each chip, so widening is
   one click and never a lost filter.
4. **Three clicks from any object to its fix**: project → component → build →
   (embedded queue) or project → build → advisory → queue.
5. **A version label is not a build.** Filters that reach the queue from an object
   carry `project_version_id` (`version_id`), never `version=main` — AUREA ships
   several components as `main` and the label query merges them.

## Decision log

| # | decision | status |
|---|---|---|
| D1 | The four nouns are **Vulnerabilidad**, **Paquete**, **Build**, **Hallazgo** — the operator calls the entity a vulnerability, so the screen keeps its name. "Advisory" (aviso) survives only as the word for the published record a vulnerability comes from, never as a screen label. | decided (revised: the rename in the first version of this doc is refused) |
| D2 | `/cve/:cve`, `/package/:id` and `/build/:project/:component/:version` become real paths with a crumb (project › build › package › advisory). Findings keeps `#findings::<id>` until P2. | recommended |
| D3 | The queue's default scope is the whole estate; the facet bar (project · build · vector · origin · cycle) is always visible, and the crumb states the active facet. | decided (operator's ask) |
| D4 | The build's bespoke "Vulnerabilities" tab is replaced by the shared queue component scoped to that build — same columns, same actions as the global queue. | recommended |
| D5 | The advisory page gains **how it reaches us**: per affected package, `direct`/`transitive` + the immediate parent(s), reusing `_ancestry()`; the package page gains the same chain. | recommended |
| D6 | `AssetDetail` gains a findings section fed by `/api/v1/findings?asset=<id>`; assets in the requested flow are a subject, not only an inventory row. | recommended |
| D7 | Run / cycle / CI run / pentest engagement each get one link into the queue filtered by their id (`cycle`, `origin_run_id`, `ci_run`, `origin`). No new list inside them. | recommended |
| D8 | Two objects, two granularities: a **finding** is a vulnerability that affects us *on a specific subject* (component, build, domain, asset) — the row you triage; a **vulnerability** is the fact itself — the row you read. The estate list prints one row per vulnerability; the advisory page lists the subjects; Findings keeps the instances. | decided (operator: "un hallazgo es una vulne que nos afecta en determinado componente, dominio, version etc.") |
| D9 | No new tables, no new finding kinds, no schema change. Everything above is router fields the tables already hold plus UI. | decided |
| D10 | One closure vocabulary in `app/status.py`; the six local copies are gone, and `GET /findings?open=true` answers "still open" for the whole platform. `notifications` keeps its own set on purpose (delivery policy ≠ count). | decided |

## Phases

**P0 — doors and names (UI only, no backend).**
Rename Vulnerabilities → Advisories in `en`/`es`; queue defaults to the whole estate;
facet bar with active-facet crumb; every printed count becomes a link; advisory and
package pages get a rail-reachable door (breadcrumb + ⌘K + "open" from the queue) and
a back path that returns to the exact scoped queue.
*Acceptance:* from `/projects` a reader reaches a single finding in ≤ 3 clicks; the
`#findings` header total equals the unfiltered estate (859 while 7 are cycle-held);
every `N` on the prov/ovac pages is clickable; `make lint` green; both locales render.

**P1 — the two entity pages, complete.**
Real paths (D2); chain column on advisory + package (D5); package page shows license,
chain, builds and advisories in one scroll; advisory page separates "affected here"
from "worldwide".
*Acceptance:* for one CVE in the live estate, the page answers *which builds, which
projects, how each package got in, what version closes it* without leaving the page.

**P2 — subjects and provenance.**
Asset findings section (D6); one door per producer (D7); `#findings::<id>` becomes
`/findings/:id`.
*Acceptance:* from a scan run, a cycle and a pentest engagement, one click lands on
the queue scoped to it with a correct count (cross-checked against `psql`).

**P3 — queue maturity.**
Grouping switch (`one row per finding` / `per advisory` / `per package`), saved facets
per user, bulk resolve from the grouped view.
*Acceptance:* the advisory rollup is reachable as a grouping of the queue and prints
the same numbers as `/api/v1/vulnerabilities`.

## Shipped — P0, first slice (2026-11-11)

What is now in the console, and the measurement that proves it:

- `#findings` asks the whole estate: **859 findings** (866 minus the 7 a cycle is
  still holding, which the router has always excluded), scope line reads
  `todo el inventario — sin filtrar` when nothing narrows it.
- Every active facet is a chip with its unit (`proyecto AUREA`, `build main`,
  `arreglo dependencia — actualizar el paquete`) and the chip is the way out:
  dropping the build widened 344 → 576 without losing the project.
- The facet travels in the address and a count can now point at a scoped queue:
  `#findings::project=aurea&build=<version id>&build_label=main` → **344**; the second
  build of the same project and the same label → **227**; the label form the old
  screen used returned 572 for both. `#findings::<id>` still opens the record page.
- A `fix` facet (the `vector` axis the API already had) separates *upgrade a package*
  from *fix the code*: dependency-cve 497, runtime-cve 79, sast 14, credential 5,
  misconfig 2, network 1 — and 266 vulnerability rows carry no vector, which the
  empty option keeps visible instead of hiding behind a filter.
- The empty state distinguishes "nothing filtered" from "this estate has nothing".
- Files: `frontend/src/Findings.jsx`, `frontend/src/App.jsx` (`parseHash`), both
  `findings.json` locales. `npm run i18n`, `npm run build`, `make lint` (85 screens)
  green; verified in the browser at 760px and 620px with no horizontal overflow.

Not changed in this slice, on purpose: the build's own Vulnerabilities tab (D4), the
advisory/package pages (P1), the nav labels (D1 waits on D8).

## Shipped — P1, the chain (2026-11-11)

The half of the ask that reads "vulnerability → how it reaches us" and "package →
which builds, and who pulls it in". No new table: `version_components.parent_purl`
already held the graph; what was missing was a reader outside the build screen.

- `backend/app/ancestry.py` — one walk (`ancestry`, `links_of`), moved out of the
  build router so the advisory page, the package sheet and the graph share it
  instead of three copies. `sbom.py` keeps its `_ancestry` name as a thin call.
- `GET /api/v1/vulnerabilities/advisory/{ref}` — every affected row now carries
  `direct` (the BOM's claim) and `chain` (nearest parent first). Live:
  CVE-2026-69152 → `brace-expansion 1.1.12` in AUREA `main` comes in through
  `minimatch 3.1.2 → config-array 0.21.0 → eslint 9.30.1 → … → aurea-frontend 0.0.0`.
- `GET /api/v1/components/{id}` — each build in `usage` carries the same `chain`.
- Advisory page prints the hop you act on plus the depth (`viene de minimatch 3.1.2
  · +4 arriba`), full path in the tooltip; the package sheet prints the immediate
  parent per build with the whole path on hover.
- Width defects found while measuring, fixed at the class level: the advisory title
  in two tables widened its column to 3153 px because `.table-wrap td` is nowrap and
  the paragraph never opted back into wrapping — it now uses the `.vuln-title` clamp
  the Vulnerabilities list already had. The affected table went 1261 → 683 px, the
  findings-behind table 3816 → 763, the package advisories 1002 → 714. At 1440 px
  every table fits its card exactly and the page never scrolls sideways; at 620 px
  the 7-column tables scroll inside their card (pre-existing for 7 columns; the page
  itself still does not).
- Tests: two new cases in `backend/tests/test_advisory_sheets.py` (direct vs chain on
  the advisory page, chain per build on the package sheet); full gate
  777 passed / 3 skipped. `npm run i18n`, `npm run build`, `make lint` green.
- Deploy: API image rebuilt and the container recreated (`healthz` after 2 s), console
  bundle `index-DLu-OHrR.js` served.

Still open from P1: real paths for the two pages and the nav door (D2, D1 — they wait
on D8), the "affected worldwide" split, and the licence block on the package page.

## Shipped — D8, one row per vulnerability (2026-11-11)

The operator settled the vocabulary, so the estate list stopped being a third thing.
`_groups` buckets by `(vector, signature, component)` — the **acting** view: a CVE on
two packages is two upgrades. The **reading** view is the vulnerability itself, so
`_groups(..., by="signature")` is now what `/api/v1/vulnerabilities` and the dashboard
KPI count, and a row's `components` / `projects` / `versions` / `locations` are the
findings that connect it to the estate. The per-package split stays where it belongs:
the advisory page (`affected.components`, one line per upgrade, now with its chain).

- List total is the number of vulnerabilities, not of findings. On this estate the
  number reads 431 before and after the change: no advisory here hits two
  differently-named packages (a CVE over two versions of `brace-expansion` was
  already one bucket, because the acting key uses the package *name*). The contract
  is what changed, and the test pins it; the row now prints `en N paquetes` when
  closing it takes more than one.
- Status and bulk actions keep the acting view (`by="component"`), so nothing about
  "resolve this CVE everywhere" changed underneath the operator.
- Test: `test_the_estate_list_shows_one_row_per_vulnerability` pins the split —
  2 findings, 1 component, 2 projects in the list; 2 affected rows on the page.

## Anti-goals

- No new tables, no migration, no re-scan, no reseeding of the operator's data.
- Do not merge `Vulnerability` into `Finding`: the catalog is org-free by design.
- Do not build a second graph renderer — the build graph and the chain share
  `useForceGraph`/`graphForce`.
- Do not hide a screen to "simplify" the rail; demote it to an embedded view.
- No client-side sorting or filtering on paged tables.

## Shipped — counts are doors (2026-11-11)

Every screen that prints how many findings something has now links into the queue
with that something as the facet, through one builder (`queueHash` in `ui.jsx`) so a
screen cannot invent a facet the queue does not understand.

- **Build header** — `96 hallazgos abiertos` → `#findings::project=aurea&build=<id>&build_label=main&kind=vulnerability&open=1` → **96**. Measured both ends.
- **Project → components → version row** — the count cell is the door; AUREA `main`
  `ca2c0da6` printed 205 and the queue answered 205.
- **Vulnerability page** — `Hallazgos abiertos: 3` → `#findings::q=CVE-2026-69152&open=1` → **3**.
- The queue gained two facets to make those doors exact: `q` (a CVE or rule id, so
  "the findings behind this vulnerability" is a link) and `open` (still open, which
  is what every count means).

**A door is only honest if both ends count the same thing**, and they did not: the
same build read **212 vulns** on the project table and **96 open** on the build page,
because six modules each kept their own idea of closure and four of them did not know
the word `closed`. Found by building the door, fixed at the source:

- `backend/app/status.py` — one set (`closed`, `resolved`, `false_positive`,
  `accepted_risk`, `suppressed`); `gates`, `dashboard`, `ctem`, `inventory`, `projects`,
  `sbom`, `vulnerabilities` and `findings` import it. `notifications` keeps its own
  set on purpose: what deserves an alert is delivery policy, not a count, and the doc
  says so where that policy lives.
- `GET /findings?open=true` filters on that set instead of one status word.
- After the fix: project table 96 = build page 96 = queue 96, and 205 = 205.
- Gates: 778 passed / 3 skipped, `make lint` 85 screens, `npm run i18n`, build; API
  image rebuilt, container recreated, console `index-C9-mGY9W.js`.

## Shipped — build → package (2026-11-11)

Clicking a package inside a build no longer opens the side drawer; it opens the
package's own page (`/component/:id`). The drawer was a narrower copy of that page —
same advisories, same builds, no address — so it could not be linked, compared or
kept while reading the build. Rows in **Overview** and **Components**, and graph
labels now leave for the sheet; the drawer component and its `Drawer` import are
gone. The dependency graph keeps its **inline** panel (the node and its path stay on
screen while you read them), which is the rule for graphs, not a lateral drawer.

`‹ back` on the package page returns where the reader came from — normally the exact
build, `#components::aurea/web/main::<version id>` — instead of resetting to the build
index; a deep link in a fresh tab has nothing to return to and falls back to the index.

Verified on the operator's own URL: `#components::aurea/web/main::ca2c0da6…` →
Components tab → row `node >=22.12.0 <23` → `/component/4ae7cd12…` → `‹ back` → the
same build. No drawer element on the page, no horizontal overflow.

## Shipped — the record is a link (2026-11-11)

`#findings::new` opens the record form. The queue's "nuevo hallazgo" is a link to
that address, not a modal, so the same record can be reopened, pasted to a colleague,
or pre-filled with the subject it came from (`#findings::new&project=aurea`). The
small modal is gone: one way to write a finding, the professional one.

The form now **names its subject**: project, build (disambiguated — `main · web` vs
`main · Backend`, because a label is not a build), cycle (optional; naming one files
the claim in that ledger), plus the product component and the asset it already had.
A record with no subject is refused in the form ("Necesita un sujeto…"), because a
record nobody can route is a paragraph.

- `POST /api/v1/findings/record` is the estate door; the cycle ledger endpoint and it
  both call `claims.record_claim`, so the fields, the fingerprint and
  `triage_status = new` cannot drift. `cycle_id` is the only difference.
- Fixed on the way: the Spanish `finding.subtitle` was the English sentence.
- Verified end to end: one record created through the UI with project + build, read
  back from the database (`origin = manual`, `triage_status = new`, `project_id` set,
  `last_seen_version_id = ca2c0da6…`), and the QA row deleted afterwards so the
  estate is back to 866 findings.
- Gates: 783 passed / 3 skipped, `npm run i18n`, build, `make lint`; API image
  rebuilt, container recreated, console `index-BzuXmutN.js`.

## Open questions (owner)

1. Where does the rail put the two entity pages: as doors of their own, or only as
   crumbs from Builds/Vulnerabilities (they have real paths either way)?

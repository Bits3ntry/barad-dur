# End-to-end acceptance: load → analyse → decide

A reproducible pass over the whole product on an **empty** organization: every
number on screen has to come from something written during the run, either
through the console or through a documented import endpoint. Nothing is seeded.

Two scripts back it:

| Script | What it is for |
|---|---|
| `scripts/e2e_stack.py` | Empty organization (`bitsentry`) + the built console on `127.0.0.1:8099`. Prints the API key and writes `barad_e2e_state.json`. |
| `scripts/demo_v0.py` | The same stack with a **labelled fixture set** already loaded, for API-level checks and for a five-minute look at a populated console. |

```bash
npm run build --prefix frontend
python scripts/e2e_stack.py --port 8099
# open http://127.0.0.1:8099/ → "api key" tab → paste the key it printed
```

## The pass, in order

Each row is one action and what proves it worked. "UI" means it was done by
clicking; "API" means the console has no importer for it yet and the documented
endpoint is the supported path.

| # | Step | Path | Expected |
|---|---|---|---|
| 1 | Open all twenty screens on an empty org | UI | Every screen renders an honest empty state ("No CVEs affecting this inventory yet", "Upload an SBOM for this version…"), no JS error, no request ≥ 400 |
| 2 | Declare `*.bitsentry.xyz` | Scope → *declare target* | `1 declared · 1 active · 1 pattern rule`; inventory stays at **0 assets** — a pattern is a rule, not a host |
| 3 | Declare `api-aurea.bitsentry.xyz` | Scope → *declare target* | `2 declared`; Assets shows **1 asset** with provenance `scope` |
| 4 | Create group `Production` and add the asset | Assets → Groups → *new group* → open → *add* | Group lists the asset as a member; the asset row shows the group chip |
| 5 | Import a CycloneDX SBOM for `aurea` `v1` | Components → *import SBOM…* (file picker) | Receipt `2 created, 0 updated, 2 links`; Components lists django 4.2.0 (BSD-3-Clause) and requests 2.31.0 |
| 6 | Record a manual finding (IDOR, no CVE) | Findings → *new finding* | Row appears with `P3 · HIGH · code-weakness`, path and line; no CVE is invented |
| 7 | Add a priority rule `secret → P0` | Prioritization rules → *add rule* | Rule listed at position 100; findings are reclassified on save |
| 8 | Import a SARIF base run and a head run with a diff | API `POST /api/v1/analysis/import` | `base: no_reference 1`; `head: persistent 1, on_modified_line 1` |
| 9 | Open the analysis | Code analysis → *open* head run | File tree with the supplied snapshot, rule `py.sqli · CWE-89` at line 12, diff tab `1 added · 1 removed`, results tab `persistent / modified line: yes` |
| 10 | Import two host observations (ports 443/8080, then +9090) | API `POST /api/v1/observations` | First: `events_created 1`, no change (baseline). Second: `changes 1` → `open_port 9090` |
| 11 | Read the derived screens | Attack surface → Changes, Exposures, Dashboard | Changes shows `open port · — → 9090 · e2e-import`; Exposures `2 open` (new host + open port); dashboard counters agree (assets 1, projects 1, findings 2, exposures 2, changes 7d 1) |
| 12 | Create a cycle with an explicit selection | Cycles → *new cycle* (projects `aurea`, group `Production`, environment `production`) | `planning`, preview `3 members`, and the honest gap `no deployment recorded for environment production` |
| 13 | Activate, link findings, review, close | Cycles → *activate and freeze* → *link project findings* → *record review* → *close cycle* | `activated: 3 members frozen`; findings `2`; `review recorded`; detail keeps charter, selection and review after closing |
| 14 | Re-read Business impact | Business impact | `1 application · 2 open findings · 1 asset · 0 production deployments`, P1 1 / untriaged 1, and the note that criticality is not modelled |

## Identity and channels (same stack, session login)

The e2e stack also creates a human account (`ana@bitsentry.xyz`, throwaway
password printed by `scripts/e2e_stack.py`) so the flows that need a session can
be walked:

| # | Step | Expected |
|---|---|---|
| 15 | Settings shows *sign-in and security* | with an API key: "second factor needs a signed-in user"; the SSO line names the provider when `OIDC_*` is set, otherwise the four variables to set |
| 16 | Sign in with email+password → Administration → *My security* → start enrolment → scan the QR/manual secret → confirm a code | factor becomes `enabled`, eight recovery codes appear **once**, and the next login asks for a code before issuing a session (wrong code rejected, recovery code accepted once) |
| 17 | Notifications → *Delivery channels* → kind `slack` → paste a webhook URL → **test** | `test delivered … HTTP 200`; the receiver gets `{text, blocks}`, not the signed generic envelope |

## What the pass checks under the surface

- **Console errors and failed calls.** Before navigating, the browser records
  `window.onerror`, unhandled rejections and every `fetch` with `status >= 400`
  into one array; the run is only "clean" when that array is empty for all
  twenty screens. This is how two real defects surfaced (below).
- **Data written once is read everywhere.** The same finding is the row in
  Findings, the `P3` in Business impact and the count in the dashboard; the same
  observation is the row in Changes and the `open` event in Exposures.
- **Honest states.** Empty (no SBOM), not configured (weekly delivery),
  coverage gap (assets without project, environment with no deployment) and
  error (`HTTP 401` with an invalid key) are distinct on screen.
- **Persistence.** Reload keeps the closed cycle's snapshot, the group's
  membership and the imported analysis.

## Defects found by this pass (and fixed)

| Defect | Symptom | Fix |
|---|---|---|
| `pr is not defined` in `CodeReview.jsx` | Pull requests and every screen visited after it (Gates, Licenses, Members, Audit, Setup) rendered blank | the publish dialog read a table-scoped variable; it now stores the pull-request id in state (`publishFor`), and the duplicate handlers were removed |
| Setup guide called `/api/v1/pipelines` | 404 on every visit | the route lives under `/api/v1/ci/pipelines` |
| No way to create a finding from the console | The backend had `POST /findings` (and the report claimed manual creation) but the screen only listed findings | Findings → *new finding* dialog: kind, severity, path/line, CWE, impact, reproduction, recommendation, assignee |

## Deliberately not covered here

- Scanners, sensors, CI/CD execution and provider sync: not part of v0. The
  SAST and SBOM documents are **imported**, and the console says so.
- Multi-operator concurrency and mobile widths.
- Browser matrix: this pass ran in one Chromium session.

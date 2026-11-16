# CTEM cycle flow — the model, what OpenCTEM runs, and what Barad-dûr must manage

Audit date 2026-11-09. Read-only review of the upstream tree at
`/Volumes/980PRO/Workspace/Councilbox/CYB/openctem` (GPL-3.0, concepts only, no
code copied) plus the live installation of this repository. Numbers were read
from `barad_platform`, not from memory.

The question this answers: *what has to exist so a CTEM cycle is a campaign with a
plan and a verdict, instead of a folder that lists screens?*

## 1. How OpenCTEM runs the loop

**It has no cycle.** `grep -ri cycle api/` returns two CI quarantine scripts and
nothing else: no `cycles` table, no campaign entity, no time-boxed evaluation. The
loop is not an object there, it is a set of mechanisms:

| Mechanism | Upstream | What it decides |
|---|---|---|
| Coverage ledger | `pkg/domain/coverage`, RFC-093, `asset_coverage` | per (asset, capability, vantage): state `due/queued/covered/failed/blocked/paused/not_applicable`, reason, last attempt/success, next due, failure streak |
| Coverage policy | `configs/asset-types.yaml` → `coverage:` | what each asset **type** needs and how often: `{capability: probe.http, every: 3d, requires: [web_port], expects: http_service}`, cadence in [1h, 30d] |
| Due marking | ingest, same transaction as the asset write | a new or changed asset becomes work without a scheduler sweep |
| Planner | `coverage/planner.go` | due pairs → one run per capability through the scope gate; batch 200, daily budget 5000, blocked recheck 6h, stall 24h, jittered due times |
| Scope gate | `scopeauth`, `scangov` (approval modes, ceilings), `scanwindow` | the only authority; a refusal is `blocked` **with its reason**, never a silent skip |
| Gap detection | `coverage/alerts.go` | a required pair uncovered for >2× cadence, or a capability producing zero outputs over ≥20 inputs / 3 consecutive failures |
| Explanation | `GET /assets/{id}/coverage` | per asset: what was done, what is due, why something was skipped |
| Priority | RFC-017 `ClassifyPriority` | `priority_class` P0–P3 + reason, computed at ingest, reclassified on EPSS/KEV/criticality change — a property of the finding, not a phase |
| Validation / closure | RFC-011 retest, RFC-015 remediation groups, ticketing | separate domains that consume findings |

Why the ledger exists is measured in the RFC itself: on a live install **92 of 94
open web ports were never HTTP-probed**, 34 of 105 subdomains were never a target
of the port/HTTP/template stages, **292 derived targets were refused as
unconfirmed and 288 confirmed later were never offered again**, and none of it
raised an alert. A campaign object catches none of that; an obligation with a due
date does.

Its console, however, is twenty sidebar entries (Discovery 8, Prioritization 9,
Validation 6, Mobilization 4 — with the cycle itself absent from the tree). That
is a module map, not a loop: `IOCs`, `Detections` and `Control testing` are other
products' surfaces parked here. **We take the mechanisms, not the inventory.**

## 2. The model, corrected

The owner's map is right in substance and conflates three different things. Split
them and the missing work becomes obvious.

### 2.1 Two layers: standing vs temporal

**Standing — true until someone changes it:**

| Inventory | Question | Where it lives today |
|---|---|---|
| Assets & components | what do we have, and what is it made of? | `assets`, `components`, `deployments`, `observations` |
| Crown jewels | what matters, and how much? | **missing** — `impact.py` answers `criticality: "not modelled"` |
| Authorization | what may we do, to what, as whom? | `scope_targets` + `scope_exclusions` + `scan_grants` |
| Threat model | for this jewel, which techniques threaten it, and which capability tests each? | **missing** — nothing maps an ATT&CK technique to a capability |

**Temporal — true for one window:** the cycle. It freezes a subset of those
standing inventories plus a technique plan, measures the window, records a
verdict, and carries the remainder forward.

### 2.2 Two kinds of cycle, one object

- **Sweep** — the whole estate, every capability, a quarter. Answers "is the
  inventory still true, and did anything appear?"
- **Campaign** — one technique family against one subset, a couple of weeks. The
  owner's example: *npm supply-chain attack against `aurea`'s builds* = technique
  T1195.002 → capability `code_analysis` + dependency-confusion checks → frozen
  members = aurea's builds → verdict = findings found vs builds actually analysed.

Both are the same `cycles` row. What differs is the charter (`kind`, `techniques`,
`profile`, `capabilities`) and the selection. Without this distinction a cycle
becomes a folder holding everything and the review has nothing to judge.

### 2.3 The pipeline, in the order the decisions actually happen

1. **Scope** — declare what is ours (`scope_targets`) and what may be done to it
   (`grants`). Standing, never per-cycle. A cycle never grants.
2. **Business context** — mark the jewels (`criticality` per asset, plus the
   business service that depends on it). This is what makes a CVE on one host
   different from the same CVE on another, and it is the **prerequisite** for
   everything downstream: no jewels, no campaign target, no path worth drawing.
3. **Threat model** — per jewel class, the techniques that threaten it, each mapped
   to the capability that can test it. It is the plan's source, and it is what
   turns "ATT&CK coverage" into an **output** (techniques testable ÷ techniques
   declared) instead of a screen nobody can fill.
4. **Cycle (charter + activation)** — subset × techniques × profile × window ×
   success criteria; preview what activation freezes and what it cannot test (no
   grant, no capability); activate.
5. **Discovery & validation** — the execution plane runs the capabilities; every
   run cites the technique it closes; findings created in the window on frozen
   members link to the cycle. A finding outside the reference is a *candidate*, and
   the review must say how many appeared outside — freezing a reference has a blind
   spot, and hiding it is the defect.
6. **Per-finding decision** — dismiss / accept (remediate, mitigate, transfer) /
   defer, each with a reason. This already exists as `triage_status`; it is not a
   cycle phase, it is the decision the cycle counts.
7. **Review & close** — per criterion `met / not_met / not_measurable` **with the
   number behind it**, technique coverage (`ran / blocked / never attempted`), delta
   (created / settled / still open), learnings. Close carries forward: unrun
   techniques, never-observed assets, un-triaged findings → the next cycle's draft.

The correction to the owner's sentence "citar los fallos descubiertos a este
ciclo": a finding belongs to the cycle if it was **created in the window on a
frozen member**. Auto-link already covers frozen projects; what is missing is the
*outside* count, so the review can say "12 more appeared outside the reference",
which is the honest reason the next cycle is bigger.

### 2.4 A run declares its cycle, and what it finds is not yet truth

The owner's rule, made mechanical: **a tool is launched *into* a cycle**, and a
run's output is a claim, not a fact about an asset.

- `scan_jobs.cycle_id` is set at launch. The console's scan dialog requires it for
  any active profile (`recon`, `deep recon`, later the heavy ones); system jobs
  (`internal-scan`, advisory clock, coverage enrichment) are exempt because they
  are not somebody's campaign. Claim re-checks it the way it re-checks scope: a
  target that is not a frozen member of that cycle is refused **with the reason**,
  and the run stays `queued` instead of quietly scanning the wrong estate.
- A run produces **three** different outputs, and conflating them is what makes
  the ledger lie: **observations** (facts — port 443 open, nginx 1.24, cert 12 days),
  **candidates** (a host we did not know we had → an ownership decision, not a
  finding), and **findings** (a claim that needs validation). A recon profile
  produces zero findings *by design*; deep recon produces more observations, not
  more findings. Only validation profiles produce findings, and even those arrive
  unvalidated.
- Findings land with `triage_status='new'`, `asset_id = NULL`, attached to the
  **run and the cycle** (`origin_run_id`, `cycle_id`). Promotion is the validation
  step: a human (or a validation run) sets `asset_id` + `evidence_level`, and only
  then does the finding appear on the asset page and count toward posture.
- The dedupe key has to change with it: today's fingerprint is
  `org|project|rule|where`, and an unattached finding has no project. For
  cycle-origin findings the identity is `org|target|rule` (plus cycle when the same
  claim may legitimately recur in a later cycle) — otherwise every run of the same
  path mints a new row.

**What this breaks today, verified:**

- `routers/surface.py:528-545` **drops** every finding whose asset has no project
  (`unattached`, no row written). With 261 of 274 assets unattached, a deep recon
  of this estate writes zero findings rows — the exact opposite of the rule above.
- `Finding.triage_status` defaults to `triaged`, so unvalidated scanner output is
  already inside `COUNTED_TRIAGE` and counts toward posture (572 rows). The
  default has to be `new` for scan-origin rows, which `ctem.py` already knows how
  to exclude.
- `ScanJob` has no `cycle_id`, and `surface_triage` sets the finding's status but
  never attaches the asset, so "validate" today means "acknowledge", not "this is
  now a fact about this host".

### 2.5 Two keys, three rungs: the machine raises evidence, the human decides

The owner's rule: Shauron may pre-validate *anything*, and a human still has the
last button. Made mechanical, that is not one "validated" state but a ladder where
each rung has exactly one owner:

| Rung | Column | Who can move it | What it means |
|---|---|---|---|
| `observed` | `evidence_level` | any collector | a tool reported it; nothing was retried |
| `demonstrated` | `evidence_level` | **machine only** | a run reproduced it and stored the evidence (`evidence_id`); a human clicking cannot manufacture proof |
| `confirmed` / `rejected` / `accepted` | `triage_status` | **human only** | this is real, and it is ours — the asset link, the posture count and the SLA clock start here |

Rules that follow, and that the UI must not blur:

- **The machine never sets `triage_status`.** A pre-validated finding stays `new`
  with a badge `reproducido por Shauron` + the run id; it is *in the queue*, not
  settled. `COUNTED_TRIAGE` stays the human-only gate, so posture never counts a
  claim nobody confirmed.
- **The human never sets `evidence_level='demonstrated'`.** Confirming a
  `hypothesis` is allowed and honest ("I believe this, nothing reproduced it") —
  which is why the two axes exist.
- **Both words are visible, never one badge.** "Reproducido por Shauron" and
  "confirmado por <user>" are different sentences; collapsing them into a single
  green tick is how a pre-validated row reads as decided.
- **A re-run cannot overturn a human.** Re-observing a rejected finding appends an
  occurrence and bumps `occurrences`; it does not flip the status. Reopening needs
  new *evidence kind* (a demonstrated reproduction where there was none), it is
  audited, and it lands back in the queue as `new` with the previous note kept.
- **The queue is ordered by machine evidence**, never by recency: demonstrated +
  crown jewel + KEV first, then demonstrated, then observed-by-two-sources, then
  hypothesis. With 317 open rows the human's last button is only viable if the top
  20 are the ones that matter, and batch confirm is still a human click.

**Triage debt.** A cycle can close with 40 `demonstrated` and 0 `confirmed`. That is
not a passing review — it is triage debt, and the review criterion "all findings
decided before close" is `not_met` with the number `40/0` behind it.

## 3. What each phase holds, and what it earns

Mapping the owner's list and the upstream sidebar against this repo. **BUILD** =
nothing exists, **FOLD** = exists and must not get its own screen, **HAVE** =
shipped, **SKIP** = not this product.

### Scope

| Item | State | Verdict |
|---|---|---|
| Scope targets + exclusions | `routers/scope.py`, `Scope.jsx` | HAVE |
| Grants | `scan_grants`, Grants screen (8 active, 1 revoked) | HAVE |
| Business context / crown jewels | `impact.py` says `criticality: "not modelled"`; no field on `Asset`, no business-service → asset mapping | **BUILD (data)** |
| Threat model → ATT&CK → capability | nothing; the AI harness's `discover/validate/exploit` lanes are tool lanes, not attacker profiles | **BUILD (data + one panel)** |
| Cycle definition | `cycles` API complete, 0 rows, no UI flow | **BUILD (flow)** |

### Discovery

| Item | State | Verdict |
|---|---|---|
| Scans | Orchestration + surface runs | HAVE |
| Sensors | `workers` + heartbeat, shown in Orchestration | FOLD |
| CI/CD | `CiPipeline` / `CiRun` + Gates | HAVE |
| Attack surface | web endpoints, lookalikes, review | HAVE |
| Assets | Assets + `#asset::<id>` | HAVE |
| Exposures | `exposure_events` + decisions + `exposure_verdict` | HAVE |
| Credential leaks | secret findings exist per build (`code.secrets`); no leak surface; Shauron has the scanner | **BUILD (tab, not screen)** |
| Components | SBOM + versions | HAVE |

### Prioritization

| Item | State | Verdict |
|---|---|---|
| Priority rules | `lifecycle.py` rules tab, first-match-wins | HAVE |
| Threat intel (KEV/EPSS/NVD) | `intelligence.py`, daily clock | HAVE |
| Emerging threats / advisories | `advisories.py`, notification channel, in-app bell | HAVE |
| Business impact | counts only, no criticality | FOLD into business context |
| Exposure chains + attack paths | nothing; `AssetLink` + `FindingContext` are the substrate, no query computes reachability to a jewel | **BUILD (one screen)** |
| Compensating controls | nothing | SKIP until jewels + paths exist (then one boolean + reason per asset) |
| IOCs / Detections | nothing, no feed | SKIP — different product (SIEM) |

### Validation

| Item | State | Verdict |
|---|---|---|
| Overview | the cycle workspace (to build) | **BUILD** |
| Pentest campaigns | `PentestEngagement` + Pentest screen | HAVE |
| Attack simulation | surface runs + Missions, `exploit` gated by `redteam_allowed` **and** a grant | HAVE — name it honestly |
| Retest queue | `retest_pending` inside pentest | FOLD |
| Control testing | nothing, and nothing to test | SKIP |
| ATT&CK coverage | nothing | **BUILD as a cycle panel** (technique → capability → last run) |

### Mobilization

| Item | State | Verdict |
|---|---|---|
| Remediation | `RemediationTask` + screen | HAVE |
| SLA compliance | `SlaPolicy` + lifecycle | HAVE |
| Exceptions | suppressions + license exceptions | FOLD (one place in Findings) |
| Automations | schedules, notifications, Jira outbox | SKIP — nothing new earns a screen |

**Net: three screens to build** (paths to jewels, cycle workspace, credential-leak
tab), **two data models** (asset criticality + business service; technique →
capability map) and **one measurement endpoint**. Twenty upstream entries collapse
into these without losing a question a reader actually asks.

## 4. Live state (2026-11-09)

```
cycles                 0 rows (every state)
scope_targets          5 active, all `domain`      exclusions 2
scan_grants            8 active, 1 revoked
projects               2      builds 13      components 623      deployments 4
assets                 274 (273 domain, 1 url)   with any observation: 8
                       without a project: 261   aurea 11 · juice-shop 2 · none 261
observations           352 (port 119 · technology 63 · dns 56 · host 28 · cert 28 · web_path 50)
web_endpoints          0      inventory_groups 0      services 0
findings               577: open 317 · closed 254 · false_positive 5 · acknowledged 1
                       triaged 577 · ranked (priority set) 556
pentests 0 · regression 0 · jira 0 · exposure_events 10 · analysis_runs 28
alembic                0059_mission_profile
```

The estate is wide and shallow: 274 assets, 8 observed, 261 unattached, zero
validation and zero mobilization artefacts. A percentage over that denominator is
not progress, it is a fill with nothing behind it.

## 5. Defects the flow would inherit (verified)

1. **Two status vocabularies.** `findings.status` holds `closed` (254, written by
   `scripts/dedupe_advisory_findings.py:81`) and `resolved` (0, the word
   `routers/findings.py` allows). `ctem.py`'s `NON_OPEN` omits `closed`, so closed
   findings count as open (**572** instead of 317) and `resolved` counts **0**
   although 254 are settled. Mobilization is wrong in both directions.
2. **`/ctem/overview` has no cycle dimension** — it cannot answer "progress inside
   the window"; a review would be typed by hand while the platform holds the data.
3. **`Cycles.jsx` is a table plus an inline `<dl>`**: the selection prints as
   `JSON.stringify`, the frozen membership is never listed, the preview canvas is
   discarded except for one count, and charter criteria are free text with no link
   to what was measured.
4. **Selection is a CSV of slugs in a dialog.** With 261 unattached assets and 0
   groups, typing is the only way in — no picker, no counts, no "what would this
   freeze" before the click.
5. **Candidates are one-way.** `GET /cycles/{id}/candidates` lists what appeared
   after the snapshot; nothing opens the next cycle from them, so the loop does not
   close, it restarts from zero.

## 6. Decisions

| # | Decision | Status |
|---|---|---|
| D1 | **The cycle is an accountability frame, not a scheduler.** Cadence, dispatch and authorization stay with orchestration + grants + Shauron. A cycle freezes a reference, measures the window, records a verdict and carries the remainder forward. | recommended |
| D2 | **Everything a cycle reports is restricted to its frozen membership**, denominator fixed at activation, `unknown` for anything never observed. Org-wide numbers stay on `Cycle overview`; the two never mix. | recommended |
| D3 | **No cadence, no due dates, no planner inside the cycle.** A per-asset obligation ledger (asset × capability × state + next due) is the engine, built after the cycle flow; the cycle reads it, never the reverse. | recommended |
| D4 | **Review verdicts are pre-filled from the measurement** (met / not_met / not_measurable, each with the number behind it); a human overrides with a note. | recommended |
| D5 | **Close carries forward**: candidates + never-observed members + unrun techniques become the next cycle's draft, with the previous learnings as charter defaults. | recommended |
| D6 | **One canonical finding-status vocabulary** before Mobilization can be measured: `closed` or `resolved`, never both. | **open** |
| D7 | **Cycle selection ≠ scope target ≠ grant.** Three facts, three owners; the cycle shows the gaps (selected-but-undeclared, declared-but-ungranted, granted-but-unselected) instead of collapsing them. | recommended |
| D8 | **The crown jewel is a component** — `AUREA > Backend`, not `AUREA` and not a domain (`application_components.criticality`: `crown/high/normal/low` + `business_service` + `criticality_reason`). A project is a container; a component is what the business runs. Deployments, environments and assets hang off the judgement; findings are attributed to the project today and the screen says so instead of splitting a number nobody measured. Only registered components are listed. | decided (revised x2, implemented) |
| D9 | **The threat model is a table, not prose**: `threat_entries (jewel, ATT&CK technique, why)` against a seeded `attack_techniques` catalogue that names the capability able to test each one (`NULL` = nothing we run can reach it). Coverage is arithmetic — declared / testable / ready (capability granted) / blocked / untestable — and `ran` stays **unmeasured** until a run cites the technique it closed, never `0`. | decided (implemented) |
| D10 | **Two cycle kinds, one object**: `sweep` (estate-wide, all capabilities) and `campaign` (one technique family, one subset). The review judges differently — sweep = inventory still true; campaign = technique confirmed or refuted. | recommended |
| D11 | **Reachability is computed, never typed**: a path is a chain of existing `AssetLink` edges ending at a jewel, each hop citing the finding/observation that supports it. No path without a jewel — which is why D8 comes before the paths screen. | recommended |
| D12 | **Fold, don't mirror.** Credential leaks = a tab in Exposures. Sensors = Orchestration. Retest = Pentest. Exceptions = Findings. IOCs, Detections, Control testing = not in this product. | recommended |
| D13 | **Every tool run declares its cycle** (`scan_jobs.cycle_id`): the scan dialog requires it for active profiles, the claim re-checks that each target is a frozen member and refuses with the reason. System jobs (advisory clock, enrichment) are exempt — they are not a campaign. | recommended |
| D14 | **A run's findings are claims, not facts**: `triage_status='new'`, `asset_id` NULL, attached to run + cycle; the asset link happens at validation. Ingest keeps every finding — a finding on an unclaimed host is the normal case in this estate, not a reason to drop the row. | recommended |
| D15 | **One run, three outputs**: observations (facts), candidates (an ownership decision), findings (a claim to validate). Recon and deep recon produce no findings by design, and their run screen says so instead of rendering an empty card as a failure. | recommended |
| D16 | **Two keys, three rungs.** The machine may raise `evidence_level` to `demonstrated` and never touches `triage_status`; a human confirms / rejects / accepts and never claims `demonstrated`. Posture, the asset link and the SLA clock start at human confirmation. The UI shows "reproducido por Shauron" and "confirmado por <user>" as two facts, never one badge. | recommended |
| D17 | **A re-run cannot overturn a human.** Re-observation appends an occurrence and bumps the count; reopening a rejected finding requires a new evidence *kind*, is audited, and returns it to the queue as `new` with the previous note kept. | recommended |
| D18 | **A cycle declares its kind**, from a closed set: `sweep`, `campaign`, `pentest_external`, `pentest_internal`, `supply_chain`, `ai_redteam`. The kind is what the KPI is bucketed by and what the review is judged on, so it is set at creation and frozen at activation. A typo may not invent a bucket. | decided (implemented) |
| D19 | **A hand-written vulnerability is a claim too.** `POST /cycles/{id}/findings` records it with `origin='manual'`, `triage_status='new'`, linked to the cycle's ledger, idempotent on its identity, and refused on a closed cycle. Typing a finding is not confirming it — the human key is still a separate act. | decided (implemented) |
| D20 | **A pentest report enters as claims against a cycle**, not as a parallel object. `pentest_engagements` keeps the vendor, scope and dates of an on-site engagement; the report's findings are recorded/imported into a `pentest_external|pentest_internal` cycle, where the same two keys apply. Two ledgers for one report is the defect to avoid. | recommended |
| D21 | **KPIs read the cycle ledger by kind**: claims / reproduced / confirmed / rejected, time-to-confirm, and coverage of the frozen set. No score is invented; a KPI is a count with its denominator and the window it was counted in. | recommended |
| D22 | **A report file is evidence before it is data.** Upload the PDF/DOCX as an attachment on the cycle, and let extraction produce *draft* claims a human files — never rows written straight from a parser. PDF extraction is the last mile, not the first: a wrong finding invented by a parser is worse than a slow upload. | recommended |
| D23 | **Activation freezes a snapshot, not the charter.** The live charter stays amendable while the cycle is open (`kind` and `selection` do not: the KPI bucket and the membership are frozen). The review judges the **frozen** charter, and the screen says `amended` out loud, so a mid-flight change cannot move the goalposts silently. | decided (implemented) |
| D24 | **Sidebar structure follows the loop the owner drew**: `Scoping` holds Cycle overview, Cycles, Scope, Crown jewels (and Threat model next); `Discovery` holds the inventory surface (Applications, Assets, Attack surface, Components, Exposures). Renaming `Inventory` to `Discovery` was the correction; renaming `Scoping` to `Discovery` was my misread and is reverted. | decided (revised, implemented) |
| D25 | **The crown-jewel screen is a short list with a search, not a registry.** It shows only the components somebody designated; the rest are reached through `GET /business-context/candidates?q=`, which is the designation picker. A wall of undecided rows is the defect the owner named twice ("solo veo lo que creé"), and `?all=1` exists for audits, not for the screen. | decided (implemented) |
| D26 | **Attacker profiles are org-scoped bundles of techniques**, not a free-text field on a cycle: a profile outlives one window, and a cycle cites it. Profiles are created on the Threat model screen next to the techniques that give them their meaning. | decided (implemented) |
| D27 | **The cycle is where the three inventories meet**: `selection.components` (crown jewels) + `charter.profile_ids` (attacker profiles) → the plan derives every technique declared on those jewels, adds the ones a profile names, and scores each ready / blocked / untestable against the grants that exist. Activation freezes that plan next to the membership, so a review can say what was *intended* as well as what ran. | decided (implemented) |
| D28 | **A cycle is created whole**: the create form takes jewels, profiles, notes and (after creation) documents, and previews the plan's coverage *before* the cycle exists (`POST /threat-model/plan`, stateless). A scope letter or a pentest report is kept as bytes on the cycle (`cycle_documents`, 20 MB cap), not as a link that rots. | decided (implemented) |
| D29 | **The scope is written, not browsed**: `GET /cycles/scope-search?q=` searches assets, projects and repositories at once, and a selection may name **one asset** or **one repository** (`selection.assets`, `selection.repositories`), not only whole projects. A single host is a valid campaign. | decided (implemented) |
| D30 | **The charter is a form, not a read-only report**: labelled fields with a hint per block and one save button; notes and documents save on their own. The old `dl` + modal pair hid what to do. | decided (implemented) |
| D31 | **A hand-written finding is a record, not a title**: CWE class, product (the crown jewel, not the domain), method + endpoint, whether it needs a session, the raw request and response, expected vs observed, the validation output, impact and numbered reproduction. `auth_profiles` holds the session recipe once and every finding of the engagement references it (`auth_profile_id`); a profile in use cannot be deleted. The endpoint is part of the fingerprint: the same weakness on two endpoints is two findings, the same endpoint twice is one claim. | decided (implemented) |

D6 is the only row this document cannot settle alone: it is a data migration on
254 live rows and the owner's call is which word survives.

## 7. Phases and acceptance

**P0 — the standing data and the run binding (no screens).** `assets.criticality` +
`business_service` + reason; `threat_techniques` (ATT&CK id → capability → asset
class); canonical finding status (D6); `scan_jobs.cycle_id` + `findings.cycle_id` /
`origin_run_id`; ingest stops dropping findings on project-less assets, writes
`triage_status='new'` / `asset_id` NULL, and keys the fingerprint on
`org|target|rule` when the finding has no project. Acceptance: every asset answers
criticality or the honest `unclassified`; every technique names a capability that
exists in `surface_catalog`; `ctem.py`, `gates.py`, `pipeline.py`, `sbom.py` and the
dedupe script agree on the status list, pinned by a test; a run against a host with
no project creates a finding that appears in that cycle's delta and on **no** asset
page, and validating it is what attaches the asset; re-running the same profile on
the same target does not mint a second row.

**P1 — cycle charter and the picker.** *(kind and manual entry shipped: D18/D19.)*
Charter gains `techniques[]` and `profile`; the picker offers projects, assets,
groups, deployments with counts; preview says what can be tested (capability
granted) and what cannot (no grant → the reason, linking to Grants). Acceptance:
activating freezes exactly the previewed set; a technique with no granted
capability appears as `blocked` with the grant that would unblock it; the frozen
membership list matches `cycle_memberships`.

**P1b — a report becomes draft claims.** Upload a PDF/DOCX to the cycle as an
attachment (evidence), then file claims from it — one by one, or a pasted table.
Acceptance: the attachment is stored and readable from the cycle; a filed claim
carries `origin='manual'` and the attachment id; nothing is written from a parser
without a human filing it.

**P1c — cycle KPIs** (`GET /api/v1/cycles/{id}/kpis`). Per kind: claims,
reproduced, confirmed, rejected, time-to-confirm (median, only over decided rows),
and coverage of the frozen set. Acceptance: every number is a count with its
denominator and window; a kind with no closed cycle answers `null`, not `0`.

**P2 — `GET /api/v1/cycles/{id}/progress`.** Per phase over the frozen members:
coverage (observed / never observed / no answer), discovery (components, imports
since activation, new assets inside and *outside* the reference), ranking (open,
ranked, KEV, awaiting triage), validation (grants covering members, runs, exposure
events, pentests), mobilization (settled, past SLA, tickets), plus technique
coverage. Acceptance: every number equals the same SQL over the frozen set; a
member with no observation is `unknown`, never `clean`; the response names its
denominator; `claims`, `reproduced` and `confirmed` are three separate counters,
and triage debt is the gap between the first two and the third.

**P3 — the cycle workspace** (`#cycles::<id>`). Verdict line, phase rail, technique
coverage, frozen membership with type/state, findings linked and the outside count.
Acceptance: no percentage without a denominator; `scrollWidth == clientWidth` at
620px; the review's verdicts arrive pre-filled and the override is audited; a
pre-validated finding renders `reproducido por Shauron` with its run id and still
sits in the queue, and pressing confirm is the only thing that moves it to
`confirmed` and onto its asset.

**P4 — paths to the jewels** (`#paths`). Chains of existing links ending at a crown
jewel, each hop citing evidence, ordered by "exposed → jewel" and not by a score.
Acceptance: a path with no crown jewel at the end is not drawn; an unobserved hop
is `unknown` and breaks the chain visibly; two hops deep reads without a legend.

**P5 — coverage ledger** (`asset_coverage` shape). Read-only first, fed by the
collectors; planner and gap alerts after it has data. Acceptance:
`GET /assets/{id}/coverage` explains every capability as covered / due / blocked
with reason / never attempted.

## 8. Anti-goals

- A cycle that owns a cron: two schedulers, two answers to "what ran".
- Percentages over members nobody observed. 8 of 274 is `unknown`, not `3%`.
- A frontend copy of the phase logic; `ctem.py` derives, the cycle endpoint reuses
  it with a membership filter.
- Cycles as authorization — already true in code, and the UI copy must say it.
- Mirroring upstream's twenty entries. Twenty screens is how a loop becomes a menu,
  and a menu is what the owner refuses.
- Reproducing sensor/zone/vantage machinery before the ledger has data.
- A "risk score" invented before criticality exists.

## 9. Open questions

1. D6 — which status word survives, `closed` or `resolved`?
2. Does a cycle close on `ends_on` automatically (state `review` + notice), or only
   when a human says so? Auto-close on a date hides work.
3. Does the first real cycle need to be a `campaign` (npm against aurea) or a
   `sweep` (estate-wide)? The answer decides whether P1 ships precision or breadth
   first.

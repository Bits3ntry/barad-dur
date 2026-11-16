# UI/UX audit and redesign record — console

Branch: `feat/console-redesign`. Scope: the React console in `frontend/src`
(65 screens), served by nginx at `:8092`.

This document records **what was wrong, how it was measured, what changed, and
what is still open**. The rules that came out of it are in
[`console-design-system.md`](./console-design-system.md); the captures are in
[`captures/`](./captures).

## Method

1. Read the live console at 1600×1200 in both themes (signed-in profile, real
   data — 273 assets, 572 open findings, 5 KEV).
2. Read the CSS as it actually layers: three successive visual passes, later
   rules overriding earlier ones (`.sev`, `.nav-item`, `.card` and `.metric` are
   each defined three times).
3. Measured instead of eyeballing: computed colours and WCAG ratios, element
   rects (`getBoundingClientRect`), `scrollWidth - innerWidth` at five widths,
   `document.activeElement` + `outline` after real Tab key events, and
   `transitionDuration` under emulated `prefers-reduced-motion`.
4. Compared against `HEAD` (`fdbb8d0`) rendered from a throwaway worktree and
   the vite dev server against the same live API, so before/after differ only
   in code.

## Findings

Severity is the cost of leaving it: **A** blocks the screen's job, **B** costs
work on every visit, **C** polish.

| # | Sev | Finding | Evidence | Status |
|---|---|---|---|---|
| A1 | A | **Canvas and card were the same colour.** Light theme had `--bg: #ffffff` *and* `--panel: #ffffff`; dark had `#11141b` vs `#191e28`. Every surface depended on a hairline border, which is why the console read as flat. | card/canvas ratio measured **1.00** (light) / **1.08** (dark) | fixed → 1.16 both themes; cards now separate with the border removed |
| A2 | A | **Row actions looked like text.** `.table-wrap td button` and `.card .row > button.mini` were reset to `background:none; border:none; padding:2px 6px` by the "calm details" pass. `deploy`, `refresh`, `open findings` were indistinguishable from cell values. | `styles.css:1300-1306`, `1339-1343` | fixed: row actions are compact chips; `.mini` is a bordered control everywhere |
| A3 | A | **The dashboard had no primary action.** 14 equal cards; the 8 KPI tiles in "Scope and coverage" mixed inventory (assets, CVEs) with risk (open findings) at identical weight; the only solid-fill control on the screen was the Shauron launcher. | screenshot `captures/before-dash-dark.png` | fixed: one verdict hero with one solid CTA, risk band, coverage band, trend band, operations band |
| A4 | A | **Severity badges were text, not chips.** `.sev-critical { background: var(--panel); color: var(--critical) }` (a later pass) overrode the solid badge the first pass defined, leaving coloured text on the same surface as the row — no shape, no weight, colour-only meaning. | `styles.css:698-701` vs `1266-1274` | fixed: tinted chip + leading dot + name; tint text ratios 6.4–8.0:1 |
| A5 | B | **Priority reused the severity palette.** The exposure-flow donut drew P0/P1/P2/P3 with `--critical/--high/--medium/--low`, so a ranking looked like a severity and P0 looked like a critical finding. | `ExposureFlow.jsx` `PRIORITY` | fixed: one-hue rank ramp (`--rank-p0..p3`), severity keeps four hues |
| A6 | B | **Focus was invisible.** `:focus-visible` used `box-shadow: 0 0 0 3px rgba(17,24,39,.14)` — 14% black on a pale ground. | `styles.css:61` | fixed: 2px solid ring, 2px offset, both themes (verified by Tab) |
| A7 | B | **Charts used GitHub-era hex values** (`#ff7b00`, `#8b949e`, `#30363d`): gridlines were near-black dashes on white, and the palette clashed with the ember brand. | `Charts.jsx` pre-change | fixed: every fill/stroke resolves to a token |
| A8 | B | **Typographic scale was contradictory.** `.card-title` was 11.5px uppercase/1.2px tracking in one layer and 13px sentence case in another; labels ranged 9.5–11.5px across files. | `styles.css:523`, `1236`, `1283` | fixed: one scale in §6 of the design system |
| A9 | B | **A component with 0 analysed builds looked identical to a healthy one**, and the version table's `—` did not distinguish "no analysis recorded" from "zero". | `Projects.jsx` component header | fixed: `never analysed` / `N/M analysed` chip with tone + tooltip; `—` carries a tooltip saying it is not zero |
| A10 | B | **The disclosure caret was a 9px text glyph** (`▸`/`▾`) with no box: at 1600px it rendered as a dot, so component cards did not read as expandable. | measured caret box 9×17, colour `--muted` | fixed: 20×20 boxed chevron that rotates, accent when open |
| A11 | B | **The version table widened the page at 620px.** Bare `<table>` inside a grid child with default `min-width:auto` pushed `.component-block` to 602px inside a 556px column. | `scrollWidth - innerWidth` = **+35px** at 620px | fixed: `min-width:0` down the chain + table scrolls inside its card; now 0 at 480/620/900/1280/1600 |
| A12 | C | **Density only changed tokens.** Table cells were hardcoded `13px 14px`, so `compact` barely differed from `comfortable`. | `styles.css:1262` | fixed: density-specific padding/size rules |
| A13 | C | **No `prefers-reduced-motion` handling.** Shimmer and transitions ran regardless. | — | fixed: global collapse to `0.01ms` (verified) |
| A14 | C | **A card that only said the feature does not exist** ("Quality gate verdict history — requires the backend"). It carried no information and undermined trust in the rest. | `Dashboard.jsx` | removed; the gate verdict banner above it already states the current verdict |
| A15 | C | **The assistant competed with the primary action.** A solid ember pill, bottom-right, was the loudest element on every screen and covered the last card's actions. | `captures/before-*.png` | fixed: neutral 42px round launcher; the solid fill belongs to the screen |

### Data observations (not design defects, not fixed here)

Reading the live estate surfaced numbers that disagree with each other:

- `open findings` 318 in the v0 scope card vs 572 in the findings summary —
  different definitions (v0 counts what the estate holds, the summary counts the
  open queue).
- Exposure-flow sources sum to 574 while `received` says 577 (sources are capped
  at five).
- Portfolio critical/high sums (17/161) do not equal the org-level open
  severities (25/232) because the portfolio counts the **latest** version per
  project by design.

These are answered in the API/serializers, not in CSS. They are listed here so
the next pass fixes them at the source instead of "correcting" the UI.

## What changed

### Design system (all 65 screens)

`styles.css` grew a final, documented layer (`DESIGN SYSTEM v2`, §1–§15) that
re-declares the palette, maps the legacy tokens onto semantic ones, and redefines
the primitives: buttons (4 tiers + icon + group), tables, badges, KPIs, tabs,
banners, empty states, dialogs, forms, focus, motion and density. Because it
sits last and uses equal-or-higher selector weight, the existing 3.5k lines
inherit it without being rewritten.

`ui.jsx` gained `Card band`, `Stat quiet` and `Stat onClick` (a KPI that is a
door renders as a button). New CSS primitives: `.btn-group`, `.icon-btn`,
`.eyebrow`, `.card-band`.

`Charts.jsx` was rewritten around tones/tokens and now prints its own values
(bar values above the bars, min/max on the line axis) — a chart without a scale
is decoration.

### Dashboard (pilot 1)

Reading order is now: **verdict → priority risk → coverage → portfolio → trend →
operations**.

- `posture-hero`: one state word (`action required` / `monitoring` / …), one
  sentence, three supporting facts, and the screen's only solid button
  (`Review 5 exploited` → `#vulnerabilities::kev=1`, which now opens the list
  pre-filtered).
- `Priority risk`: four KPIs that all mean "do something"; zeros are recessed
  (`quiet`) so the two that matter dominate.
- Coverage band: inventory counts as doors + the record gaps, which now carry a
  warning tone when they are non-zero (272 of 273 assets have no owner).
- Portfolio table: identity column, right-aligned numbers, rows are links to the
  project scope.
- Trend band: three charts, all tokenised, all with printed values.
- Operations: the two job-status blocks merged into one section (they answered
  the same question twice).
- Removed: the 8 equal tiles, the "quality gate history" placeholder, the
  duplicate scanner-health counters.
- Height at 1600px: **2953px → 2143px** (−27%) while showing the same facts.

### Projects → Components (pilot 2)

- Card head with `expand all / collapse all` as a group and `add component` as
  the primary.
- Each component is a card: boxed chevron, name + `N versions · N repositories`,
  a coverage chip (`never analysed` / `2/11 analysed`, toned), the severity bar
  of the newest build, and `new version`.
- Open state is an accent rail + stronger border, so "expanded" is legible
  without reading.
- Version rows: the version label is an underlined monospace identity that opens
  the build; `deploy` is a compact chip; `—` in the source columns explains
  itself.
- The whole block now survives 480–1600px without pushing the page.

## Verification

| Gate | Command | Result |
|---|---|---|
| Build | `npm run build --prefix frontend` | ✓ (96 modules, bundle unchanged in shape) |
| UI import check | `make lint` | ✓ `UI import check passed (65 screens)` |
| Backend suite | `cd backend && ../.venv/bin/python -m pytest -q` | ✓ **588 passed, 1 skipped** (163s) — no backend change |
| Route sweep | 29 routes in the live console | ✓ every screen renders (h1 present, `#root` non-empty), no error banner, no horizontal overflow |
| Widths | 480 / 620 / 900 / 1280 / 1600 px on both pilots | ✓ `scrollWidth - innerWidth = 0` |
| Contrast | computed styles in both themes | ✓ muted ≥ 6.2:1 light / 7.3:1 dark; labels ≥ 4.7:1; control borders ≥ 3.6:1 |
| Keyboard | 3 × Tab in the live app | ✓ `outline: solid 2px`, offset 2px, on brand, org switcher and nav |
| Reduced motion | CDP emulation | ✓ transitions compute to `1e-05s` |
| Density | `barad.density=compact` | ✓ row/header padding and metric size change |
| Both themes | every pilot captured in light and dark | ✓ `captures/after-*.png` |

Transient during the run: `platform-api` restarted (unrelated process), which
produced a 502 on one navigation. Re-verified after it came back; not a
regression.

## Before / after

| | Before | After |
|---|---|---|
| Dashboard, dark | `captures/before-dash-dark.png` | `captures/after-dash-dark.png` |
| Dashboard, light | `captures/before-dash-light.png` | `captures/after-dash-light.png` |
| Components, dark | `captures/before-components-dark.png` | `captures/after-components-dark.png` |
| Components, light | `captures/before-components-light.png` | `captures/after-components-light.png` |

## Still open

1. **Composition of the other 63 screens.** They inherit the tokens and
   primitives, so buttons, tables, chips and focus are consistent, but their
   layout has not been re-reviewed. Next candidates by traffic: Findings,
   Assets, Grants, Orchestration.
2. **`deploy` is offered on builds with no SBOM.** The table invites deploying
   an unanalysed artifact. Gating it is a product decision (the API accepts the
   call today), so it was left alone.
3. **The data disagreements listed above.** They belong to the serializers.
4. **Entity breadcrumbs** are still screen-local (`Projects` has one, `Assets`
   does not).
5. **The v0 dashboard payload** still mixes inventory and risk counters; the
   screen now separates them, the endpoint could too.

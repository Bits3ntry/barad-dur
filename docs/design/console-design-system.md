# Console design system

The console is a **security operations surface**: it has to carry a lot of
technical facts without hiding the one thing that needs a decision. This
document is the contract every screen follows. It is written to be read before
touching `frontend/src/styles.css`, `ui.jsx` or a screen.

- Code: `frontend/src/styles.css` — section **DESIGN SYSTEM v2** (the last
  layer of the file, authoritative) plus section **16/17** for the pilot
  screens.
- Primitives: `frontend/src/ui.jsx` (`Card`, `Stat`, `Table`, `Pager`, `Tabs`,
  `Banner`, `EmptyState`, `Loading`, `Dialog`, `Drawer`, `Field`, `Input`,
  `Select`, `CheckBox`, `Toggle`, `SeverityBadge`, `StatusBadge`, `Pill`).
- Charts: `frontend/src/Charts.jsx` — tokens only, never a hex.

## 1. Principles

1. **Clarity over minimalism.** A quiet screen that hides its actions is not
   minimal, it is unfinished. Every interactive element looks interactive at
   rest, not only on hover.
2. **One decision per screen.** The first block states the verdict and offers
   the one action that follows from it; everything else is evidence for it.
3. **Hierarchy by weight, not by decoration.** Three text weights (strong,
   default, muted), one page title, one section per question. A row of equal
   tiles is a table of contents, not a hierarchy.
4. **Solid fill = action.** The only saturated filled block on a screen is the
   primary action. Severity, priority and state are tinted chips that carry a
   mark *and* a label.
5. **Colour is never the only signal.** Every severity badge has a dot and the
   severity name; every priority chip has its numeral; every coverage chip says
   `never analysed` in words.
6. **An empty table is unknown, not clean.** "Nothing found" and "never
   analysed" are different facts and the screen says which one it is.
7. **Density is a feature.** We compress with grouping and progressive
   disclosure, never by shrinking type below the measures in §6.
8. **Light and dark are two variants of one system.** Same tokens, same
   components, different values. Nothing is an inversion of the other.

## 2. Surfaces

Four surfaces, in increasing elevation. A card must be distinguishable from the
canvas **with its border removed** — otherwise the theme reads flat.

| Token | Role | Light | Dark |
|---|---|---|---|
| `--surface-canvas` | app ground behind everything | `#eaeef4` | `#070a0e` |
| `--surface-card` | cards, tables, dialogs' body | `#ffffff` | `#151c26` |
| `--surface-raised` | table head, hover, inset chips, inputs | `#f2f4f8` | `#1d2431` |
| `--surface-inset` | code blocks, pressed states, tracks | `#e6eaf1` | `#0b0f15` |
| `--surface-sidebar` | navigation rail | `#fbfcfe` | `#0a0d12` |
| `--surface-header` | top bar (translucent) | `rgba(255,255,255,.86)` | `rgba(7,10,14,.9)` |

Elevation is expressed differently per theme on purpose: light separates with a
shadow (`--shadow-1..3`), dark separates with a lighter surface plus a ring.
A dark theme that only darkens is unreadable; a light theme that only borders is
flat.

## 3. Borders and text

| Token | Use |
|---|---|
| `--border-subtle` | separators inside a card, decorative only |
| `--border-default` | card edge, table row divider |
| `--border-strong` | section split, dashed empty state |
| `--border-control` | **outline of an interactive control** — ≥ 3:1 against its surface (WCAG 1.4.11) |
| `--border-interactive` | hover edge |

| Token | Use | Light | Dark |
|---|---|---|---|
| `--fg-strong` | titles, values, row identity | `#0b111c` | `#f5f8fc` |
| `--fg-default` | body copy, nav labels | `#1b2432` | `#dbe2ed` |
| `--fg-muted` | metadata, captions, secondary controls | `#58626f` | `#9ea9ba` |
| `--fg-subtle` | labels, eyebrows, axis ticks | `#646e7b` | `#8b95a6` |
| `--fg-disabled` | unavailable | `#a4acb8` | `#5b6675` |

Nothing below `--fg-subtle` is used for text that has to be read. Measured
ratios are in §6.

## 4. Actions

| Tier | Class | Look | When |
|---|---|---|---|
| Primary | `.btn-primary`, `.primary-action`, `button.primary` | solid `--action-bg`, 640 weight | exactly one per screen; the commitment |
| Secondary | bare `button` | card surface + `--action-2-border` | everything else that acts |
| Ghost | `.btn-ghost`, `button.ghost` | no border, hover fills | toolbar utilities, dismiss |
| Destructive | `.btn-danger` | danger tint, never a solid red block | delete / revoke |
| Compact | `button.mini` | 28px, bordered | row and toolbar actions |
| Icon | `.icon-btn` | 28×28 square | expand/collapse, refresh, close |
| Group | `.btn-group` | joined frame | mutually related controls (expand all / collapse all) |

Rules that are not negotiable:

- A row action inside a table is a **compact chip**, never bare text: an action
  that reads like a cell value is not discoverable.
- `--action-bg` is black in light and ember in dark. It is the only saturated
  fill in the theme; severity chips are tinted, not filled, so they can never
  compete with it.
- Hover and focus are always defined together. `:focus-visible` → 2px ring at
  2px offset on every interactive element, including `<tr>` when it is a link.

## 5. Severity, priority, state

Three different vocabularies, three different shapes. They must not be
interchangeable.

| Vocabulary | Meaning | Shape | Tokens |
|---|---|---|---|
| **Severity** | how bad the finding is | tinted chip + leading dot + name, or a proportional bar | `--sev-critical/high/medium/low/info` (+ `-fg`, `-bg`, `-line`) |
| **Priority** | where it sits in the CTEM queue | numeral chip, and a **one-hue ramp** in charts | `--prio-p0..p3` (chips), `--rank-p0..p3` (charts) |
| **State** | lifecycle | neutral chip, tinted only for terminal states | `--success-*`, `--warn-*`, `--danger-*`, `--info-*` |

Priority deliberately does **not** reuse the severity palette: a P0 slice in the
exposure-flow donut used to be the same red as a critical finding, which made a
ranking look like a severity. Charts take `tone="critical|high|medium|low|info"`
or `tone="accent|ok|muted"` and resolve it to a token (`Charts.jsx`).

## 6. Type, spacing, motion — the measured floor

| Role | Size | Weight |
|---|---|---|
| Page title | `--fs-page` 26px (25 dark) | 660 |
| Section heading (band) | 15px | 640 |
| Card title | `--fs-card` 13px | 620 |
| Body / table cell | `--fs-body` 13.5px | 400–520 |
| Metadata / caption | `--fs-meta` 12px | 400 |
| Label / table head | `--fs-label` 11px, `0.06em` tracking, uppercase | 600–640 |
| Metric value | `--fs-metric` 26px | 650 |
| Technical identifier | `--fs-mono` 12.5px monospace | 400–620 |

Contrast (measured in the live console with the real computed colours):

| Pair | Light | Dark | AA normal text |
|---|---|---|---|
| `--fg-strong` on card | 18.9:1 | 17.0:1 | ✓ |
| `--fg-default` on card | 15.6:1 | 13.9:1 | ✓ |
| `--fg-muted` on card | 6.2:1 | 7.3:1 | ✓ |
| `--fg-subtle` on raised | 4.7:1 | 5.2:1 | ✓ |
| control border vs card | 3.6:1 | 3.7:1 | ✓ (1.4.11) |
| severity chip text on its own tint | 6.4–8.0:1 | ≥ 5.5:1 | ✓ |

Motion: `--dur-1` 120ms, `--dur-2` 180ms, `--ease cubic-bezier(.2,.6,.3,1)`.
Only state changes animate (background, border, colour, chevron rotation). All
of it collapses under `prefers-reduced-motion: reduce` (verified: transitions
compute to `1e-05s`).

Density: `data-density="comfortable"|"compact"` on `<html>`. Compact changes
padding and metric size, **not** the legibility floor:

```
[data-density="compact"] th, td   → 7px 10px, 13px
[data-density="compact"] .metric  → 10px 12px, value 21px
[data-density="compact"] .card    → 14px 16px
```

## 7. Component conventions

**`Card`** — `band` puts the title in a header strip that belongs to the card.
Use it for a card that owns a whole section (table, diagram, form). Without
`band` the card is a titled panel.

**`Stat`** — label above value (order is CSS, not markup). `tone` (`bad|warn|
good`) tints the tile and the number; `quiet` recesses a zero so it does not
compete; `onClick` renders it as a `<button>` and it becomes the door to its
list. A KPI that cannot be clicked must not look clickable.

**Tables** — header in `--surface-raised` at 11px, 0.06em, muted; rows separated
by `--border-default`; numeric columns right-aligned with tabular numerals;
identity column (`td.ident`/`td.title`) at 580 weight; wide tables scroll inside
`.table-wrap` and never push the page.

**Bands.** A screen with more than three blocks is banded:
`<section class="dash-band">` + `.band-head` (an `<h2>` naming the question and a
one-line `<p>` saying why it is there). This is what stops a dashboard from
becoming a pile of equal cards.

**Empty states** — `EmptyState` renders a dashed frame, a title and a hint that
names whether the data is missing or merely absent.

**Charts** — `LineChart`, `BarChart`, `DonutChart`, `ProgressBar`. They take a
tone, print their own values (bar values above bars, min/max on the line axis)
and use `--surface-card` for the gap between donut arcs so they survive both
themes.

## 8. Adding a screen

1. Compose from `ui.jsx`; do not re-implement a card, a table or a pager.
2. Use `PageHeader` for the title + the screen's one primary action.
3. If the screen answers more than one question, band it and name each band.
4. Every count that is a drill-down is a `Stat`/`Coverage`-style button, not a
   dead number.
5. Empty, loading and error states are part of the screen, not an afterthought:
   `Loading`, `EmptyState`, `ErrorBanner`.
6. Never hardcode a colour. If a new tone is genuinely needed, add it to §2–§5
   of the token block first, in both themes.
7. Check `document.documentElement.scrollWidth - window.innerWidth === 0` at
   480, 620, 900, 1280 and 1600px before calling it done.

## 9. How the CSS is layered

`styles.css` accumulated three successive visual passes, and 65 screens depend
on their selectors. The v2 layer was therefore **appended**, and it wins by
source order rather than by `!important`:

- `:root` and `[data-theme]` in the v2 block re-declare the palette and map the
  legacy tokens (`--bg`, `--panel`, `--line`, `--text`, `--accent`, `--critical`
  …) onto the new semantic ones. The 3.5k lines above therefore inherit the new
  system without being rewritten.
- Component rules in the v2 block use the same or a higher selector weight as
  the earlier ones (`td button:not(.version-open)`, `.table-wrap td button`).
- Removing a duplicated rule is welcome **when the screen it serves has been
  checked in the browser**; blind deletion of the earlier passes is not,
  because they style screens no one has looked at in this pass.

## 10. Known limits

- Only the two pilot screens (Dashboard, Projects → Components) were
  restructured at the layout level. The other 63 screens inherit the tokens,
  primitives and states, but their *composition* has not been reviewed.
- The global search and the topbar breadcrumb still resolve only screen names;
  entity breadcrumbs are per-screen (`Projects` has its own).
- `--surface-*` shadow elevation is intentionally shallow in dark mode; a
  heavier elevation pass needs a device check on a low-contrast display.

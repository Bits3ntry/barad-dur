# Reproducible test cases

Every case states what to do and what proves it worked. Names like
`manifest.cycle` refer to the ids printed by `scripts/e2e_stack.py --seed`, so
the same case works after every rebuild.

**Precondition for everything except TC-001/TC-002**: the seed stack.

```bash
npm run build --prefix frontend
python scripts/e2e_stack.py --port 8099 --seed     # prints URL, key, user, manifest
export B=http://127.0.0.1:8099 ; export K=<printed key>
```

Console sign-in: `api key` tab → paste `K`. For the session cases, sign in as
`ana@bitsentry.xyz` with the password the script prints.

---

## Gate

**TC-001 · contract smoke** — automated
`python scripts/qa_smoke.py --url $B --key $K`
Expected: `64/64 checks passed · 1 skipped` (the MFA check needs a session).
Any `fail` line is the bug report; it names area, path and the reason.

**TC-002 · end-to-end assertions** — automated
`python scripts/demo_v0.py`
Expected: every `ok` line, exit 0. Covers §14 steps 1–13 on a throwaway DB.

---

## General

**TC-010 · dashboard counters match their lists**
Open `#dashboard`. Note `open findings`, `assets`, `open exposures`, `changes 7d`.
Click each counter. Expected: the destination list shows exactly that many rows,
with the same filter (open+acknowledged, archived excluded) visible in the header.
Automated: `test_dashboard_counters_equal_their_destinations`.

**TC-011 · dashboard never invents a metric**
With an unknown project: `GET /dashboard/summary?project=nope` → **404**, never the
org-wide numbers. Empty org → counters read `0` with the coverage note, not a
percentage.

**TC-012 · My work trays**
`#my-work`, acting as `ana@bitsentry.xyz`. Expected: `Assigned to me` lists the
seeded IDOR; each tray header count equals its list length; `Organization queue`
states there are no teams instead of implying them.
Approve/reject requires a reason; approving your own request answers **409**.

**TC-013 · queue visibility**
Act as another user (`actor` field or a second session). Expected: only that
identity's items; the org tray lists others' items only for roles entitled to
see them.

**TC-014 · findings filters**
`#findings` with project `aurea`. Apply version, kind, severity. Expected: row
count changes coherently, the header count matches, `include suppressed` reveals
the suppressed one and nothing else.

**TC-015 · create a manual finding (no CVE)**
`new finding` → title `IDOR on invoice export`, kind code weakness, HIGH, path
`app/api/invoices.py`, line 42, CWE-639, impact/reproduction/recommendation →
`create`. Expected: row appears with `P3 · HIGH`; opening it shows CWE-639 and
**no CVE**; Vulnerabilities still reports 0 CVEs.

**TC-016 · finding drawer and history**
Open the created finding. Expected: Overview has location `path:line`; History
lists `finding.created` with actor; adding a comment and an attachment appears in
the respective tabs; a secret-kind attachment is marked `unreviewed`.

**TC-017 · finding lifecycle**
`mark resolved` with a reason → status `resolved`; `reopen` → `open`; the history
keeps both transitions with actor and reason. A viewer session attempting the
same gets **403**.

**TC-018 · vulnerabilities grouping**
`#vulnerabilities`. Expected: header says how many CVEs affect the inventory;
a manual IDOR without CVE is absent; bulk selection shows a **preview** first and
only the previewed ids change after apply.

---

## Scoping

**TC-020 · rule, apex and exclusion**
`#scope` → `declare target` `*.bitsentry.xyz` (domain, passive discovery).
Expected: `1 pattern rule`, inventory still 0 assets. `check a value`
`api-aurea.bitsentry.xyz` → allowed; `bitsentry.xyz` → denied with the apex
reason. Add an exclusion for one subdomain → check it again → denied, and the
exclusion is named as the winner.

**TC-021 · concrete scope entry creates the canonical asset**
Declare `api-aurea.bitsentry.xyz` → `#assets` shows one asset with provenance
`scope`; declaring it again does not duplicate it.

**TC-022 · cycle freeze**
`#cycles` → `new cycle` with name, owner, objectives, projects `aurea`, group
`Production`, environment `production` → `create`. Expected: `planning`,
`preview` resolves members and lists gaps (“no deployment recorded for
environment production”). `activate and freeze` → `active`, `N members frozen`;
changing the group afterwards does not alter the snapshot.

**TC-023 · auto-link respects the frozen selection**
With the cycle active: `link project findings`. Expected: only findings located in
the frozen assets/deployments link; a finding of the same project outside the
selection does not. Automated: `test_auto_link_respects_the_frozen_selection`.

**TC-024 · review and close**
`record review` with results + criteria (`met`/`not met`/`not measurable`) →
`review recorded`, state `review`; `close cycle` → `closed`; reopening the row
still shows charter, selection and criteria.

---

## Discovery

**TC-030 · inventory, needs attention**
`#assets` → filters by type/classification; the seeded asset shows group
`Production` and reasons `no_owner`, `no_project` in *Needs attention*, each with
an action. Archiving hides it from the default list and keeps it under the
archived filter.

**TC-031 · group membership is not access**
`Assets → Groups` → open `Production` → remove the asset. Expected: the asset
still exists in Inventory; the group simply has no members. Adding it to two
groups and removing one leaves the other.

**TC-032 · activity ledger**
`Assets → Activity`. Expected: rows for scope/asset/group/deployment/cycle with
actor and time; an ordinary edit appears here **and** in the audit trail.

**TC-033 · changes need equal coverage**
Import two observations for the same asset (`POST /observations`), the second
adding port 9090 with `coverage: full`. Expected: one `open_port 9090` change.
A third import with `coverage: failed` produces a coverage note and **no**
`host_disappeared`/`closed_port`.

**TC-034 · web surface honesty**
`#attack-surface` → Web surface. Expected: excluded paths are labelled
`not evaluated`, never `safe`; a `200` is a candidate/observed, not a finding.

**TC-035 · lookalikes are external**
Add a lookalike candidate. Expected: it is `external`, never gains a scope entry,
and the UI states passive-only watching (DNS/CT).

**TC-036 · review confirms ownership only**
`Attack surface → Review`: confirm one address as ours, mark another external
with a reason. Expected: confirmation changes `classification_status`, not
authorization; the scope decision is unchanged.

**TC-037 · SBOM import and idempotence**
`#components` → `import SBOM…` with a CycloneDX file for `aurea` `v3`. Expected:
receipt `N created, 0 updated, M links`; importing the same file again reports
`0 created` and the component count does not grow.

**TC-038 · artifact chain**
`GET /artifacts?version=v3` → open the artifact. Expected: digest, SBOM presence,
`in_production: true` because a production deployment points at it, and
`usage_per_artifact: not implemented` declared, not faked.

**TC-039 · exposures decisions**
`#exposures` → `decide` on an open event: accept requires a future validity and a
reason; resolve requires a reason; false positive requires a reason. Re-observing
the condition after a decision follows the documented reopen policy. Counts in the
header describe the organization, not the current filter.

---

## Code security

**TC-040 · SAST import (base + head)**
`POST /analysis/import` twice (base `revision=base123`, then head with
`base_run_id`, `diff`, `files`, `repository_id`, `pull_request`). Expected:
base counters `no_reference 1`; head `persistent 1`, `on_modified_line 1`.

**TC-041 · viewer**
`#analysis` → `open` the head run. Expected: file tree, code with syntax colour,
the rule/CWE/message on the line; `diff` shows the hunk with `1 added · 1 removed`;
`results` shows `persistent` and `modified line: yes` (never “introduced by the PR”
without a comparable base).

**TC-042 · deep links both ways**
From `results` press `open finding` → URL `#findings::<id>`, drawer open, the line
“last evaluated by OpenGrep @ abc1234def on feature/payments · PR 77”; press
`open in analysis` → `#analysis::run=…&path=…&line=…`, the file opens and scrolls
to the line. Reload the URL: it still lands there.

**TC-043 · pull request review** (partial)
`#code`: register a PR for `aurea`; the row shows counts and gate verdict; opening
it lists findings with context/diff toggles. No provider sync exists — the screen
must not claim a remote state.

---

## Prioritization

**TC-044 · priority rules and SLA**
`#priority-rules` → add `secret → P0` with a reason. Expected: rule listed at its
position, findings reclassified on save; a finding with no match keeps the
severity fallback and says so. SLA policy edit changes the displayed deadline.

**TC-045 · business impact**
`#business-impact`. Expected: one row per application with open/P0-P3/untriaged/
late/unassigned/CVE/asset/production-deployment counts; the footer states
`criticality: not modelled` and that a coverage gap is not a clean bill.

---

## Auth and administration

**TC-046 · optional TOTP**
`Administration → My security` → start enrolment (password) → QR + secret shown,
status still `off` → confirm a code → `enabled`, 8 recovery codes shown once.
Sign out, sign in: password alone returns a code prompt; a wrong code is rejected;
a TOTP **or** a recovery code issues the session; the same recovery code twice
fails. Disable requires a current or recovery code.

**TC-047 · SSO for registered users only**
With `OIDC_*` unset: the login screen shows no SSO button and Settings says what
is missing. With it set: `Continue with Google` appears; the callback for an
email that has no account answers **403** and creates nothing; for a registered
user it issues a session, and if that user has TOTP it still asks for the code.

**TC-048 · Slack channel and tray**
`#notifications` → Delivery channels → kind `slack`, URL
`http://127.0.0.1:8123/slack` (mock from `docs/integrations/slack.md`) → `add
channel` → `test`. Expected: `test delivered … HTTP 200`; the receiver sees
`{text, blocks}` and no `X-Barad-Signature`. The tray lists notifications and
`mark read` flips the unread counter.

**TC-049 · roles and permissions**
As a `viewer` session: writes answer 403 (create finding, add channel, suspend
asset); reads stay available. As an API key: admin endpoints work, MFA endpoints
answer 403 (a factor belongs to a person). Revoking a key makes it 401 on the
next call; the last active key cannot be revoked.

**TC-050 · audit trail**
`#audit`. Expected: rows for scope change, cycle activation, channel creation,
MFA enable/disable, each with actor, resource and detail; a read-only request
creates no row.

**TC-051 · Jira out and back** (needs a configured Jira)
Create a link with `send_now=true` → an issue key appears; the outbox marks it
`sent` once (repeat the call: same dedupe key, no duplicate issue). Send the
webhook with a Done status → `sync_state=verification_required` and the finding
stays open. Without `JIRA_*` variables the endpoint reports `jira_not_configured`
instead of pretending.

---

## Adversarial

**TC-052 · cross-organization isolation** (S0)
With org B's key, request org A's ids directly: finding, cycle, artifact, analysis
run, exposure, asset, group, channel, notification → **404** for each. Counters
and lists in B show zero of A's rows. Export endpoints too.

**TC-053 · states are distinguishable**
On one screen each: empty (no SBOM), not configured (weekly delivery), no
permission (viewer hitting an admin read), error (bad key → `HTTP 401: …` and a
header that says `not loaded`), and partial coverage (analysis `diff`, changes
with a failed collection). Expected: five different messages, never one generic
"nothing here".

**TC-054 · malformed and oversized imports**
`POST /analysis/import` with invalid JSON → 422 with a useful message; a SARIF with
an unknown `ruleId` → imported with `uninterpreted` counted; an SBOM over the size
limit → rejected with the limit named. None of these may 500 or leave half a row.

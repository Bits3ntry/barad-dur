# Jira inbound — assessment (not implemented)

Question: should Jira issues come *into* Barad-dûr, so a ticket becomes a
finding or a work item, while Barad-dûr keeps reporting and creating tickets in
Jira?

This document answers what exists today, what each direction would cost, and
what I recommend building first. Nothing here is implemented.

## What exists today (verified)

| Capability | State |
|---|---|
| Finding → Jira issue | works: `POST /api/v1/jira/links` queues a `create` in an idempotent outbox (`jira_outbox.dedupe_key`), a drain calls the real REST API and stores `issue_key`/`issue_url` |
| Update / transition | works: `update`, `transition` actions through the same outbox |
| Jira → status | works: `POST /api/v1/jira/webhook` (shared secret) updates `external_status`/`external_assignee`; a Done ticket sets `sync_state=verification_required` and **never** closes the finding |
| Reconcile | works: re-reads linked issues and repairs drifted state |
| Jira issue → finding | **does not exist** |
| Jira issue → work item | **does not exist** |
| Comments / attachments sync | **does not exist** |

So today the bridge is "finding owns the ticket", and Jira only reports back
state. `JiraLink.finding_id` is non-nullable, which is the structural reason an
issue cannot exist here without a finding.

## The three options

### A. Import issues as **work items** (recommended)

A Jira issue is work, not a weakness: it has an owner, a status, a project and no
location in code. The domain already has `work_items` (from the My-work slice)
with owner, status, due date and a source.

- New table `work_item_links` (`work_item_id`, `provider`, `instance`, `issue_key`,
  `external_status`, `last_synced_at`) plus `work_items.source = "jira"`.
- Poll (`JQL updated >= last_sync`) or webhook (`jira:issue_created|updated`) →
  upsert by `(provider, instance, issue_key)`, which is also the dedupe key.
- Mapping: summary→title, assignee→owner (email if the account offers it),
  status category→`open|in_progress|done`, due date→due, project key→a reference,
  **never** to a finding.
- Permission: the issue is visible to whoever can see the linked project/group;
  the sync runs under a dedicated integration identity, audited per upsert.

Cost: ~1 migration, ~250 lines of router + mapper, ~20 tests, one settings panel.
Risk: low — it adds a source, it does not touch findings.

### B. Import issues as **findings**

Tempting when the team tracks vulnerabilities in Jira ("SEC-123 = SQLi in
reports.py"). The blockers are real:

- A finding's identity is a fingerprint over kind+project+location (`analysis.py`,
  `incidents.py`); a Jira issue carries none of that. Reconstructing it means
  parsing summary/description, i.e. guessing.
- Imported findings would land in every counter (dashboard, SLA, exposures,
  cycles) without evidence or coverage, which is exactly the "invented metrics"
  the v0 rules forbid.
- Closing semantics collide: Jira Done would have to mean "resolved" here, and
  we already refuse that for linked tickets.

Cost: high, and it weakens the model. Only justified with a **field mapping
contract per Jira project** (custom fields for path/rule/severity), which is a
config product of its own.

### C. Read-only mirror inside the finding drawer

Show the linked issue's title/status/comments next to the finding without
creating anything. Cheapest, but it does not answer "read tickets as work".

## Recommendation

Do **A**, and only after the integration identity exists (a service principal
with its own permissions and audit trail — today the Jira bridge reads
credentials from the environment and has no per-connection record). Sequence:

1. `integration_connections` (provider, instance, credential reference, health) —
   the connector contract the spec asks for in §11.
2. `work_item_links` + upsert-by-key + a `jira:issue_*` webhook event.
3. A read-only issue panel in the work item drawer; writes stay out until the
   outbox has a matching inbound conflict policy (who wins when both sides moved).

Questions that must be answered before coding:

- Does the Jira account expose assignee **emails** (GDPR-restricted on some
  plans)? If not, ownership maps to an opaque account id and My-work queues
  cannot attribute it.
- One Jira instance per organization, or several? The schema above assumes
  several (`instance` in the key).
- Should a Done issue close a work item here? (For tickets created *by* us the
  answer was "verification required"; for imported ones it is a product choice.)

Estimated effort for A: 2–3 focused sessions including tests and a settings
screen. B: not recommended.

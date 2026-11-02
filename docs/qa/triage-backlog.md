# Triage backlog — known gaps, by severity

Everything here is a **known** limitation: it is written down, labelled and has a
proposal, so nobody discovers it in production. Bugs (things that were meant to
work and did not) live in the pass reports, not here.

Severity: **S0** data loss / cross-org leak · **S1** feature unusable ·
**S2** wrong result or workaround exists · **S3** cosmetic.

| ID | Sev | Area | What is missing | Why it matters | Proposal | Status |
|---|---|---|---|---|---|---|
| T-01 | S2 | Auth | Organisation-wide MFA policy ("every require a factor") | an admin cannot enforce what the product offers | policy flag on the org + enforcement in `resolve_principal`, plus a "members without MFA" list | open |
| T-02 | S2 | Integrations | Jira issues → work items (inbound) | tickets cannot be worked from here | see `docs/planning/jira-inbound-assessment.md`, option A | open, designed |
| T-03 | S2 | Delivery | Scheduled weekly digest | the query exists, `delivery.configured=false` | scheduler + channel wiring; decide owner (cron vs. outbox tick) | open |
| T-04 | S2 | Code security | Project/repository → recent analyses | the viewer is reachable only from a finding | "analyses" card on the project screen, reusing `/analysis/runs?project=` | open |
| T-05 | S2 | Code security | Source→sink traces | impact claims would be invented | render only when `codeFlows` carries data; otherwise keep the count | accepted limitation |
| T-06 | S3 | Components | Artifact screen / component → artifact link | the chain is API-only | small screen reusing `/artifacts` | open |
| T-07 | S2 | Scans | No collectors, no sensor admin, no CI/CD execution | acquisition is out of v0 | out of scope for v0; imports are the supported path | accepted limitation |
| T-08 | S3 | Notifications | Slack app features (buttons, slash commands) | needs a public endpoint + OAuth app | only if a workflow demands triage from Slack | accepted limitation |
| T-09 | S3 | Auth | WebAuthn/passkeys, SMS factor | TOTP covers the v0 need | evaluate after the MFA policy | open |
| T-10 | S3 | Reporting | PDF/HTML only for pentest reports | dashboards cannot be exported | reuse `pdf_report.py` for the v0 dashboard | open |
| T-11 | S2 | Access | Access groups / per-team data scoping | "My team" is the org queue | needs the access-group model; the tray already says so | open, designed |
| T-12 | S3 | Inventory | Dynamic groups / saved expressions | manual grouping only | after access groups, same expression engine | open |
| T-13 | S3 | QA | No browser-matrix automation (Safari/Firefox) | one Chromium pass today | add a Playwright runner if the UI keeps growing | open |
| T-14 | S3 | QA | Cases TC-043/TC-051 need external systems | they are partial by dependency, not by code | run against a sandbox Jira when available | blocked |

## How to add a row

1. Severity first (does it lose data / leak across orgs / make the feature
   unusable?), then area.
2. "What is missing" must be falsifiable; if it cannot be verified in five
   minutes, it is not a row yet.
3. Link the design or the file that would change, and mark `open`, `accepted
   limitation`, or `blocked (dependency)`.

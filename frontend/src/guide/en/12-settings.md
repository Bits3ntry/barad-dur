Settings is a full screen with its own navigation, not a modal. It holds everything that configures the workspace rather than reporting on it. Two groups, and the difference is who the setting belongs to.

### Workspace settings

| Section | What it configures | Reach for it when |
|---|---|---|
| **Organization** | name, logo, a description, the site | the workspace identity is wrong, or a new team takes over |
| **Account** | the platform URL, the API key stored in this browser, sign-in, password change, sign-out | the browser cannot reach the platform, or you need to re-authenticate |
| **Appearance** | theme (dark / light / system) and density (comfortable / compact) | the screen is hard to read, or you want more rows visible |
| **Delivery** | the SMTP relay used for invitations and email notifications | invitations do not arrive |
| **Intelligence** | the advisory clock: sources (OSV, CISA KEV, EPSS, NVD runtime CVEs), interval, version cap, run now | you want a CVE published after the scan to appear |
| **AI** | providers, sealed keys, prices, monthly token and cost caps, the red-team decision | you are wiring a model, or the AI stops at a budget |
| **Service identities** | API keys for automation | a CI job, a worker, the MCP server or a script needs to authenticate |

### Administration

| Section | What it configures | Who should have it |
|---|---|---|
| **My security** | multi-factor authentication for your own account | everyone, eventually |
| **Notifications** | delivery channels (Slack / webhook), per-event subscriptions, the in-app centre | whoever is on call |
| **Grants** | scanner authorization: approve, widen, shorten, revoke | the person accountable for what gets scanned — usually an Administrator or Owner |
| **Runtime** | scan concurrency policy: per zone, per org, per worker, queue ceiling, pool bounds | whoever owns the target relationship |
| **Members** | people, roles, invitations, seats | Owner / Administrator |
| **Audit trail** | the recorded security actions, hash-chained per organization | auditors. Read-only by design |
| **Setup guide** | the six-step status page from empty workspace to working pipeline | whoever is onboarding the workspace |

### The one setting people look for and cannot find

**Where do I change what may be scanned?** Not here. That is **Grants** — and a grant is approved from a request, which starts with a declaration on **Scope** or **Assets**. Settings can widen or revoke an existing grant; it never creates authority out of nothing.

### The two settings that explain surprising behaviour

- **Intelligence → interval.** The advisory sweep decides for itself whether its interval has elapsed. Calling it again answers `not_due` and writes nothing, so a manual run that "did nothing" may simply have been early. The poll rate is not the sweep rate.
- **Runtime → queue ceiling.** A ceiling refuses **at creation** with `429`; the per-zone and per-org caps hold a run `queued` instead. One is an immediate answer, the other is a wait — and neither is a failure.

### Appearance and density, in one line

Theme follows the OS when set to *system*; density changes the base font scale and the spacing tokens for the whole console, so a compact screen is genuinely more rows, not a zoomed one. Both are stored per browser, not per account.

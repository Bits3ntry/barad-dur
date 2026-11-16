A finding is the only object the platform asks a human to decide on. Everything else — inventory, observations, runs — exists so a finding is worth reading.

### Where a finding comes from

| Source | Kind of finding | Arrives via |
|---|---|---|
| SBOM ingestion | a CVE (or a group) in a package of a build | build upload, pipeline, CLI |
| advisory clock | a CVE published **after** the build was scanned | the platform's own sweep (OSV, KEV, EPSS, NVD) |
| code analysis | a weakness (`sast`) or an exposed secret (`secrets`) | the CI scan, on a checkout |
| surface run | an exposure: a reachable service, a weak certificate, an open path | a recon run's observations |
| pentest / manual | a validated issue | the pentest campaign, or an imported report |

A finding is keyed by the thing that is wrong (a CVE, a rule, a subject), not by the document it arrived in. Two sources naming the same defect produce one row.

### How the list is ordered

**risk = severity weight × KEV × EPSS, capped at 100.** A known-exploited vulnerability outranks a theoretical one even when both read "high", and the screen says why the order is what it is. When you sort differently, you are choosing another question — `Findings` and `Vulnerabilities` both sort server-side, so a filter and a sort always describe the whole set, not the visible page.

### Triage is a decision, and it is recorded

Open a row and set:

| Status | Means |
|---|---|
| `open` | nobody has looked, or nothing was concluded |
| `acknowledged` | seen, accepted as work, not started |
| `in_progress` | someone is on it |
| `resolved` | closed by evidence: an upgrade, a rotation, a code change |
| `false_positive` | the scanner was wrong, and why |
| `accepted_risk` | real, and we choose to live with it |

Plus an **owner** and, on most rows, an **SLA** with a deadline. Overdue rows are what the Dashboard badge counts and what `sla.breached` notifies about.

Triage can happen from **the run** that produced it, and there it appends a `decision` event to that run's own timeline. That is the point: six months later the run still says who looked and what they concluded, instead of a status field with no author.

A dismissed finding does not disappear from the build it belongs to. Builds list settled rows with `dismissed: true`, because "we looked and dismissed it" and "nobody scanned this" are different facts about a build.

### The screens, and the one question each answers

| Screen | The question |
|---|---|
| **Dashboard** | where does the estate stand today? |
| **My work** | what is mine, and what is due? |
| **Findings** | what needs a decision? |
| **Vulnerabilities** | which advisories exist, and how bad are they really? |
| **Exposures** | what is reachable that should not be? |
| **Prioritization rules** | how is priority computed here? |
| **Business impact** | which application carries the open work? |
| **Regression** | what came back after we thought it was fixed? |
| **Remediation** | what is the plan and the lifecycle of the work? |

**My work** is built from assignments, requests, tasks and acceptances — real queues from real rows, never a static mock. Each queue says what it is: *assigned to me*, *waiting for my decision*, *waiting for my acceptance*.

**Vulnerabilities** is the advisory catalogue: KEV and EPSS beside severity, filters that arrive from a dashboard card (`#vulnerabilities::kev=1` opens the known-exploited door), and the affected builds. It answers "is this famous CVE in our estate", which is a different question from "what should I do next".

**Exposures** groups reachability findings and counts them honestly: open, accepted, resolved.

**Prioritization rules** is where the weighting policy is visible and editable, and **Business impact** rolls open work up per application — counted from findings, assets and deployments, so it cannot drift from the rows it summarises.

### Regression

When a fix is claimed, regression re-tests the claim instead of trusting it. That is the only way a "resolved" status survives the next scan: the same rule, the same target, a new run.

### The honest states, in the finding list

- **A raw 404 is not "not affected".** Looking up a vulnerability the workspace does not hold answers "no finding matches", which reads identically to "you are clean". The API distinguishes never-scanned from scanned-and-absent, and any automated answer keeps that distinction.
- **Coverage travels with the finding.** `partial` on the run means the estate was not fully examined; the finding is still real, the silence around it is not informative.
- **Unknown is a state, not a colour.** A component with no advisory feed for its ecosystem is `unknown`, with the reason.

### What closes a finding

Not a comment. Three classes of closure, and they do not close the same way:

1. a **credential** is exploitable now and closes by rotation — deleting the file does not revoke the key, and git history keeps it;
2. a **CVE** closes by upgrading the component, which the next build proves;
3. a **code weakness** closes by changing code and re-scanning, which regression confirms.

Storing the class (dependency CVE, credential, SAST, misconfiguration) next to the finding is what lets you answer "is this actually closed?" a year later.

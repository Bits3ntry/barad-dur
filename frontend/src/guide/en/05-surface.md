Attack surface is the half of the estate nobody declares: the subdomains that exist, the ports that answer, the certificate that is about to expire, the page that reveals a version. Barad-dûr treats it as evidence — typed observations with a source and a coverage — not as a scan report PDF.

### What an asset is

An **asset** is a domain, subdomain, URL or IP under observation. Its identity comes from the subject that produced it, never from a filename: a URL is a `url` asset because it starts with a scheme, and two rows for one host means an ingestion bug, not a display choice.

Four tabs on **Assets**:

- **Inventory** — the tree, with ownership, project, criticality and when it was last observed;
- **Observed** — the rows a collector wrote, with source and coverage;
- **Timeline / activity** — what changed and when;
- **Unassigned** — assets with no project, which is work waiting for a decision, and it is counted honestly (`showing N of M`, never the page size pretending to be the total).

An asset page (`#asset::<id>`) is the single object: overview, certificate, **services grouped by the port that serves them**, the fingerprint evidence folded away, its relationships and a pre-filled scan dialog.

Two rules the screens obey, because getting them wrong teaches people to ignore the product:

- **Trust needs its own state.** A TLS probe that failed verification stores an error; a certificate that fails trust must not render as a certificate with empty dates. It prints the reason.
- **"Never observed" is not "healthy".** A solid dot means it answered, a hollow one means we could not see it.

### The authorization chain

```
declare the host  →  grant requested  →  approved in Settings → Grants
      (Scope/Assets)        (status=requested)        (level + scope + expiry)
                                                        ↓
                                            a plan may now execute on it
```

Three things to internalize:

1. **The declaration never chooses what may be done with the host.** Not the level, not the scope — asking is not authorizing. If a screen ever looked like it decided, that would be a bug.
2. **The request is ignored by the engine until it is approved.** `status=requested` grants nothing, by construction.
3. **A grant names a principal, a target, a capability set and an expiry.** A plan asks as the *collector*; a console approval records `console`. The platform accepts its own two principals and denies anything else, so a plan that reports *not authorized* while the Grants table shows a row is almost always the target or the expiry, not the principal — check both.

### Scan levels

A level is a bundle of capabilities, and a capability is the only real gate.

| Level (as printed) | Capabilities | Collects | Risk |
|---|---|---|---|
| basic scan | `passive_discovery`, `active_verification` | IPs, the certificate served (issuer, validity, expiry), the technologies the response reveals | opens a TLS connection and reads what the server answers |
| advanced scan | + `vulnerability_analysis` | everything basic, plus open ports, the services behind them and their versions | active but non-intrusive: banners, headers, ports |
| deep recon | + `intrusive_testing` | everything advanced, plus content discovery — the paths and files a host exposes | more requests, including to paths that do not exist; still never tests a vulnerability |

The order is a ladder: a higher level strictly contains the one below. There is no fourth level because a fourth would not answer a new question.

### Profiles: what actually runs

A **profile** is a set of stages and tools. The console shows only the ones this plane can execute, and a profile that cannot run says why rather than disappearing.

| Profile | Level | What it does |
|---|---|---|
| `recon.simple` | simple | DNS → TLS → headers → technology. "What is this host?" |
| `web.redteam` | redteam | everything above, plus ports, services, versions and content discovery |
| `code.sast` | — | source analysis on a checkout |
| `code.secrets` | — | secret scanning on a checkout |
| `code.supply-chain` | — | SBOM plus runtime versions |
| `image.supply-chain` | — | an image's packages and CVEs |

Neither web profile hunts vulnerabilities. `nuclei`, `dalfox` and `sqlmap` exist in the catalog but hang off no web profile: the moment one did, the product would have changed category. Content discovery is the deepest thing a web tier does.

### Running one

From the **asset page → scan**, or **Orchestration → new schedule** for recurring work. The dialog asks asset, profile and an optional engagement note; the plan itself is composed by the server and frozen into the job, so the run screen never has to guess what was meant.

What must be true for it to execute:

1. a **worker** is alive and advertising a capability the job needs;
2. the target is **covered by a grant** (or the run was started by an operator, which records an administrative override — except red team, which is always re-checked as the collector);
3. the zone is under its **concurrency cap**.

Then: `queued` → `leased` → `running` → `finished` / `failed`, with steps reported as they complete.

### Reading a run

The run screen is one verdict plus the evidence under it:

- a **flow graph derived from the plan** — columns are stages, rows are steps, an edge where the plan says data moved;
- the **steps** with `items_in` / `items_out`;
- the **trace**;
- the **diff against the previous run** of the same profile on the same targets. DNS returns MX records in any order, so lists are compared as sets — a diff that cries on ordering is a diff people stop reading;
- **triage from the run**: setting a finding's status here appends a `decision` event to the same timeline.

**Coverage** is the sentence to read first. `full` is a claim about the profile; a skipped step makes it `partial` with the reason. A skipped step is never a failure: a missing image, a gate that did not fire (`wp-enum` on a non-WordPress host), a tool that answered "not applicable" — all `skipped`.

A recon run produces **no findings** by design. Its output is observations: DNS answers, the certificate, headers, technologies, ports, services. That is why the findings card can be empty on a run that worked perfectly.

### Collections and their doors

A host with 148 subdomains does not get a truncated diagram: the summary prints the true count and opens the whole list in a **panel over the page**, so comparing two rows costs no navigation. Each row carries what decides which one to open first — address, ports and products, certificate days, last observed — and the row itself is the door to that entity's screen.

The same rule applies to relationships: a collection gets a count and a door, not a sample.

### Politeness is a policy row

Concurrency is not hardcoded. Settings → Runtime holds one policy with four numbers:

| Setting | What it caps |
|---|---|
| `per_zone` | runs against one registrable domain (`example.com` and all its subdomains share one bucket) |
| `per_org` | runs in flight for the whole workspace |
| `per_worker` | runs one worker may hold |
| `queue_ceiling` | the queue's depth; beyond it, creation is refused with `429` |

The split is deliberate: the ceiling refuses **at creation** so the operator learns immediately, while the per-zone and per-org caps hold a run **`queued`** at the claim, because refusing there would mark a policy — your own policy — as a `failed` run. Six workers pointed at 200 subdomains of one owner is exactly the egress burst the zone cap exists to prevent.

The online worker pool sizes itself from the same policy (`min_workers`, `max_workers`, `scale_down_after_s`). The screen shows the **target** beside the live count; the process that applies it is a separate scaler service, because the API must never scale its own containers.

### What surface scanning is not

It is not a pentest and it is not a vulnerability scanner on hosts. Intrusive work needs a grant **and** an explicit decision, and the safe way to prove the red-team chain works is a deliberately vulnerable practice target, not somebody's production domain.

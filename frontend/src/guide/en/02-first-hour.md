This is the shortest path from an empty workspace to one finding you can show someone. It takes about an hour, and every step is a screen you can open from here.

### Step 0 — Getting in

**The very first time** (an empty database), the console opens on *Set up your workspace*. You need three things: an organization name, an owner account (email + password) and a **setup code**. The setup code is the deployment's `BOOTSTRAP_TOKEN` — the person who runs the stack has it. It is not a password and it does not survive setup.

**Every other day** you sign in with your email and password. Optional second factors, in the order the deployment supports them:

- **Multi-factor authentication** — configured per person in Settings → My security.
- **Single sign-on** — if the deployment has an identity provider, the sign-in screen offers it; you must type the organization slug first, because SSO needs to know which workspace you are entering.
- **An invitation link** (`/invite#token=…`) — single use, resolves to one seat with one role. Someone with *Administrator* or *Owner* sends it from Settings → Members.

If the top bar says **API key** instead of *Signed in*, the browser is talking to the platform with a service key. That key acts as the workspace owner, so treat the browser profile like a credential.

### Step 1 — Tell the console where the platform is

The **first run continues in a walk-through** (`/startup`): workspace and owner, organization details, invite your team, connect code, connect tickets, enter. Every step saves as you type, so a reload resumes where you left off, and an optional step can be skipped without pretending it was configured.

Settings → Account holds two things: the **platform URL** and, for automation, an **API key**. On the local Docker stack the URL is empty (same origin through nginx) and a signed-in session needs no key. You only paste a key here when the browser has no session — for example a read-only wallboard.

Settings → Organization is the workspace identity: name, logo, a sentence about the organization, its site. It is what the sidebar shows under the product mark.

### Step 2 — Declare scope before anything else

**Scope** is the list of things this workspace is allowed to care about. Declaring a target is a statement of ownership, not a permission to scan — the two are separate on purpose (see *Authorization*, below).

Targets come in eight types:

| Type | What it covers |
|---|---|
| `domain` | one hostname, or a `*.pattern` rule |
| `url` | an origin plus an optional path prefix |
| `ip` / `cidr` | a single address or a range |
| `repository` | `owner/name` on the connected code host |
| `service` / `api` | a named internal boundary |
| `cloud_account` | declarative only, no collection |

**Exclusions always win** over any target that would include them, and they can be patterns. A well-formed scope has both: what you own, and what you must never touch even if it resolves under something you own.

### Step 3 — Create the project, then its components

A **project** is one application or product. From **Projects → new project**:

| Field | What it is for |
|---|---|
| name | human name — `Aurea` |
| group | the business unit or portfolio it belongs to |
| owner | a person's address, for accountability |
| slug | the URL address: `/projects/aurea` |
| description | one sentence: what it does and who uses it |

A new project is never an empty shell: it is created with a first component. Add more from the project's *components* tab — **Backend**, **Web**, **Mobile** are components, and each one carries its own versions, repositories, environments, domains and endpoints.

Creating a component costs nothing and unlocks the rest:

- **attach a repository** — this is the authorization a CI run relies on, and without it no pipeline can be generated for that component;
- **add a version** — `1.8.0`, `main`, a commit sha; versions group builds;
- **add environments, domains and endpoints** — they are the project's own view of where it runs.

### Step 4 — Give the assets business context

**Assets** is the other inventory chain: everything actually observed — domains, subdomains, URLs, IPs. It has four tabs (what is declared, what was observed, what was seen over time, and the activity ledger), and every row answers "who owns this, how important is it, which project does it belong to".

Two things worth knowing before you touch it:

- **Assigning a project to a domain cascades to its subdomains**, but only to the ones with no project of their own, and only when you tick **with subdomains**. A click files one row; the tick files the subtree. The count you are about to move is yours to decide, not the console's.
- **`last_seen` is not evidence.** That column is when the row was written. "When did we last observe it" comes from the newest observation.

### Step 5 — Authorize analysis (this is where scanning becomes possible)

Declaring a domain opens a **grant request**. The declaration asks; it does not answer. Only **Settings → Grants** approves, and approval is what writes the scope registry the scan engine reads.

When you approve, you choose three things:

1. **The level** — a bundle of capabilities:

| Level | Capabilities | What it collects | Risk |
|---|---|---|---|
| basic scan | passive + active verification | IPs, the certificate served, the technologies the response reveals | opens a TLS connection and reads the answer |
| advanced scan | + vulnerability analysis | everything basic does, plus open ports, services and versions | active but non-intrusive: banners, headers, ports |
| deep recon | + intrusive testing | everything advanced does, plus content discovery | more requests, including to paths that do not exist |

2. **The scope the grant covers** — the host, or the host and everything under it. "Everything under it" means the apex plus `*.host`; the API owns that definition, not the screen.
3. **An expiry** — default hours, because an authorization without an end is a policy nobody revisited.

An expired or narrower grant is the most common reason a scan refuses to run while the screen says the asset is authorized. Both read the same row: compare the principal, the target and the expiry before doubting the console.

### Step 6 — Run the first scan

Two doors, same queue:

- **Orchestration → new schedule** — recurring work.
- The **asset page → scan** (also on a run screen) — a single deliberate run. The dialog asks three questions: which asset, which profile, and what this run is for (an optional engagement note). The profile list is filtered to what this plane can actually execute, and a profile that cannot run here says why instead of disappearing.

The console only **enqueues**. A run executes when a worker is alive, claims it, and the re-authorization on claim passes. If nothing happens, the answer is in *Troubleshooting*, not in the UI.

What you should see: the run appears immediately as `queued`, moves to `leased`, then reports its steps and finishes with a **coverage** (`full`, or `partial` with the sentence that explains what was skipped). Recon profiles deliberately produce **no findings** — they produce observations. That is the product, not an empty screen.

### Step 7 — Get a build in

Builds are software bills of materials. They are not typed by hand: they arrive from a scan.

- **From CI**: build a pipeline (see *Pipelines and delivery*) and push a commit. The CI announces the commit, mints a ticket, scans and uploads.
- **From a laptop**: `barad scan .` writes evidence locally; the platform side is the upload (the API accepts a CycloneDX JSON document as a raw body).
- **From the API**: `POST /api/v1/sbom` with the document as `application/octet-stream` (not JSON-encoded) and `project` / `component` / `version` in the query.

The same document twice changes nothing: ingestion is idempotent per `(project, version, content hash)` and answers `unchanged`. Re-uploading a file to “repair” stored rows is a dead end — repair happens on the read path.

### Step 8 — Triage your first finding

**Findings** is the working list. Open a row: severity, what it is, where, its evidence and its history. Then decide — that is the only thing the platform asks of a human, and it keeps the answer:

- set a **status** (open → acknowledged → in progress → resolved, or false positive / accepted risk),
- give it an **owner**,
- and if you arrived from a run, the decision is appended to that run's timeline, so six months later the run still says who looked and what they concluded.

**My work** is the same rows, filtered to you: assignments, requests, tasks and acceptances with their deadlines.

### The checklist that reads live data

Settings → **Setup guide** is not a tutorial; it is a status page. Six steps, each reading a real count from the API:

| Step | It is done when |
|---|---|
| Scope | at least one target or exclusion exists |
| Projects | at least one project exists |
| Assets | at least one asset carries business context |
| Authorization | at least one grant exists |
| Findings | at least one component is tracked |
| Cycles | at least one CTEM cycle has been created |

An empty organization shows `0 of 6` — that is the correct answer, not a bug.

### Where to go next

- *Concepts* if a word in this chapter was new.
- *Inventory* to understand what a build actually contains.
- *Attack surface* for the full declare → grant → scan → observe loop.
- *Orchestration* when a run does not move.

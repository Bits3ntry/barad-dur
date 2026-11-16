Shauron is the execution plane: the program that owns the tools, the sandbox and the network position next to a target. It is a separate repository, and it keeps nothing: a run directory and the disk.

The split that makes the whole design work:

| | Barad-dûr | Shauron |
|---|---|---|
| Owns | the key, the budget, the plan, the triage gate | the tools, the sandbox, the network position |
| Decides | what may be scanned, at which capability, by whom | which tool runs each step, with which version |
| Produces | the verdict and the record | the artefact and the typed observation |
| Depends on | Postgres | a signed ticket and pinned binaries |

You do not need to install it to read this console. You do need it to produce evidence.

### How it gets work: the ticket

The platform composes a plan and mints a **ticket** (`barad-ticket-v1`): a signed envelope naming the tasks, the targets, the capability, the principal and an expiry. Shauron verifies the signature offline and **never widens it**.

```
CI / laptop / console
     │  the platform mints the ticket
     ▼
  barad-ticket-v1   signed, expiring, scoped
     │
     ├── shauron run --ticket        (CI or laptop)
     └── POST /tickets → shaurond    (service or worker)
     ▼
  events    → POST /scans/{id}/events
  evidence  → POST /scans/{id}/evidence
     ▼
  Barad-dûr: fingerprint, store, triage
```

Four decisions that matter more than the diagram:

- **The signature is Ed25519, not a shared secret.** The private key never leaves the platform; a compromised scanner cannot mint its own authority.
- **Two economies.** `push` is for work on a machine that already has the code (CI, a laptop) — it contacts nothing on the target, so it needs no grant; the authorization is the repository→project binding. `allow` is for work that leaves the platform (clone, pull an image, touch a host) — that is where grants rule.
- **Evidence has two transports.** Small documents travel inline in an envelope; big artefacts travel as the request body with the hash, the tool and the coverage in the query. A real SARIF is megabytes of rule metadata and does not fit inline.
- **An unknown schema is refused** (`409`), never guessed.

### The four shapes, one core

| Shape | Use |
|---|---|
| `shauron` CLI | one person, one machine: scan, plan, run, upload, login |
| `shaurond` | a service that accepts tickets over HTTP |
| CI action | a repository workflow: mint, install pinned engines, scan, upload |
| worker | claims queued runs, beats before each claim, retires if the beat fails |
| field agent | one bounded AI task in a disposable container |

All of them run the same normalisation code. A tool is never told the platform exists: it writes a file into the run directory and the runner uploads it. A tool that spoke HTTP to Barad-dûr would be the second implementation that always drifts.

### Commands you will actually type

| Command | What it does |
|---|---|
| `shauron doctor` | checks the environment and the pinned engines |
| `shauron tools` | prints the catalogue of tools and profiles, offline |
| `shauron plan --profile … --target …` | composes and shows a run plan without executing it |
| `shauron surface --profile … --target …` | runs a surface scan and uploads as it goes |
| `shauron scan --platform … --api-key …` | runs a code/supply-chain scan against the platform |
| `shauron run --ticket` | executes a ticket the platform minted (the CI path) |
| `shauron ticket --out` | announces a run before the slow work, and writes the ticket |
| `shauron runtime --path . --out runtime.cyclonedx.json` | declares the interpreters and base images the tree claims |
| `shauron upload --run <dir>` | uploads an offline run: steps, then observations, then finish |
| `shauron worker --once` / `--loops N --interval S` | claims queued surface runs |
| `shauron agent run <task-id>` | runs one AI mission task |
| `shauron login` / `whoami` / `logout` | the device flow for a human session |

### Code scanning: five tasks

`sbom`, `runtime`, `misconfig`, `secrets`, `sast`. Each one names a **contract**, never a binary: `secrets` can be served by two engines at once, and every finding keeps the engine that produced it. If one provider fails while another delivers, the task survives and the failure is named in the evidence — a broken engine must never hide behind a healthy one.

Engines are pinned by version and SHA-256 per platform. A platform with no pin is refused **by name**; a binary reporting another version is refused too; an engine that exits 0 without writing its artefact is **not evidence** and the task drops with that reason.

`runtime` is the task no engine can serve. It does not look for packages; it reads what the tree *declares* (`engines.node`, `.nvmrc`, `requires-python`, `go.mod`, `.ruby-version`, `Dockerfile FROM`) and writes a CycloneDX document. A declared range stays a range.

### Surface scanning: the catalogue is data

Profiles and tools are files, not code, and the loader **fails closed**: an unknown tool, a stage reading from a stage that does not exist, a tool whose capability is above its profile's level — any of those makes the whole catalogue refuse to load, before a scan starts.

Two rules hold the product's category:

1. **No web profile hunts a vulnerability.** `nuclei`, `dalfox` and `sqlmap` exist as tools but hang off no web profile. Content discovery is the deepest a web tier goes.
2. **The basic tier is a strict subset of the deep one.** Two tiers, because a third would be a third choice with no new answer.

A step can carry a **gate**: `wp-enum` runs only on hosts whose accumulated evidence says WordPress, and when it does not, the step is recorded as `dropped` with its reason — never as a failure. That is what makes an expensive, picky tool admissible in a profile that also serves hosts it cannot read.

### The field agent

The reasoning is proxied to the platform (`POST /llm/complete`), so revoking the provider key kills every agent at once. The loop, the tools and the sandbox live here, because this is where the binaries, the isolation and the network position are.

What an agent may do is decided by the **envelope** it receives, not its judgement: targets with per-host rate limits, a tool allowlist, a lane (`validate` | `discover` | `exploit`), a step/token/wall budget, `must_return` and a deadline. The tool list the model sees is generated from the catalogue — what it is not told, it cannot choose.

Three refusals are always **events with a reason**, never silent skips: a tool outside the envelope, a target the scope check denies, and an exhausted budget.

Scope is enforced by the **absence of a route**, not by a proxy: the agent container joins an internal network whose only reachable peer is the scope proxy, because raw sockets ignore `HTTP_PROXY` and DoH, ICMP and link-local addresses never speak HTTP. That is what makes handing an agent a shell defensible — the network is the boundary, not the binary.

One task per container, and the task is typed. A long-lived agent is a context rabbit hole; a task that ends cannot be one.

### The device flow (why a URL appears in your terminal)

`shauron login` prints a short code and a URL. That code is approved by a **person** in the console, on a hidden screen (`#activate::<code>`), and an API key can never approve one — a machine credential must not mint a human session.

The code is short-lived and unambiguous, the secret is stored hashed, and the session lands in the OS keychain. If someone pastes a session token into a chat, treat it as leaked and revoke it.

### What the evidence guarantees

1. **Attributable**: the tool's version and digest travel with the ticket, so a finding traces to an exact binary.
2. **Honest coverage**: `full` or `partial`, always with the reason. `full` is a claim about the profile, not about the steps that happened to run.
3. **Skip is not fail**: missing image, missing adapter, a tool that answered *not applicable* — `skipped`, with the sentence that would fix it.
4. **Unknown is not clean**: an empty answer with no scan behind it is a question.
5. **Revocable without cooperation**: the worker kills the child, the proxy drops the flow. Neither asks the agent's permission.

### What it is not

- not a SaaS, and not a multi-tenant service;
- not an automated pentest — the web profiles are reconnaissance;
- not an AI product — the model reads, proposes and is bounded;
- not a replacement for a person: the agent proposes, the platform stores, a human decides.

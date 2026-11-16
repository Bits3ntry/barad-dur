# Surface scans: Shauron as the arsenal

Status labels follow `docs/architecture/domain-model.md`: **[live]** = shipped,
**[next]** = designed here, **[gap]** = not started.

The platform already decides *who may touch what* (`authorization.py`, grants,
exclusions) and already stores *what was seen* (`observations`, `asset_snapshots`,
the Assets tree). What is missing is the execution plane for **network** targets:
today Shauron only reads local trees (trivy, opengrep, gitleaks) and the only
network probes are the in-process DNS/TLS of `POST /assets/{id}/collect`.

This plan adds surface scanning to Shauron without a second model, a second
evidence format, or a second place where permission is decided.

---

## 1. Decisions this plan is built on

| # | decision | status |
|---|---|---|
| D1 | **Grants gate machines, not people.** A worker, a cloud button or CI need a grant. An interactive operator with an owner/admin session does not: the human is the authority. | decided |
| D2 | **The plan always comes from Barad-dûr**, even in admin/override mode. The session can skip *authorization*; it can never choose the *composition* of a scan (which tools, which versions, which order). | decided |
| D3 | **A level is a bundle of tasks**; a task is (tool, mode, capability). Levels: `simple` ⊂ `advanced` ⊂ `redteam`. They are the same axis the Grants screen already exposes. | decided |
| D3b | **Red teaming is a profile, and it only runs from Barad-dûr.** Profiles declare their plane (`cli | cloud`); `web.redteam` is `cloud`, so the CLI never has it, the laptop never pulls that image, and intrusive work always happens where the platform can revoke it mid-run. | decided |
| D4 | **Three runnable images, one release**: `scan-simple ⊂ scan-full ⊂ scan-redteam`, chained with `FROM` so layers dedupe, published with one version number and never independently. | decided |
| D5 | **Tools live in images pinned by digest**; the catalog stores references, not binaries. The repo stores ~20 lines per tool, not 50 downloads. | decided |
| D6 | **The catalog and profiles are data in the repo**; the console only *renders state* (`available / not accepted / not authorized / not installed`). Turning a task off is a policy input, and its effect is frozen into the plan. | decided |
| D7 | **Tools write files, never HTTP.** The runner uploads. One execution path for laptop, worker and swarm. | decided |
| D8 | **An exclusion is never bypassed.** It is released with a reason (`--release-exclusion`), audited, and then the scan proceeds. | decided |
| D9 | **No `--force`, no raw tool flags.** A tool that is not in the plan, not accepted for the org, not in the image, or has no adapter does not run. | recommended |
| D10 | **Redteam egress is a separate IP** from recon. | open |
| D11 | `engagement` is free text on the run, not an entity with scope and dates (yet). | open |
| D12 | Default `--keep-raw`: upload for redteam, local for recon. | open |

## 2. What exists and is reused

- `authorization.py`: `authorize()`, `revalidate()`, exclusions-first, wildcard
  never covers its apex. **[live]**
- `ScanGrant` + levels + the request/approve flow and the Grants screen. **[live]**
- `ScanJob` with `claim`/`lease`/`heartbeat`/`cancel`/`artifacts` and worker
  tokens (`orchestration.py`). **[live]** — the worker already exists as a
  contract; nothing new is needed to dispatch work.
- `contract` (`CONTRACT.md`, signed `barad-ticket-v1`, two evidence transports,
  `GET /scans/{id}/state`). **[live]**
- `POST /observations` with `kind ∈ {host, port, dns, certificate, technology,
  web_path}`, `coverage ∈ {full, partial, failed}`, `source`, and the diff that
  produces exposure events. **[live]**
- `observations` → Assets tree, asset detail, "needs attention". **[live]**
- `AssetSnapshot` as the raw, immutable observation. **[live]**
- Shauron: engine lock with per-platform sha256, fail-closed, providers-per-task,
  artifact-per-provider, evidence envelope. **[live]**

## 3. Shauron: catalog, profiles, plan

Three layers, all data except the adapters.

**Tool** (`tools/<name>.yaml`): image + digest, consumes `target_kind`, produces
`xml|jsonl|sarif|cdjson|text`, `writes: stdout|file|dir`, `capability`,
`needs: [network|net_raw|host_net]`, `cost` (seconds/target, requests), `license`,
`redistribution: allowed|forbidden`, adapter name.

**Profile** (`profiles/<kind>.<intent>.yaml`): a selection of tools in up to
three stages — `discover → probe → test` — with defaults (rate, timeouts,
parallelism) and a **plane**. Profiles compose: `web.redteam` includes
`web.exposure` instead of copying it.

| profile | level | plane | stage 1 | stage 2 | stage 3 |
|---|---|---|---|---|---|
| `recon.simple` | simple | cli + cloud | dns, tls, http-head | — | — |
| `recon.advanced` | advanced | cli + cloud | + naabu/nmap | httpx -tech-detect, wp-enum, dns-policy, takeover | — |
| `web.exposure` | advanced | cli + cloud | httpx (live hosts) | paths sensibles | — |
| `web.redteam` | redteam | **cloud only** | *(inherits exposure)* | nuclei | dalfox, sqlmap, ffuf |
| `code.supply-chain` | — | cli + cloud | trivy fs, shauron runtime | — | — |
| `code.sast` | — | cli + cloud | opengrep | — | — |
| `code.secrets` | — | cli + cloud | trivy, gitleaks | — | — |
| `image.supply-chain` | — | cli + cloud | trivy image | — | — |

The plane is enforced where the plan is resolved, not in the UI: a CLI session
asking for `web.redteam` gets `runs only from Barad-dûr` — a plane refusal, not a
grant refusal, so the operator is never told to go and request a grant that would
not help.

**Plan**: `profile × org policy × authorization × available images`. The resolver
returns every step with a state and a reason. The plan is hashed, frozen into the
run and recorded in the manifest; the platform can verify the hash on ingest.

## 4. Images

```
shauron/base            ← pinned OS by digest + common libs
 ├── tools-simple       ← dns, tls, http-head
 │    └── tools-full    ← naabu/nmap, httpx, whatweb, wp-enum
 │         └── tools-redteam ← nuclei (+templates baked), dalfox, sqlmap, ffuf
shauron/scan-simple  = tools-simple  + shauron wheel
shauron/scan-full    = tools-full    + shauron wheel
shauron/scan-redteam = tools-redteam + shauron wheel
```

Rules: base pinned by digest, never `:latest`; every tool at an exact version;
tags immutable (`2026.11.3@sha256:…`); the wheel layer goes **last** so a code
change rebuilds ~50MB; every image gets its own SBOM (trivy on itself); wordlists
and nuclei templates are baked at build and never updated at runtime, except
databases fetched with a recorded version (trivy DB, WPScan) — same as today.

The same image runs three ways: `shauron scan` on a laptop, a worker claiming a
job, or a service in Swarm. The level→image mapping is data, so a redteam plan
cannot run on `scan-simple` because the binary is not there.

## 5. The run directory (the contract that makes paths equal)

```
runs/<started_at>-<engagement>/
  plan.json            resolved plan, hashed
  raw/                 one file per invocation: <stage>.<tool>.<target>.<fmt>
  normalized/
    observations.jsonl one line per observation (Barad's shape)
    findings.jsonl
  manifest.json        plan hash, image digest, tool versions, per-step status
                       and reason, coverage, counters, sha256 of every file,
                       egress IP, actor, basis, normalizer_version
  .pending             present until upload succeeds
```

- Tools get `--out` inside `raw/`; nothing writes to the host's `$HOME`.
- A tool that cannot produce a file is wrapped (`--output-dir`); if it still
  cannot, it is not eligible for automated runs — a catalog decision, not a CLI
  hack.
- Every raw file maps to ≥1 observation, or is kept and flagged `uninterpreted`
  (the mechanism SARIF already uses). Never silently dropped.
- `coverage` is declared per step: a filtered port or a dropped VPN is `partial`,
  and `partial` never closes a finding (the existing closure rule).
- Upload is idempotent per file `sha256`; interrupted runs resume; the platform
  dedupes like it does for SBOMs.

## 6. CLI

**Login** — `shauron login --platform <url>` starts a device authorization
(RFC 8628): browser opens `/activate`, the operator signs in with email/password
and MFA if enabled, then approves a page that names the machine, the org, the
role and the scopes. Tokens land in the OS keychain, short access + rotating
refresh, bound to a locally generated keypair (proof of possession). `whoami`
prints `actor · role · org · expiry`; `logout` revokes.

**Scan** — `shauron scan --profile recon.advanced --target api.example.com`:
1. asks Barad for the plan (session of the org; no grant needed with
   owner/admin);
2. verifies the plan's steps against the image (digest, presence, adapter);
3. skips `not accepted` steps and reports them in the manifest;
4. runs the stages inside the container, writing to the run directory;
5. uploads observations + the raw files the policy says to upload;
6. prints the summary and a link to the asset in Barad.

**Offline** — `shauron plan pull … --out plan.json` before entering a client
network, `shauron scan --plan plan.json` with no connectivity, and
`shauron upload --run runs/…` afterwards. No plan means no scan: the CLI never
invents one from what it finds installed.

**Inspection** — `shauron tools` (catalog with per-org state), `shauron doctor`
(image + digest, session, org, egress IP, plan reachable), `shauron show
runs/…` (plan, steps, counters, diff against the previous run of the same
target).

**Guardrails** — the CLI simply has no intrusive profile: `web.redteam` is
refused by plane, so there is no `--intrusive` flag to misuse. Rate limits come
from the plan, never from a flag; `--release-exclusion <value> --reason` instead
of a bypass; `--actor` and `--engagement` recorded on every run. The CLI is not a
cage (anyone can run nmap by hand); it provides identity, record and ingest.

## 7. Cloud path

Asset → **scan** button → modal listing **profiles**, not tools, ordered by the
grant's level: the profile whose level the grant reaches is runnable; the wider
ones appear locked with the action that unlocks them (*approve a wider level in
Grants*). Each opens its plan with the steps' states and, for anything blocking,
the action that fixes it (enable in policy, deploy the image). Choosing a profile
mints a ticket and queues a `ScanJob`; it never runs anything inline.

A pull worker (Swarm service, N replicas) claims the job, revalidates the grant
before the first step and between stages, runs the same image with the same run
directory, and uploads.

**Red teaming gets its own worker and its own egress.** Since the profile is
cloud-only, this falls out of the design instead of being a separate decision:
the offensive worker is the only one holding `scan-redteam`, it sits behind a
different source IP, and a detection during a pentest never blocks the recon path
used every day. When the target is only reachable from inside the client network,
the answer is a worker agent deployed there — never a laptop, because intrusive
work has to run where the platform can revoke it mid-run.

## 8. Ingestion and the UI

- Evidence lands as `observations` (`source=cli:<actor>` or the worker's
  principal) + raw artifacts attached to the job.
- The asset detail distinguishes three states that are currently conflated:
  `scanned manually by <actor>` · `authorization requested` · `authorized for a
  <level>`. "No authorization" must stop meaning "never touched".
- The tree, the certificate panel and the technology block fill themselves from
  the same run; exposure events come from the existing diff.

## 8b. Run visibility: the flow is the product

Barad-dûr must see the workflow **step by step**, and the same way for both
planes. The substrate already exists: `ScanJob` (with `origin` and `executor`),
`ScanEvent`, `scan_flow.append/apply_status`, the idempotent `POST
/scans/{id}/events`, and a `GET /scans/{id}/events` timeline. What is missing is
**granularity and attribution**, not a new channel.

**A CLI run is a `ScanJob` like any other** (`origin=cli`, `executor=cli`), created
when the plan is pulled and closed on upload. One row, one timeline, one screen —
the flow view never branches on where the scan ran.

**Steps travel as events.** `progress` carries one step per call:

```json
{"event": "progress",
 "detail": {"step": "probe.nmap", "stage": "probe", "tool": "nmap",
            "status": "ok", "started_at": "...", "finished_at": "...",
            "counters": {"ports": 14, "services": 9},
            "coverage": "full", "artifacts": ["raw/probe.nmap.api.xml"]}}
```

Idempotency on `(kind, at_client)` already covers retries; the step key
(`run_id, step`) makes the upsert safe when stages run in parallel and arrive out
of order.

**Three outputs per step, each attributable:**

| output | where it lands | why it matters |
|---|---|---|
| observations | `POST /observations` → asset tree, exposures | what Barad *collected* |
| findings | findings pipeline, `tool` + `rule_id` + `occurrence.step` | what the step *proved* |
| artifacts | job artifacts, keyed by `sha256` | what the step *produced* |

A finding that cannot name the step and the artifact that produced it is
unreviewable; the adapters must carry `step_id` into `occurrences.sighting_key`
so the timeline can say "nuclei surfaced these 3 at this step" and the finding can
link back to the exact raw file.

**The timeline shows, per step**: state (`pending | running | ok | dropped |
failed | cancelled`), duration, counters, coverage, and a drill-down to what it
produced — ports, technologies, certificate, observations, findings by severity.
A dropped step says why ("nmap without NET_RAW", "443 filtered"), and a step with
zero observations shows its coverage, never a bare `0`.

**Honesty rules for the view**:

- A CLI run uploaded after the fact renders as a **recorded timeline** ("run
  offline, uploaded 19:04"), never as live progress.
- A step whose telemetry arrived but whose evidence did not shows `evidence
  pending`, distinct from `no findings`.
- A revoked grant stops the worker between stages, and the timeline shows
  `cancelled` at the step where it stopped, with the reason from the engine.
- The run summary is the engagement artifact: what was scanned, what each step
  produced, coverage, and the diff against the previous run of the same assets.

This is why the flow view lands in **P1**, not P4: it is the surface that proves
the contract works before there is any scheduler.

## 9. Phases

| phase | deliverable | acceptance |
|---|---|---|
| **P0** | catalog + profiles as data, `recon.simple` tools in the image, adapter for dns/tls/http-head | `shauron tools` lists them with states; `shauron doctor` green on a laptop |
| **P1** | CLI login + plan pull + `recon.simple` → run dir → upload + **run timeline** | scanning a granted asset from the laptop produces `observations` visible in the Assets tree with `source=cli:<actor>`, cert and IP populated, `manifest.json` with image digest and plan hash; the timeline lists each step with counters and coverage; an excluded target is refused before running |
| **P2** | `recon.advanced` (nmap/nahttpx/wp-enum) + coverage semantics | a filtered port yields `coverage=partial` and does not close an existing finding; technologies appear in the asset detail |
| **P3** | offline: `plan pull`, `scan --plan`, `upload --run` | a run made with no connectivity uploads later, idempotently, and the manifest's hashes match |
| **P4** | worker (pull) + the asset modal | the same plan run from the console produces the same observations as the CLI, with `origin=console`; no Docker socket in the platform |
| **P5** | `web.redteam` on its own worker + egress, double revalidation + window | a CLI session asking for it is refused by plane; revoking the grant mid-run stops the next stage; the offensive worker is the only one with `scan-redteam` |
| **P6** | code profiles migrated onto the same catalog (trivy/opengrep/gitleaks as tools) | the existing code scans keep passing with the new resolution path |

Order is deliberate: P1 validates mint, authorization, plan, image, adapter,
evidence and ingest in one day of work, before any scheduler exists.

## 10. Anti-goals

- No free-form YAML that executes shell, no importing third-party plugins.
- No second normalizer or a CLI-specific output format.
- No per-scan Docker orchestration from the platform.
- No tool outside the plan; no raw tool flags on the CLI.
- No silent skip: a step that did not run says so, with the reason, in the
  manifest.
- No "no findings" without the coverage that produced it.
- No opaque run: every step says what it did, what it produced and why it
  stopped — in both planes.

## 11. Open decisions

1. **D11** — `engagement` as free text (recommended for now) or as an entity with
   scope and dates.
2. **D12** — default `--keep-raw`: redteam uploads, recon keeps local
   (recommended).
3. Whether `admin` qualifies for the CLI session or only `owner`.

`D10` (redteam egress) closed itself: the profile is cloud-only, so intrusive
work only ever runs on the offensive worker, which is the one with its own IP.

## Status — P0 and P1 shipped (2026-11-06)

Built and verified end to end against the live platform, uncommitted:

- **Shauron**: `shauron/catalog/{tools,profiles}/*.json` (20 tools, 8 profiles,
  validated on load — the loader refused three incoherent catalogs while they were
  being written), `core/surface.py` (native dns / tls / http-head / dns-policy /
  takeover), `core/surfacerun.py` (run directory, manifest, step reports),
  `surface_cli.py` (`tools`, `plan`, `surface`, `upload`, `show`) and `ui.py`
  (banner, tables, step lines).
- **Barad-dûr**: `surface_plan.py` (published catalog + resolver: allow /
  not_authorized / not_accepted / not_installed / excluded, plane refusal for
  `web.redteam`), `routers/surface.py` (`/surface/catalog`, `/plan`, `/runs`,
  `/runs/{id}/steps|observations|finish`), `step` events on the existing
  `scan_flow` timeline, `backend.app` package data for the catalog.
- **Console**: `SurfaceRun.jsx` at `#surface` and `#surface::<run_id>` — verdict,
  flow graph derived from the plan, steps, trace.
- **Proofs**: 460 backend tests, 109 Shauron tests, `make lint`; a real
  `recon.simple` run put `bitsentry.xyz` in the Assets table with two addresses, a
  Google Trust Services certificate 43 days from expiry and `cloudflare`/`next.js`
  as technologies; `aura-api.bitsentry.xyz` produced `trusted=false` with the
  handshake reason and `coverage=partial` instead of a failed step.

**`shauron login` also shipped and was exercised end to end**: device code
(`device_authorizations`, migration `0053`), approval by a person in
`#activate::<code>` (an API key is refused on purpose), and a real `UserSession`
stored in the macOS keychain. After it, `whoami`, `plan` and `surface` ran with no
key in the environment at all.

Not built yet: the tiered images (`base` + `scan-{simple,full,redteam}`), the
worker and the scan modal, red team execution, and the run diff ("what is new
since the last run"). P2 (containerised tools: naabu, nmap, httpx) needs the
images before a plan can honestly report them as anything but `not_installed`.

## D4 — the offensive worker is one more Swarm service (decided)

It runs the same image and the same binary as the passive worker, as a service in
the same Swarm, **sharing the cluster's egress**. Consequences, and what they
force:

- **The grant is the only control.** With no separate IP there is nothing to
  firewall around a red-team run, so `intrusive_testing` can never be an
  `admin_override`: the plan is composed as the collector, every intrusive step is
  judged by the engine, and the claim re-checks the grant even when the job recorded
  an override. Verified both ways (refused without a grant, allowed with one).
- **Cancellation must be polled between steps.** A Swarm container can be killed,
  but a tool in the middle of a payload run has to be allowed to finish its step;
  `cancel_check` is asked between steps, and the timeline shows `cancelled` at the
  step where the run stopped.
- **The tools arrive by image, not by socket.** The service needs either
  `/var/run/docker.sock` (docker-in-docker, a privilege we should not grant an
  internet-facing service) or the tools baked into its own image. The second is the
  plan: `scan-redteam` inherits `scan-full` and adds nuclei, dalfox, sqlmap and ffuf,
  so the offensive service holds no docker access at all.
- **Egress is shared, so the run's `egress_ip` is informational, not a boundary.**
  It stays in the manifest because "which address did the target see" is still the
  first question in a post-incident review.

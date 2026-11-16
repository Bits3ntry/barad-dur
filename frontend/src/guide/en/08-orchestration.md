**Orchestration** is the console's answer to three questions, in this order: what will run on its own, who will run it, and what has run. Every run in the workspace — the platform's own sweeps, the queued jobs, and the ones a terminal started — appears here as one ledger.

If you only read one thing on this screen, read the **origin** column. `internal`, `worker` and `cli` are three different blast radii and three different people to call at 3am.

### 1. What is scheduled

Two kinds of schedule, shown together because to a reader they are the same promise:

- **your schedules** — "this scan, on this asset, every N minutes". Each row prints its cadence, the next run and the actions you can take on it (toggle, run once);
- **the platform's own sweeps** — the advisory clock and the runtime CPE matching. These are `internal` scans: they are not jobs handed to a worker, they are work the API process does itself.

An internal sweep can also be forced from its row. The answer tells you whether it was **due** or not: a job that decides its own interval answers `not_due` and writes nothing, because history is not a heartbeat — a `not_due` tick is not a run and should not appear as one.

### 2. Who runs it

The workers table is a count of **rows**, not of live processes, so it prints what the row claims and what the heartbeat says:

| Column | Means |
|---|---|
| worker | the registered name |
| slots | `max_concurrent` — how many runs it may hold |
| capabilities | the CSV of capabilities it advertises |
| status | `online` while it beats; anything else is stale |

A worker is declared **stale** after a couple of minutes without a beat, and a stale worker's claims are refused with `409 worker heartbeat is stale`. That is the design, not a bug: a worker that registered once and stopped beating must not keep taking work. If the list shows nothing alive while a run sits in the queue, the answer is almost always "the process is not running", not "the scanner is broken".

**Registering a worker here does not start one.** This row is the identity a process uses; the process itself is `shauron worker`, which in the provided stack runs as the `shauron-worker` service. A registration is a row, and a row cannot execute anything.

### 3. What has run

The ledger is every run, newest first, paginated, filterable by origin. Each row prints status, when, what kind of work, the target and the duration. A run that is `running` for over an hour is reported **stale** — a killed process must not leave a spinner forever, and no cron job is needed to say so.

### The claim protocol, in plain words

A worker's loop is three calls: **beat**, **claim**, **report**.

1. `POST /orchestration/workers/{id}/heartbeat` — "I am alive".
2. `POST /orchestration/jobs/claim` — "give me work". The platform re-authorizes the job's targets with the job's principal, checks the worker's capabilities are a **superset** of what the job needs, applies the zone and org caps, then leases it.
3. Report steps as they happen, then finish.

Two consequences worth knowing:

- **An empty claim may be a refusal.** The answer can be `{"data": null, "rejected": {"job_id", "reason"}}` — the queue had something and the engine said no. Reading that as "nothing queued" hides an authorization decision behind an idle worker.
- **A worker killed mid-run leaves the run `leased`** with its id still attached, and the next claim answers `409 worker at concurrency limit` while the run never moves. The repair is to requeue it (`status=queued`, `worker_id=null`, `lease_expires_at=null`) and claim again.

### Concurrency and the pool

Settings → **Runtime** holds the policy the claim reads on every request:

| Setting | Effect |
|---|---|
| `per_zone` | runs in flight against one registrable domain |
| `per_org` | runs in flight in the workspace |
| `per_worker` | runs one worker may hold |
| `queue_ceiling` | queue depth; beyond it, creation is refused with `429` |
| `min_workers` / `max_workers` / `scale_down_after_s` | how the online pool sizes itself |

The floor is one on purpose: zero workers and a broken scanner look identical on every screen, and that is what once made a healthy queue read as "the scan does not work".

The scaler is a **separate process**; the API publishes the target and the scaler applies it. The console shows the target read-only beside the live count — an app that scales its own containers is an app you cannot reason about.

### The platform's own jobs

The internal scans are the half of "what runs on its own" nobody scheduled by hand:

| Job | What it does |
|---|---|
| advisory refresh | re-asks OSV about the newest build of every project/component, and refreshes KEV and EPSS |
| runtime CPE matching | maps declared runtimes and image tags to NVD products and matches their CVEs locally |

Each execution is a row with its counters, its duration and its log, and the log is a door on the row. Settings → Intelligence owns the interval, the sources and whether the clock runs at all.

### Queue a job by hand

The collapsed **setup** block at the bottom of the page holds the three things that are configuration, not daily work: register a scanner, register a worker, queue a job manually. A manual job takes a scanner, a capability, a principal, a target and an environment — it is how you prove a path works without waiting for a schedule.

A run an operator starts from the console has no grant of its own; it is recorded as an administrative override so the claim's re-validation cannot kill it. The exception is red team: an intrusive profile is re-checked as the collector even behind an override, because intrusive work never runs on a human's say-so alone.

### The four fields that name a failure

When a run does not move, read these together before touching anything:

| What you see | What it means |
|---|---|
| `queued`, `attempts: 0`, `worker_id: null`, `error: null` | nobody ever claimed it: no live worker, or no worker advertising the capability |
| `leased` with a `worker_id` | a worker took it and died |
| `failed` with an `error` | the platform refused it — read the error |
| `429` at creation | the queue ceiling |
| `409 … stale` on claim | the worker stopped beating |

None of those five is a scanner problem, and four of them are fixed without touching a scan.

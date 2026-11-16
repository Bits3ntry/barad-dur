The order here is deliberate: cheapest check first, and most of these are answered without changing any code.

### A list is empty

| First check | Then |
|---|---|
| Is a filter applied? The table prints `N of M`. | clear it |
| Does the empty state say *never analysed* or *nothing found*? | if it says never analysed, the work has not run — go to Orchestration |
| Does the screen read the data you think? A `.count` on a summary card may count a different set than the table under it | read the total from the API for the same filter |

An empty table in this product is a **question**. It becomes an answer only when a scan ran and its coverage is `full`.

### A scan produced no findings

Recon profiles do not produce findings. Their output is observations: DNS, certificate, headers, technologies, ports, services. Open the **asset page** and the run's evidence, not the findings card. If the run was a code or supply-chain scan, read its coverage — a `partial` run examined less than the profile promised, and the reason is printed.

### A run sits `queued` and never moves

Read four fields together: `status`, `attempts`, `worker_id`, `error`.

- `attempts: 0` and `worker_id: null` → **nobody claimed it.** Either no worker is alive, or no worker advertises a capability the job needs. The scanner is not the suspect.
- Try the claim from Orchestration against a live worker and read the answer: an empty claim may be a **refusal** carrying a `reason`.

### A run is `leased` forever

A worker took it and died. Requeue it (`queued`, `worker_id = null`, lease cleared) and let the next claim have it. The run's steps stay; nothing is lost except the lease.

### A worker answers `409 worker heartbeat is stale`

It beats too rarely. A worker beats before each claim; one that registered and stopped beating is stale after a couple of minutes and its claims are refused. A worker whose beat fails should retire with the reason rather than claim blind — if it keeps claiming blind, every run looks frozen.

### A grant is approved but the plan says `not_authorized`

In this order:

1. **Target** — is the host (or the `*.host` wildcard) inside the grant's scope?
2. **Expiry** — has it lapsed?
3. **Level** — does the profile need a capability the level does not include? (Deep recon needs `intrusive_testing`; basic scan does not have it.)
4. **Principal** — a console approval records `console`, a plan asks as the `collector`. The platform accepts its own two principals; a plan naming anything else denies by default, which is the intended behaviour, not the bug.

### `429` when creating a run

The queue ceiling in Settings → Runtime. Raise the ceiling or wait for the queue to drain. The per-zone and per-org caps behave differently on purpose: they hold the run `queued` instead of refusing it.

### The same build uploaded twice did nothing

Correct. Ingestion is idempotent on `(project, version, content hash)` and answers `unchanged`. A repair happens on the read path; re-uploading the same bytes cannot repair rows.

### The console shows an old version after a deploy

A fragment-only navigation can keep the previous document. Navigate with a query string after a real path (`/orchestration?ui=2`) or reload with the cache ignored, then confirm the loaded bundle hash matches the file being served. Concluding "the deploy did not land" from a stale bundle is a whole wrong diagnosis.

### A link lands on the dashboard

Only `/projects…`, `/pipeline`, `/orchestration` and `/invite` are real paths. Everything else is `#key`. `#findings` works; `/findings` silently falls back. Check the crumb: `barad-dûr / dashboard` means the route did not resolve.

### The whole app is blank

A render crash blanks `#root` and looks like a routing bug: HTTP 200, no visible error. Reload with the error captured once, then report the stack — that is the fastest path, and it is almost always a state read before it is initialised.

### A certificate shows "unknown issuer · no expiry"

That is a **trust failure rendered as a certificate**. A TLS probe that fails verification stores an error, and a screen that infers trust from empty fields hides it. The trust state and its reason are the fields to read; the fix is upstream (hostname, intermediate, expiry).

### `Jira not configured`

The deployment is missing `JIRA_BASE_URL` / `JIRA_TOKEN`. Nothing in the console can supply them.

### Channels are silent

Check, in order: is the channel subscribed to the event you expect (subscriptions are per event); has it already delivered today (delivery is deduplicated per channel per day); does the receiver resolve from inside a container (`host.docker.internal`); is the port you expect actually yours (an older listener answering 404 looks like a broken integration). Use the **test** action on the channel before debugging the event.

### The AI stops early

- `stopped_budget` → a monthly cap was reached. The cap that stopped it is named on the run.
- `429` on a model call → the mission's own token ceiling, not a flake. Do not retry it as if it were transient.
- `503` → the workspace has no provider configured, or the selected one is disabled.

### Invitations do not arrive

Settings → Delivery: if the mail source is `none`, nothing was sent. The Members screen gives you the invite URL in that case — hand it over and say so, instead of asking the invitee to check spam for a mail that does not exist.

### The console cannot reach the platform

`Failed to fetch` on every screen usually means the stored **platform URL** points somewhere the browser cannot call (for example `http://127.0.0.1:8090` from a page served on another origin). On the provided stack, leave it **empty**: nginx proxies `/api` same-origin, and an explicit origin turns a working session into a CORS failure that looks like a broken screen.

### "7 workers online" when one is running

The workers table counts **rows**, and test registrations leave rows behind. A worker row is `online` only while it beats, and the deployment's configured replica count is shown beside the live one for exactly this reason. Trust the heartbeat, not the row count.

### Reporting something that is actually broken

Include: the screen (and the address in the bar), what you expected, what you saw, the **full** run/finding/asset id, the UTC time, and the workspace. With those five things a defect is reproducible; without them it is a screenshot. One rule: when you report a run that did not start, do not restart the daemon or requeue it first — the state you would destroy is the evidence.

Numbers, addresses and vocabularies. Nothing here is a tutorial; it is the sheet you keep open.

### Where things run

| Thing | Address | Notes |
|---|---|---|
| Console | `http://127.0.0.1:8092` | nginx serving the built console, `/api` proxied same-origin |
| API | `http://127.0.0.1:8090` | health at `/healthz`, OpenAPI at `/docs` |
| Postgres | `127.0.0.1:15443` | database `barad_platform`, user `barad` |
| MCP server | `barad-mcp` | a process, not a port; the client supplies transport |

Services in the provided stack: `postgres`, `platform-api`, `console`, `shauron-worker` (the pool that executes), `shauron-scaler` (the only process holding the Docker socket), and optionally `scheduler` (the ops profile that drives the advisory tick when the in-process clock is off).

`127.0.0.1` bindings are intentional. A CI runner in another network needs `PLATFORM_API_BIND` on a reachable interface (or a reverse proxy); the console never needs to be public.

### Environment that changes behaviour

| Variable | Effect |
|---|---|
| `barad_db_password` | the database password; required |
| `BOOTSTRAP_TOKEN` | the setup code that creates the first owner. Rotate it away after setup |
| `PLATFORM_API_BIND` / `PLATFORM_API_PORT` | where the API listens; `127.0.0.1` is host-only |
| `CONSOLE_PORT` / `POSTGRES_PORT` | published ports |
| `ADVISORIES_AUTORUN` / `ADVISORIES_POLL_SECONDS` | whether the API owns the advisory clock, and how often it checks whether the job is due |
| `PLATFORM_GEOIP_URL` | optional geolocation for the asset map; empty stays local |
| `NVD_API_KEY` | raises the NVD rate limit for runtime CVE matching |
| `JIRA_BASE_URL` / `JIRA_EMAIL` / `JIRA_TOKEN` / `JIRA_WEBHOOK_SECRET` | Jira integration |
| `GITHUB_API_URL` / `GITHUB_TOKEN`, `GITLAB_API_URL` / `GITLAB_TOKEN` | listing and cloning repositories |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_FROM` / `SMTP_USER` / `SMTP_PASSWORD` / `SMTP_STARTTLS` | outgoing mail |
| `SHAURON_BARAD_KEY` | the API key the worker uses |
| `SHAURON_WORKER_IMAGE` | which worker image runs |
| `SHAURON_TOOL_RUNTIME` | `local` runs the tools as child processes inside the worker |

### The screen map

Every screen in the sidebar, what it answers, and when to open it.

| Screen | Answers | Open it when |
|---|---|---|
| Dashboard | where the estate stands today | at the start of the day; it opens with one verdict |
| My work | what is mine and what is due | when you sit down to work a queue |
| Findings | what needs a decision | a finding moved, or something new arrived |
| Vulnerabilities | which advisories exist and how bad they are | someone asks "is this CVE in our estate?" |
| Chat | ask the estate a question | you would otherwise open three screens |
| AI runs | what the model did, at what cost | an AI answer needs to be traced, or a budget stopped it |
| Missions | bounded AI work and its budget | you want the field agent to do one thing |
| Cycle overview | the loop as a frame | you are explaining the programme, not fixing something |
| Cycles | time-boxed evaluations | a campaign needs a start, an end and a frozen reference |
| Scope | what this workspace is allowed to care about | before any project, asset or grant |
| Projects | applications, components, versions, repositories | you are onboarding an application |
| Assets | what was observed, who owns it, when | an asset has no owner, or its state is in doubt |
| Attack surface | observed surface and pending ownership decisions | new hosts appeared and nobody has claimed them |
| Components | the component catalogue across projects | who uses this library? |
| Exposures | reachable things that should not be | review what is reachable, not what is vulnerable |
| Prioritization rules | how priority is computed | the order of the list looks wrong for your policy |
| Business impact | open work per application | you are planning capacity, not triage |
| Pipelines | commits announced, their coverage and verdict | a build is blocked, or a commit was not scanned |
| Quality gates | what blocks a build | a gate is too noisy or not blocking enough |
| Pentests | campaign-level engagement work | a human engagement is running |
| Regression | what came back after a fix | something marked resolved reappeared |
| Builds | one artefact: packages, advisories, code findings, secrets | a build is challenged, or you need its receipt |
| Licenses | what the builds contain, by license | legal asks, or a forbidden license appeared |
| Orchestration | what runs by itself, who runs it, what has run | a run is stuck, or a schedule needs changing |
| Jira | finding ↔ ticket links and their drift | the tracker and the console disagree |
| Remediation | lifecycle of the work | you are tracking closure, not triage |
| Guide | how all of this works | this document |

Screens without a sidebar row are reached from the record that needs them — an asset from its row (`#asset::<id>`), a run from Orchestration (`#surface::<uuid>`), the analysis viewer from a finding, pull requests from a delivery gate, and the terminal approval from the URL `shauron login` prints (`#activate::<code>`).

### Vocabularies

**Finding status**: `open`, `acknowledged`, `in_progress`, `resolved`, `false_positive`, `accepted_risk`.

**Run state**: `queued`, `leased`, `running`, `finished`, `failed`. A `running` row older than an hour is reported `stale`.

**Coverage**: `full` (a claim about the profile) and `partial` (with the reason). Step states include `skipped` and `dropped`, neither of which is a failure.

**Scan levels**: basic scan → advanced scan → deep recon, each a superset of the one below.

**Capabilities**: `passive_discovery`, `active_verification`, `vulnerability_analysis`, `intrusive_testing`.

**AI lanes**: `validate`, `discover`, `exploit`. Exploit requires the red-team switch **and** a grant.

**Version confidence** (runtime CVEs): `exact` (a pin), `range` (a declared range), `line` (an image tag naming a major line).

### Addresses you will paste

| Address | Opens |
|---|---|
| `/projects/{slug}` | a project |
| `/pipeline` | pipelines |
| `/orchestration` | orchestration |
| `#guide::troubleshooting` | a chapter of this guide |
| `#findings::<id>` | one finding |
| `#asset::<id>` | one asset |
| `#surface::<full-uuid>` | one run |
| `#components::<project>/<component>/<version>` | one build |
| `#vulnerabilities::kev=1` | the known-exploited door |
| `#activate::<code>` | approve a terminal login |
| `#settings::<section>` | a settings section |

### Keyboard

`⌘K` / `Ctrl+K` focuses the search box, which jumps to any screen by name. `Esc` clears it. Everything else is a click.

### Languages

The console speaks English and Spanish. **Settings → Appearance → Language** switches the whole interface — sidebar, screens, forms and alerts — and the choice is remembered in this browser; the guide follows it chapter by chapter. The topbar's `EN`/`ES` chip is the same switch as a shortcut.

Adding a language is a folder, not a code change: copy `frontend/src/i18n/locales/en/` to a new language folder, translate the values, and the selector offers it on the next build. The guide works the same way under `frontend/src/guide/<lang>/`, and a chapter that is not translated yet says so instead of switching silently. `npm run i18n` reports what is missing.

What is never translated: the data — package names, CVE ids, hostnames, commit shas, counts, dates — and the values the API returns. Translate the label, never the payload.

### For whoever maintains the platform

| Path | Holds |
|---|---|
| `backend/src/backend/app/routers/` | one module per domain of the API |
| `backend/src/backend/app/ai/` | profiles, orchestrator, specialists, budgets |
| `backend/src/backend/app/models.py` | the schema |
| `backend/migrations/versions/` | the linear migration history |
| `frontend/src/` | the console; one stylesheet, shared primitives in `ui.jsx` |
| `frontend/src/guide/` | this documentation, as markdown |
| `mcp/` | the MCP server |
| `cli/` | the local `barad` CLI |
| `docs/` | architecture, operations, planning and the decision logs |

Deploying a change to the console is a build plus a copy into `console_html/`; the nginx service serves that directory wholesale. Deploying a backend change means the image carries the new code **and** the migration ran — a green health check does not prove either.

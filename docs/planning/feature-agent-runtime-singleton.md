# Feature: one agent runtime, many sessions (cloning 0's model)

**What this is.** A single always-on Docker instance that hosts the *execution* side of
our agents (the hands), fed by a reasoning harness inside Barad-dûr (the head), with a
non-linear thread that shows who did what, who received it, and how data moved.

**What it is not.** Not a fork of 0, not a replica-per-session, not a Swarm service. One
container, many lanes.

Why this shape: 0 is good at what it does because it separates *who decides* from *who
touches the target*, and because its agents are bounded by a typed envelope rather than
by good intentions. We keep both properties and put them on our data model.

## Implementation status (2026-11-09)

Built and verified in this pass:

- `agent_runs`, `agent_messages`, `agent_artifacts`, `candidates`, `gate_runs`
  (migration `0073_agent_runtime`), plus `ai_steps.parent_run_id/phase`,
  `agent_events.run_ref/reply_to`, `agent_tasks.parent_task_id`,
  `agent_specs.parent_slug/allowed_tools`.
- `app/harness/`: `budgets` (turn + family cost ceiling), `policy` (narrow-only
  resolution), `evidence` (stance + locator), `gates` (compose + four stages),
  `runs` (lifecycle + fan-out caps), `events` (one append point).
- Endpoints: `POST/GET /agents/runs`, `GET /agents/runs/{id}`,
  `POST /agents/runs/{id}/finish`, `POST/GET /agents/messages`,
  `POST/GET /agents/artifacts`, `POST/GET /agents/candidates`,
  `POST /agents/candidates/{id}/gates`, `POST /agents/{id}/clone`,
  `GET /agent/tasks` (the lane queue, capped per mission).
- `field-runtime`: one container, N lanes as processes, workspace per mission,
  preflight (fails fast when the image has no `agent` command), cooldown after three
  failures, health file. Built from `shauron-worker:harness` (the surface worker
  image is worker-only and has no `agent`).
- Networks: `edge` (data), `runner` (control), `probe` (execution). `shauron-worker`
  left `edge`; `field-runtime` is on `runner` + `probe`.
- Shauron catalogue: `web.hunt` (domain, redteam, nuclei) and `web.xss`
  (url, redteam, dalfox).
- Team UX: new / duplicate / archive actions, live counters, `to` + `delivered` +
  run chip in the thread.

Added in the second pass:

- **`probe.sibling`**: `grant_identities` (headers sealed with `secrets.seal`, never
  returned), `POST /agents/identities`, `GET /agents/identities`, `POST /agents/sibling`
  and the `sibling_access` gate. `leak` requires the operator's `owner_marker` to appear
  in B's response; without it the answer is `ambiguous`, because a 200 can be a public
  page. `denied` when B is refused; `ambiguous` when A itself is not authorized.
- **`sqlmap` adapter** in Shauron (`_argv_sqlmap` via `sh -c` because sqlmap writes a
  directory tree, `parse_sqlmap` reading `Parameter:` + `Type:`), plus the `web.sqli`
  profile (url, redteam).
- **Inbox**: `GET /agents/inbox` merges missions awaiting approval, runs paused for a
  decision and candidates ready to be judged; the Team view renders it as
  "waiting on me".

Still not built, and named on purpose:

- Egress proxy with a per-grant allowlist: `probe` is a bridge network today, so
  isolation is by process/workspace and by the absence of `postgres` on that network,
  not yet by an allowlist.

Operational note: after recreating `platform-api`, restart `field-runtime` — Docker's
embedded DNS keeps the old address and the lanes log `queue_unreachable`.

## 1. Scope

In scope:

- one runtime instance (`field-runtime`) running inside our compose stack, restart-safe;
- lanes: N concurrent task executors inside that one container;
- reasoning agents and subagents managed in Barad-dûr (catalogue, state, budget);
- a thread that merges chat turns, model steps, subagent messages and field events;
- artifact lineage: every request, response, tool output and candidate is traceable
  from producer to consumer;
- authorisation unchanged: `scan_grants` remains the only source of "what may be touched".

Out of scope (this feature):

- Swarm replicas, horizontal scaling, multi-host;
- static-analysis engine (tree-sitter/CPG) and binary tooling;
- a workflow graph editor;
- applying fixes (`--allow-apply` stays off).

## 2. The one-instance constraint, and what it costs

One container means:

| Consequence | Mitigation |
|---|---|
| Single point of failure | `restart: unless-stopped`, healthcheck every 20 s, jobs are idempotent and re-claimable from `agent_tasks` (status + lease) |
| Fixed ceiling (CPU/RAM) | lanes sized at deploy time (`FIELD_LANES`, default 4); queue with backpressure; per-org cap in `surface_runtime` |
| One heavy session can starve others | one **process** per lane, fair claim (oldest per mission, not global oldest), per-mission task cap |
| Sessions share a kernel and a rootfs | workspace per mission, `HOME` per lane, no shared memory, no shared env secrets |

The important property: **sharing a container is not sharing a process.** A lane is a
child process (`shauron worker` invocation) with its own workspace, its own task token
and its own cwd. A crash or a hostile payload in lane 2 must not be able to see lane 1.

## 3. Architecture

```
                    ┌──────────────── Barad-dûr (python) ────────────────┐
 console ──► api ──►│ harness/loop      reasoning + tool dispatch        │
                    │ harness/subagents per-run fork, budget, mailbox    │
                    │ harness/gates     evidence → verdict               │
                    │ agent_events      the thread (projection)          │
                    └───────┬───────────────────────────────▲────────────┘
                            │ claim/complete/events          │ task events,
                            │ llm/complete                   │ observations
                    ┌───────▼───────────────────────────────┴────────────┐
                    │ field-runtime  (ONE container, no replicas)        │
                    │  supervisor → lane 1..N  (one process each)        │
                    │  shauron worker --worker-name field-<i>            │
                    │  tools baked in: nuclei sqlmap dalfox ffuf nmap    │
                    │                  httpx whatweb opengrep gitleaks   │
                    │  workspace: /work/<mission>/<task>                 │
                    └───────┬────────────────────────────────────────────┘
                            │ egress with the task token
                    ┌───────▼─────────┐
                    │  scope proxy    │  validates token → allowlist(misión)
                    └─────────────────┘
```

Read it as three authorities: **Barad-dûr decides**, **the runtime touches**, **the proxy
admits**. None of them trusts the others' word about scope.

## 4. Who decides, who executes

| Responsibility | Where | Existing? |
|---|---|---|
| Goal, plan, delegation, subagent fork | `harness/` in Barad-dûr | **new** |
| Model calls, token accounting, ceiling (429) | `POST /api/v1/agent/llm/complete` | **yes** |
| Task envelope (targets, tools, budget, must_return) | `agent_tasks` + signature | **yes** |
| Task claim, lease, token | `POST /agent/tasks/{id}/claim` | **yes** |
| Field loop (claim → tools → events) | `shauron agent run` | **yes** |
| Tool catalogue, argv allowlist | `shauron/catalog/` | **yes** |
| Scope enforcement | scope proxy + absence of route | **yes** |
| Verification | `probe.replay` + gates | **yes** (replay), gates **new** |

The clone adds nothing to the execution contract. It adds the **head** and the
**thread** — which is exactly what is missing today.

## 5. Agents and subagents

A catalogue row is a contract; a run is an execution; an event is a line in the thread.

- **Catalogue** (`agent_specs`, exists): `slug`, `class`, `tools`, `must_return`,
  `status`, plus **new** `parent_slug` and `allowed_tools` (NULL inherit, `[]` none).
- **Run** (`agent_runs`, new): one row per agent execution, `parent_run_id` for the
  fork, `mission_id` for the session, `engine_task_id` when it delegates to the field.
- **States**, explicitly and only these: `queued → running → waiting_approval →
  running → done | failed | blocked | budget_exhausted`. `blocked` always carries a
  reason; `waiting_approval` is the only state a human resolves.
- **Bounded by construction**: `allowed_tools` is intersected down the fork chain; the
  field envelope carries the same list; the registry in the runtime refuses anything not
  in it. Three locks, one list.
- **Creating more** is a catalogue write (`POST /agents`, exists) plus optional
  `clone`. A new spec starts `draft`: it can be composed, not dispatched.

## 6. Data model

```sql
-- new
agent_runs(id, org_id, mission_id, parent_run_id, spec_slug, thread, status,
           goal, max_turns, turn_count, cost_ceiling_usd, cost_usd,
           tokens_in, tokens_out, engine_task_id, started_at, ended_at, blocked_reason)

agent_messages(id, org_id, mission_id, from_run, to_run, to_spec, kind,
               body, reply_to, delivered_at, read_at)

agent_artifacts(id, org_id, mission_id, run_id, task_id, kind,      -- request|response|tool_output|candidate|report
                sha256, bytes, storage, meta, produced_at)

candidates(id, org_id, mission_id, run_id, title, severity, claim,
           evidence_json, state)                                     -- proposed, never confirmed
gate_runs(id, org_id, candidate_id, stage, verdict, reason, evidence_ref, created_at)

-- deltas on existing tables
agent_events.run_ref text;            -- grouping a family in one collapsible block
agent_events.reply_to text;           -- non-linear thread edges
agent_tasks.parent_task_id text;      -- subagent task spawned by another task
ai_steps.parent_run_id text, phase text, priced boolean;
agent_specs.parent_slug text, allowed_tools jsonb;
```

`agent_events` stays a projection — never a second source of truth.

## 7. Contracts (only two new endpoints)

```
POST /api/v1/agents/runs                 {spec_slug, goal, mission_id, budget}
                                         → {run_id, status, thread}
GET  /api/v1/agents/runs/{id}            → {status, parents, children, budget,
                                            artifacts[], candidates[], blocked_reason}
```

Everything else already exists: claim, events, complete, scope/check, threads.

## 8. Isolation between sessions — the part that decides if this is safe

1. **Workspace per mission**: `/work/<mission_id>/<task_id>`, created by the lane,
   removed on exit. No mission can read another's tree (different uid? no: different
   path plus a lane that only receives its own task).
2. **HOME per lane**: `/home/lane-<i>`; the field loop's credentials and caches do not
   cross lanes.
3. **Token per task**: the proxy validates `X-Agent-Token` and resolves the allowlist
   from *that task's mission*. A token from mission A on a host of mission B is a 403,
   and the refusal is recorded as an event on A.
4. **Env sanitized by allowlist**, never by denylist: the lane receives the platform
   URL, `X-Agent-Token`, workspace, lanes id. Nothing else.
5. **No shared `HOME`, no shared DB handle, no shared findings writer.** A lane returns
   observations; the platform ingests them.
6. **One process per lane**, not a thread pool: a payload that exhausts memory must die
   with its lane, not with the runtime.

Acceptance for this section is a test, not a paragraph: mission A's task cannot open
mission B's workspace, and its token cannot reach mission B's host.

## 9. Data movement (what the operator must be able to see)

```
reasoning run ──goal──► agent_task ──claim──► lane ──tool──► artifact(request/response)
      ▲                    │                    │                     │
      │                    │ events ────────────┘                     │
      └── candidate ◄── observations ◄─────────────────────────────────┘
              │
              └── gates ──► finding (replay-proven) ──► estate
```

Every artifact row answers: who produced it (`run_id`), under which task (`task_id`),
for which mission, with which sha256, and which consumer read it. That is the answer to
"how does data move", and it is also the audit trail when a finding is questioned.

## 10. UX: a thread, not a chat log

**Definition.** A thread is a directed graph of events, rendered linearly by time but
grouped by run: `reply_to` gives the reply edges, `run_ref` gives the grouping,
`to_run`/`to_spec` gives the recipient.

Three views:

1. **Team** (left): catalogue cards — avatar, purpose, tools, `status`, live counters
   (active runs, cost today). Actions: new, duplicate, archive. A draft cannot be
   dispatched and says so.
2. **Thread** (centre): every line has an author (avatar + role), a recipient when it is
   addressed, and a kind (`message`, `status`, `tool`, `artifact`, `gate`, `handoff`).
   Delegations are collapsible blocks containing their subagents; subagents are indented;
   the live status line sits under the active one. Handoffs read "→ Palantír" and become
   "delivered" when the parent consumes them.
3. **Data map** (right, toggled): the artifact lineage for the mission — requests,
   responses, tool outputs, candidates — each with producer, size, hash and the run that
   read it. This is the "not only chat" view: it answers what actually left the platform.

Filters that matter: by run, by kind, and **"waiting on me"** (the only queue an
operator actually needs).

## 11. Capacity and limits

- `FIELD_LANES` (default 4) processes; `FIELD_LANE_CAP` per mission so one session cannot
  take all lanes.
- `surface_runtime` keeps the org ceiling, queue ceiling and per-zone concurrency; the
  lanes must not exceed the grant's rate limit — a lane knows its budget from the
  envelope and the proxy enforces the rest.
- Backpressure: the claim returns empty → the lane sleeps with jitter; no busy loop.
- A mission beyond its budget stops creating tasks; running tasks finish or are cancelled.

## 12. Acceptance criteria

1. Three missions × four subagents run against **one** container (`docker ps` shows one
   runtime) with no cross-contamination: A cannot read B's workspace, A's token cannot
   reach B's host, both failures recorded as events.
2. The thread shows, for one delegated run: the goal, each subagent with its author line,
   each tool call with its duration, each artifact with its hash, and the handoff back to
   the orchestrator marked delivered.
3. Killing the runtime mid-run leaves tasks `leased`; on restart they are re-claimed and
   finish, and the thread shows the retry instead of a gap.
4. A candidate without a stored request cannot become a finding; the refusal names the
   missing evidence.
5. Cost per mission equals the sum of its runs' `AiStep` rows within 1%.

## 13. Risks

| Risk | Why it matters | Mitigation |
|---|---|---|
| One container, one blast radius | A hostile payload compromises the runtime | lanes are separate processes; rootfs read-only; no socket; egress only through the proxy; workspace per mission removed on exit |
| Claim fairness | One mission with 50 tasks starves the rest | per-mission cap in the claim query, not in the client |
| Image weight (~2 GB with tools) | Slow deploys, long pulls | one image, tools baked at build, digest pinned; no per-tool images inside the runtime |
| Tool drift | A scanner changes flags and the lane silently skips | `catalog.load()` fail-closed + a smoke task per tool in CI |
| Thread noise | 18 subagents produce thousands of events | grouping by `run_ref`, status lines overwrite (not append), artifacts collapsed |

## 14. Phases

| Phase | Work | Est. |
|---|---|---|
| 1 | `field-runtime` image + supervisor + lanes + workspace per mission; worker out of `edge` | 1 week |
| 2 | `harness/` loop + subagents + `agent_runs`; thread merges chat + steps + task events; `reply_to` | 2 weeks |
| 3 | `candidates` + `gate_runs` + `probe.replay` as stage; artifact rows with lineage | 1 week |
| 4 | Team CRUD + clone + "waiting on me" + data map | 1 week |
| 5 (optional) | redteam catalogue: `web.hunt` profile, sqlmap adapter, payload catalogue | 1 week |

## 15. Open decisions

1. **Fairness policy**: cap per mission, or round-robin across missions at claim time?
   The first is a query; the second is a scheduler. Start with the query.
2. **Lanes**: 4 processes or a supervisor with backoff? A plain `s6`-style supervisor
   plus restart is enough for one container.
3. **Where do artifacts live**: Postgres rows with `storage` pointer, or files in a volume
   with rows? Recommendation: rows for metadata, volume for bodies, `sha256` in both.
4. **Do subagents get their own model or inherit?** Default inherit; per-run override is
   a catalogue field, not a prompt instruction.

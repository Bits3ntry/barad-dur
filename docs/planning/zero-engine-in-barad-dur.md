# 0 as Barad-dûr's AI engine: architecture

> **Superseded.** Decision as of 2026-11-09: we build our own harness in Python and take
> only the method. See `own-harness-architecture.md`. This document stays as the reference
> for the surface we would have exposed if we had run their binary.

Decision: **0 sec is the execution engine for the AI work, running as one always-on
worker inside our compose stack.** Barad-dûr keeps the data, the authority and the
judgment; 0 keeps the harness, the prompts and the parallel subagents.

This document is the design, not the implementation. Every external flag quoted here
was read from the cloned source (`~/.hermes/cache/scratch/zero-repo`, 2026-11-09).

## 1. Why this shape

| What we keep | What we borrow |
|---|---|
| Estate data (SBOM, versions, deployments, KEV/EPSS) | The agent harness and its turn loop |
| `scan_grants` as the authority | The subagent fan-out and its messaging |
| `probe.replay` as the final proof | Workflows, skills, templates |
| The ledger and the human gate | The prompts that are actually calibrated |

0 has 255k lines of source and 959 tests behind it. We are not going to re-derive that.
But it also ships two holes we must not inherit — a `runtime-verify` that returns
`confirmed: true` when there is no key, and a scope plugin that is off by default.
Section 8 is about closing both at our boundary.

## 2. Topology

```
console ──► platform-api ──► postgres            [edge]
                │
                ├──► llm-gateway ──► opencode Go  [edge + runner]
                │        ▲
                │        │ OPENAI_BASE_URL
                ├──► zero-adapter ──► zero-engine [runner]
                │                         │
                │                         │  [probe] internal
                │                         ▼
                │                    egress-proxy ──► authorized hosts only
                └──► surface_runtime (capacity) ──► shauron-scaler
```

Three networks, and the separation is the security model, not decoration:

- **edge** — data plane: `postgres`, `platform-api`, `console`. Nothing that runs
  untrusted input stays here.
- **runner** — control: `platform-api`, `llm-gateway`, `zero-adapter`, `zero-engine`.
  No database reachable from here.
- **probe** — execution: `zero-engine`, `egress-proxy`, ephemeral sandboxes.
  `internal: true`, no gateway, no route to the other two.

`shauron-worker` moves out of `edge` in the same change: it executes payloads and today
it can resolve `postgres`.

## 3. Four services

### 3.1 `llm-gateway` — the piece that makes it "ours"

An OpenAI-compatible endpoint (`POST /v1/chat/completions`) built on
`ai/engine.py:complete`, which already speaks that wire format
(`engine.py:192`) and already writes `AiStep` rows. What it adds:

- one **ephemeral key per run** (`sk-barad-<run_id>`) instead of our provider key, so
  the engine container never holds a real credential;
- `run_id`, `org_id` and `model` stamped on every `AiStep`;
- a hard ceiling checked before each call, and `priced=true` semantics — a model that
  returns no usage is an error, never "$0";
- provider indirection: swapping `opencode-go` for anything else is a row, not a deploy.

0 resolves its model from `OPENAI_BASE_URL` / `OPENAI_API_KEY` / `OPENAI_MODEL` /
`OPENAI_WIRE_API` (`core/src/runtime/llm-api.ts:1217`), so pointing it here needs no
patch to their code.

### 3.2 `zero-engine` — always alive

Built from the release binary (there is no app image in the repo; only
`0verse/Dockerfile` for the binary-analysis server). Always-on, not per-job, because
we want sessions, retained runs and its memory to survive between turns.

```yaml
zero-engine:
  image: zero-engine:sha-<release-digest>
  restart: unless-stopped
  user: "65534:65534"
  read_only: true
  tmpfs: ["/tmp:rw,noexec,nosuid,size=512m"]
  cap_drop: [ALL]
  security_opt: ["no-new-privileges:true"]
  pids_limit: 512
  mem_limit: 2g
  networks: [runner, probe]
  environment:
    OPENAI_BASE_URL: http://llm-gateway:4000/v1
    OPENAI_MODEL: deepseek-v4.1-flash
    ZERO_MODEL: deepseek-v4.1-flash
    ZERO_PROVIDER: openai
    ZERO_SUBAGENT_CONCURRENCY: "6"     # their default is 32
    ZERO_HOME: /home/zero/.0
  volumes:
    - zero-home:/home/zero/.0           # its memory/skills, persisted
    - zero-work:/work                   # one clone per target
```

`ZERO_SUBAGENT_CONCURRENCY` down from 32 to 6 is deliberate: 18 children at 32
parallel model calls is how a $2 run becomes $40.

### 3.3 `zero-adapter` — our contract, not theirs

~200 lines, Python, no state of its own. It is the only thing Barad-dûr talks to, so a
0 upgrade never changes our API.

```
POST /runs            {goal, target, template?, workspace, scope_json, budget}
                      → {run_id, status}
GET  /runs/{id}       → {status, nodes[], findings[], cost, tokens, error}
GET  /runs/{id}/events?after=<cursor>   → NDJSON/SSE of harness events
POST /sessions        {goal}             → {session_id}          (chat mode)
POST /sessions/{id}/turns  {text}        → {turn_id}
GET  /sessions/{id}/events?after=<n>     → events
GET  /health          → {binary, version, model, concurrency, workspaces}
```

It translates to the real CLI flags, which we read from `cli/src/commands/workflow.ts:185-191`:

```bash
0 workflow run --template security-research \
  --target <url> --workspace /work/<slug> --scope /run/scope.json \
  --model deepseek-v4.1-flash --format json \
  --time-cap <ms> --cost-cap <usd>
```

`--allow-apply` is never passed. We want candidates, not patches.

### 3.4 `egress-proxy` — the only way out

In `probe`, resolves DNS itself (no rebinding), re-validates every redirect, blocks
RFC1918 / loopback / `169.254.169.254`, and allows exactly the hosts in the run's
grant — including `host.docker.internal:19090`, which already appears in our data.

The scope JSON we hand 0 is generated from the same grant (`scope_from_grant()`), so the
logical boundary and the network boundary describe the same set. If someone edits one,
the other still holds.

## 4. A chat turn, end to end

1. Operator writes in `#agents`; the console posts a turn to the chat session.
2. Palantír (our orchestrator) decides: **answer from our data** (tools read, fast) or
   **delegate to the engine**.
3. If it delegates, it calls the `harness.run` tool → `POST /runs` on the adapter, with
   a budget and a scope built from `scan_grants`.
4. The adapter creates `agent_runs` (parent = the chat turn's run) and `harness_jobs`.
5. The engine starts; every model call lands in `llm-gateway` → `ai_steps` with the
   same `run_id`.
6. The engine emits events; the adapter maps them to `agent_events` on the thread.
7. On finish, its findings arrive as **candidates**. Each one enters `gate_runs`:
   evidence present → host authorized → our own `probe.replay` → marker match.
8. Only a candidate that passes all four becomes a `finding`. Its harness verdict is
   stored as `assumption`, never `observation`.

## 5. Event mapping (this is what makes the UX work)

| 0 event | `agent_events.kind` | rendered as |
|---|---|---|
| `node_started` | `step` | a collapsible work block ("Recon", "Verify") |
| `subagent_spawned` | `subagent` | an indented author line with avatar |
| `report_status` line | `status` | the live one-liner under that author |
| `send_message` / `check_messages` | `message` | a thread reply between children |
| tool call | `tool` | tool chips inside the block |
| `cost_update` | `budget` | the bar: tokens, $, elapsed |
| `node_completed` + artefact | `artifact` | attachment card with `sha256` |
| gate verdict | `gate` | pass/refuse with the reason |

`agent_events` already carries `thread`, `seq`, `author_spec`, `kind`, `body`, `refs`.
Adding a `run_ref` column is enough to group a whole run into one collapsible block
without a second store.

## 6. Data model additions

```sql
agent_specs.parent_slug text references agent_specs(slug);
agent_specs.allowed_tools jsonb;        -- NULL = inherit, [] = none (narrow-only)

agent_runs(id, org_id, thread, parent_run_id, spec_slug, engine_run_id,
           goal, status, max_turns, turn_count, cost_ceiling_usd, cost_usd,
           tokens_in, tokens_out, started_at, ended_at);

agent_events.run_ref text references agent_runs(id);   -- grouping only

harness_jobs(id, org_id, run_id, template, target, workspace, scope_json,
             status, exit_code, output_sha256, created_at);

candidates(id, org_id, run_id, title, severity, claim, evidence jsonb,
           state);                                      -- proposed, not confirmed
gate_runs(id, org_id, candidate_id, stage, verdict, reason, evidence_ref, created_at)
```

`agent_specs` already exists with 4 rows and a `tools_missing` guard; `POST /agents` and
`PATCH /agents/{id}` are already written and audited. The UX below sits on top of them.

## 7. UX — three views, no new concepts

**Team (`#agents`, left column).** Each card: avatar, name, class, one-line purpose,
tool count, `status`, and two live numbers — active runs and `cost_usd` today. Actions:
*new*, *duplicate*, *archive*. This is the screen that answers "which subagents exist
and what does each do".

**Thread (right column, the chat).** Orchestrator messages at top level; each delegated
run appears as a collapsible block containing its subagents (indented, own avatar and
the live status line), tool chips, budget bar and final artefact. Replies between
children show as quoted lines, which is what makes an 18-child run readable instead of
a wall.

**Run detail (drawer).** Node list with status and duration, inputs, the exact scope that
was sent, the model and cost per node, and the gate verdicts for each candidate.

What is deliberately *not* built: a flowchart editor. The graph is theirs; we render
what ran, not what could run.

## 8. Guardrails at our boundary

1. **Their verdict is an assumption.** `runtime-verify.ts:139-144` confirms by default
   when `E2B_API_KEY` is unset. Their "confirmed" enters `candidates`, never `findings`.
2. **Our replay is the proof.** `probe.replay` stays as the final gate: authorized host,
   stored request, `expect` marker. It is the only stage that can promote a candidate.
3. **Concurrency is capped** at the engine (`ZERO_SUBAGENT_CONCURRENCY`) and at the
   gateway (per-run ceiling). Two independent brakes, because theirs can be raised by
   env.
4. **Scope is generated, never typed.** `scope_from_grant()` from `scan_grants`; a host
   outside it is refused by the network too.
5. **`--allow-apply` off.** The engine proposes; a human applies.

## 9. Order of work

| Phase | Deliverable | Acceptance |
|---|---|---|
| 1 | `llm-gateway` + ephemeral keys + ledger | a run's calls appear in `ai_steps` with `run_id` and a cost; a key from a finished run is rejected |
| 2 | `zero-engine` + `zero-adapter` + `harness.run` tool | from the chat, "analizá el repo de AUREA" produces a run with nodes and a cost, and the container cannot resolve `postgres` |
| 3 | event mapping + Team/Thread UX | an 18-subagent run reads as nested blocks with live status; budget bar matches the ledger |
| 4 | `candidates` + `gate_runs` + replay promotion | a candidate that fails the replay never becomes a finding |
| 5 | `scope_from_grant` + `egress-proxy` | a host outside the grant fails with an explicit reason, both at the engine and at the network |

## 10. Open decisions

- **Hybrid or full delegation.** Recommendation: hybrid. Palantír answers estate
  questions from our tables (fast, cheap, exact) and delegates only what needs the
  harness. Sending every "¿cuántos findings abiertos tengo?" through a 40-turn agent is
  paying for reasoning we already have as SQL.
- **MCP or our own HTTP contract.** Recommendation: HTTP (`zero-adapter`). MCP gains
  us nothing here and couples our API to their schema.
- **Workspace lifecycle.** Fresh clone per run (clean, 10-20 s) versus cached with
  `git fetch`. Start with fresh; revisit when runs get frequent.

# Our own harness: architecture

**Decision.** Barad-dûr builds its own agent harness in Python, taking the *method* from
0 sec — gates, evidence with stance, hierarchical budgets, narrow-only policy, skills,
versioned workflows — and none of its code. No external binary, no adapter, no fork.
Their 255k lines of TypeScript solve problems we do not have (static analysis with
tree-sitter and CPG, binary reversing, fuzzing, PR review); they do not solve the two
that matter most to us (multi-tenant authority, and proof against our estate).

Supersedes `zero-engine-in-barad-dur.md`, which described integrating their binary.
That option is kept only as a reference for the surface it would have exposed.

## 1. What we take, what we leave

| Take (method) | Leave (their code and scope) |
|---|---|
| Gate as an interface, composed by short-circuit | `agentic-scanner` / `unified-pipeline` orchestration |
| Evidence with stance (`observation` vs `assumption`) + locator | tree-sitter, CPG, invariant mining, fuzzing |
| Hierarchical ledger, ceiling checked before each call | 15 tool domains we will never call |
| Subagent fork that inherits authority and cannot widen it | Node runtime, SQLite, single-user model |
| Skills as versioned YAML with triggers | their 959 tests (we write ours per mechanism) |
| Immutable workflow definitions, snapshot per run, server-side approval | their UI and graph editor |
| Knowledge that cannot exist without evidence and expires | their memory files on disk |

The prompts are the one thing we adapt rather than invent: their *structure* (role,
goal, constraints, contract, output shape, one hard rule per paragraph) is the part
that was validated against real systems. The *text* gets rewritten to our vocabulary —
`asset`, `grant`, `purl`, `finding`, `candidate` — because a prompt that talks about
"targets and engagements" when the tool is named `authorized_targets` makes the model
guess.

## 2. Shape

```
backend/src/backend/app/harness/
  loop.py          turn loop: build → call → dispatch tools → fold usage → decide
  policy.py        narrow-only phase policy (ContextVar), effective-tool resolution
  subagents.py     fork, concurrency semaphore, mailbox, post-join merge
  gates.py         Gate protocol, compose_gates(), the stages we ship
  claims.py        claim + evidence (stance, locator), terminal-state rules
  budgets.py       ledger hierarchy, ceiling checks, priced-usage enforcement
  compress.py      context compaction with literal preservation
  skills.py        YAML corpus loader, trigger matching, JIT selection
  learning.py      knowledge/evidence/freshness cycle
  workflows.py     definition validation, topological run, snapshot, approvals
  prompts/         one module per role, versioned by content hash
  tools/           our tools: estate reads, probe.replay, probe.request, scope
  events.py        canonical event → agent_events projection

backend/src/backend/app/runners/
  sandbox.py       docker run per execution: profiles, no socket, no secrets
  egress.py        proxy client, host allowlist from grant, DNS revalidation
```

Nothing here imports a router except through the dispatch table, which is the rule we
already follow in `app/ai/`.

## 3. The loop (`harness/loop.py`)

One turn is: check budget → build prompt → call model (tool_use wire) → fold usage into
the ledger → dispatch tool calls → decide continue / answer / stop.

Load-bearing details, each one earned from a failure we already had:

- **The ceiling is checked before the call**, not after. After is an invoice, not a brake.
- **A call that returns no usage is an error** when `priced_required`, never "$0". We
  already shipped that bug once with `finish_reason=length`.
- **The last turn has no tools** (`ANSWER_NOW`): a tool loop that exhausts its budget
  ends with "the plan produced no answer text", which the operator reads as a crash.
- **Terminal states are explicit**: `answered`, `budget_exhausted`, `blocked`, `failed`,
  and `budget_exhausted` keeps the partial answer. Never a silent cut.
- **Every iteration writes one `AiStep`** with `phase`, `model`, `tokens_in/out`,
  `cache_read`, `priced`, `finish_reason`, `tool_calls`, `parent_run_id`.

## 4. Subagents (`harness/subagents.py`)

An `AgentRun` row is the child. Not a thread, not a conversation: a row with
`parent_run_id`, `spec_slug`, `max_turns`, `turn_count`, `cost_ceiling_usd`.

- **Inheritance is a resolution, not a copy**: `effective_tools = requested ∩ inherited`;
  `None` means inherit, `[]` means none. A child asking for a tool its parent does not
  have is a rejection at dispatch, not a sentence in a prompt.
- **The ledger is shared**, so a mission ceiling binds the whole family. Without that, a
  $3 ceiling becomes $3 per child.
- **Concurrency is a semaphore**, not `asyncio.gather` of everything: global limit plus
  a per-org limit that reads `surface_runtime`.
- **The child never writes findings.** It returns candidates; the parent merges after
  the join, in input order. No concurrent writers, no lost updates.
- **Mailbox with no authority**: `send_message` / `check_messages` move text between
  runs; a message can never widen scope, approve a tool, or change autonomy mode.
- **`report_status`** writes a `status` event on the thread, sanitized (control chars,
  bidi, zero-width) because it is prose written by another model and rendered in the
  operator's view.

## 5. Gates and claims (`harness/gates.py`, `harness/claims.py`)

```python
class Gate(Protocol):
    def __call__(self, candidate: Candidate, ctx: GateContext) -> GateVerdict: ...
# GateVerdict(confirmed: bool, reason: str, evidence_ref: str | None, cost_usd: float)

def compose_gates(*stages: Gate) -> Gate:   # stops at the first refusal; an exception is a refusal
```

The stages we ship, in order, and why each has to exist:

1. `evidence_present` — a candidate without a captured request, response or locator is
   an assumption and goes no further.
2. `authorized_target` — the host resolves through an active, unexpired `scan_grant`.
3. `replay` — our `probe.replay`: the stored request, re-sent, with the credential
   headers dropped.
4. `expect_match` — the operator's marker appears (or the state is `observed`, which is
   not a confirmation).
5. `novelty` — optional, against our own findings and the KEV catalog, so "new" means new.

Claims close the loop: a claim reaching `validated` requires at least one `observation`
with a locator. An assumption can be stored, cited, and shown — it cannot confirm.

## 6. Budgets (`harness/budgets.py`)

```sql
agent_runs(id, org_id, thread, parent_run_id, spec_slug, status,
           max_turns, turn_count, cost_ceiling_usd, cost_usd,
           tokens_in, tokens_out, started_at, ended_at)
ai_steps.parent_run_id, ai_steps.phase, ai_steps.priced      -- added
```

`total_cost(run)` walks to the root; `own_cost(run)` is attribution. Three checks: loop
header, pre-dispatch, and an `on_spend` callback that cancels the shared task group.
Exhausting a budget is a state, not an exception, and it keeps what was found.

## 7. Skills and learning

Skills are versioned YAML in `harness/skills/` — `id, name, description, version,
roles[], triggers[] (regex), tags[], estimated_tokens, body`. Selection is never "inject
all": tags and triggers mark them suggested when **two distinct patterns** match recent
tool output, and one deterministic preload by vulnerability class. The two-pattern rule
is anti-noise: a single keyword match is how every skill ends up in every prompt.

Learning keeps four invariants, all cheap to enforce and all costly to miss:

1. A lesson cannot be stored without at least one evidence event in the same org.
2. A lesson points at sources (`purl@version`, `grant.id`, `finding.id`, doc path) and
   never embeds them.
3. When a source changes, the lesson is `stale`; `stale → current` requires new evidence,
   and the API answers 409, not a status edit.
4. Recalled lessons enter the prompt labelled **untrusted hints, not evidence**, with a
   byte cap, and the recall is itself an event (`recall_audit`), so we can answer "which
   lesson influenced this run".

Our sources are better than theirs: `pkg:docker/node@22-alpine` changing version is a
fact we already track, so "the lesson expired" is a query, not a re-hash of files.

## 8. Workflows (`harness/workflows.py`)

Definition JSON `{schemaVersion:1, workflow:{name, instructions, target, nodes, edges}}`,
2-16 nodes, one trigger, ≤1 report, acyclic, everything reachable. Saving or importing
creates a **draft that executes nothing and grants nothing**.

```sql
workflows(id, org_id, current_revision, name)
workflow_versions(workflow_id, revision, definition_json, parent_revision, digest,
                  primary key (workflow_id, revision))
workflow_runs(id, org_id, workflow_id, workflow_revision, definition_snapshot,
              target, status, approval_token_hash, approved_by, started_at, ended_at)
run_step_results(run_id, node_id, status, error, artifact_refs, primary key (run_id, node_id))
```

Edit is CAS on `revision`; rollback inserts a new revision; the run stores the frozen
snapshot; the launch endpoint requires `{revision, approval:"launch-authorized-run"}` and
re-checks the grant, because **the button is UX and the server is the gate**.

Policy per phase: `ContextVar[PhasePolicy]` with `instructions: tuple[str, ...]` and
`allowed_tools: frozenset | None`. Merge = concatenate + intersect. Children inherit; an
inner phase can narrow, never widen. Our workers are separate processes, so the effective
allowlist is serialized into the spawn payload or it is not enforced.

## 9. Execution (`runners/`)

The harness runs inside the API process; anything that touches a target runs in a
container:

- **Profiles, not flags.** The job names a profile (`probe-http`, `probe-shell`) defined
  in code; the caller never supplies binds, capabilities or network. A job that could
  pass `-v /var/run/docker.sock` would be root in three lines.
- **One container per execution**, `--rm --read-only --tmpfs --user --cap-drop ALL
  --no-new-privileges --pids-limit --memory --cpus`, image pinned by digest.
- **Network**: `probe`, `internal: true`; egress only through the proxy, whose allowlist
  is generated from the same grant as the scope.
- **Artefact by stdout**, ≤1 MiB, with `sha256`, and a `sandbox_runs` row for every
  execution: image digest, argv hash, allowlist, exit code, duration, output hash.

## 10. Size, honestly

| Module | ~lines |
|---|---|
| loop + prompts plumbing | 700 |
| subagents + mailbox + semaphore | 450 |
| gates + claims | 550 |
| budgets + compression | 500 |
| skills + learning | 650 |
| workflows + policy | 700 |
| runners (sandbox + egress) | 400 |
| routers + events projection | 400 |
| **total backend** | **≈4.300** |
| frontend: Team / Thread / Run drawer | ~700 |

Plus the corpus (prompts and skills), which is where the quality lives and where we
adapt rather than translate.

## 11. Order of work

| Phase | Deliverable | Acceptance |
|---|---|---|
| 1 | `loop.py` + budgets + `AiStep` columns + `agent_runs` | a run stops at its ceiling with `budget_exhausted` and keeps its partial answer; a call without usage fails loudly |
| 2 | `subagents.py` + mailbox + `report_status` | a parent spawns 3 children under one ceiling, each with its own avatar line; a child cannot call a tool its parent lacks (tested at dispatch) |
| 3 | `gates.py` + `claims.py` + `probe.replay` as stage 3 | a candidate without evidence cannot become `validated`; a stage that raises never confirms |
| 4 | Team + Thread UX | an 18-run family reads as nested blocks with live status and a budget bar matching the ledger |
| 5 | `workflows.py` + policy | importing a definition executes nothing; editing without the current revision is rejected |
| 6 | `runners/` + `scope_from_grant` | a host outside the grant fails at the engine *and* at the network; every execution leaves a hash |

## 12. What we will not build

- Static analysis over source (tree-sitter, CPG, dataflow). If we need it, it is a
  separate product decision; it is 60% of their code and 0% of our current use case.
- Binary analysis, fuzzing, PR review.
- A graph editor. Render what ran.
- A second conversation store. The thread stays a projection of `agent_events` and
  `ai_steps`.

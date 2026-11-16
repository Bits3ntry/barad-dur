# How 0sec-labs/0 works, and how to rebuild it inside Barad-dûr

Analysis of `github.com/0sec-labs/0` (cloned at `~/.hermes/cache/scratch/zero-repo`,
commit of 2026-11-09) with one question only: **which mechanics do they use that we
should reproduce in Barad-dûr, and in what order.**

No code is copied. Their code is MIT/Apache-2.0, so copying is legal; it is also
pointless, because the stack is Node/SQLite/single-tenant against our
Python/Postgres/multi-org. What travels is the design.

## 0. What it actually is

| | |
|---|---|
| Surface | local web console + CLI + MCP server, one engine behind |
| Storage | SQLite per user (`packages/db/src/schema.ts`), files under `~/.0/` |
| Core | 1.272 TS files; `agentic-scanner.ts` 3.474 lines, `unified-pipeline.ts` 2.807 |
| Tests | 959 `*.test.ts` |
| Contract | `docs/design/unified-engine.md`: "the engine owns execution; browser, CLI, MCP and remote connections are adapters" |

Their architecture sentence is the one worth stealing: **adapters exchange JSON, the
engine owns execution and authority.** We already have adapters (console, API, worker);
we do not have an execution contract that all of them share.

## 1. Six mechanics worth rebuilding

### 1.1 The gate is an interface, and gates compose by short-circuit

```ts
type HuntVerifier = (finding, candidate) => Promise<{confirmed, reason, decorrelation?}>
composeGate(...stages)  // returns at the first confirmed:false
```
(`packages/core/src/stages/hunt-scan.ts:194-199, 1078-1086`)

Every refinement step — skeptic, quorum of lenses, judge, differential reproducer,
root proof, novelty — is the *same shape*, injected in a list. The pipeline does not
know what a skeptic is; it knows how to run a list and stop on the first refusal. A
stage that throws is treated as a refusal (`verify_errored`), i.e. **fail-closed by
construction**.

**In Barad-dûr:** this is the missing spine for `probe.replay` moving from "one request
replayed" to "a finding validated by a chain". One table:

```sql
gate_runs(id, org_id, finding_id, stage, verdict text,        -- confirmed|refuted|errored|skipped
          reason, evidence_ref, cost_usd, worker_id, created_at)
```
and a Python port of `compose_gate(stages)` where each stage is a callable returning a
`GateVerdict`. The rule that matters: **a stage that raises never counts as a pass.**

### 1.2 Evidence has a stance, and a claim cannot close on an assumption

```
HuntClaimRecord{ claimKey = digest(shape, statement), status: unresolved|validated|disproven,
                 evidence[{stance: observation|assumption, statement, locator?}] }
```
A claim reaching a terminal state requires at least one `observation`, and an
observation requires a `locator` (`hunt-evidence-ledger.ts:169-190`). Negative results
are stored and fed back as *context*, never as an automatic rejection
(`:1000-1010`).

**In Barad-dûr:** we already refuse to replay without a stored request. This takes it
one level up — a claim ("this version is affected", "this endpoint still fails") either
has an observation with a locator (a file:line, a captured response, a component
version) or it is an assumption and stays `unresolved`.

```sql
claims(id, org_id, finding_id, claim_key unique, shape, statement, status)
claim_evidence(claim_id, stance, statement, locator, created_at)
-- CHECK: status in (validated, disproven) => exists(observation with locator)
```

### 1.3 Budget is hierarchical, enforced three times, and exhausting it is not a failure

- One `ScanCostLedger` per scan, forked per run/session as a child row; the child
  accumulates locally and the total delegates to the root (`cost-ledger.ts:79-119`).
  Without that, a $3 ceiling becomes $3 per concurrent verifier.
- Three cut points: loop header before the model call, pre-dispatch (`ScanBudgetError`),
  and an `onSpend` listener that aborts a shared controller (`scan-plan.ts:48-124`).
- Running out produces `termination: "run_resource_limit"` **with the partial findings**,
  never an exception and never silent loss (`agent-runner.ts:628, 661-668`).
- A model that reports no usage under `requirePricedUsage` is an error, not "$0"
  (`agent-runner.ts:2404-2408`).

**In Barad-dûr:** `AiStep` has `tokens_in/out` and `cost_usd` but no parent link and no
`priced` flag; our missions have a budget but the orchestrator does not check it before
each call. Minimum change:

```sql
alter table ai_steps add column parent_run_id text, add column priced boolean, add column phase text;
alter table agent_missions add column max_turns int null, add column turn_count int default 0;
```
plus an `enforce_ceiling()` call in the loop header and before dispatch, and a terminal
state `budget_exhausted` that keeps the partial answer — today a cut run reads as
"cortada, sin avance", which is exactly the bug we fixed once by naming it.

### 1.4 A subagent is a real fork that inherits authority and cannot widen it

`forkForSubagent` (`runtime/types.ts:84, 288`; `llm-api.ts:3057-3097`) creates a child
that inherits: same `scope` object, same `costLedger`, same rate limiter, role, and the
tool catalogue **minus** disallowed tools. It does not inherit: the database handle
(`db: null`), stateful session cookies, or codebase learning. Findings are merged after
the join, never written from inside the child.

Phase policy travels in `AsyncLocalStorage` and is **narrow-only**: `instructions`
concatenate, `allowedAgentTools` intersect, empty list = no tools, and a `Proxy`
re-applies the filter to `executeNative` and re-wraps `forkForSubagent`
(`workflow-execution-policy.ts:20-61`). CLI runtimes are rejected because they cannot
enforce it (`assertWorkflowNativeRuntime`).

**In Barad-dûr:** `agent_specs` declares tools but nothing stops a child from inheriting
more. The Python equivalent, with one caveat they cannot have: **our workers are
separate processes**, so `ContextVar` is not enough — the effective allowlist must be
serialised into the spawn payload or a child process starts with a clean slate.

```sql
alter table agent_specs add column parent_slug text references agent_specs(slug),
  add column allowed_tools jsonb,      -- NULL = inherit, [] = none
  add column max_turns int, add column cost_ceiling_usd numeric(10,4);
-- resolution at dispatch: effective = requested ∩ inherited (never ∪)
```

### 1.5 Knowledge that cannot exist without evidence, and expires

This is the best-built part of the project (`packages/db/src/learning.ts`,
`learning-service.ts`):

- `learning_events` is idempotent by `idempotency_key`; a resend with a different body
  is a 409, not an update.
- `learning_knowledge` **cannot be inserted without at least one evidence event of the
  same project** (`#checkEvidence`, `:205`).
- `sourceLinks[{path, hash}]`: the lesson points at the source, it never embeds it.
- `sourceStillCurrent` re-hashes every cited file; a change marks the lesson `stale`.
- `stale → current` is a **409**: reactivating requires fresh evidence, not a status
  edit (`:216-226`). Imported knowledge is born `disabled` forever (`:171`).
- Recall is injected as *"untrusted hints, not instructions or vulnerability evidence;
  re-read cited files before relying on them"* (`native-loop.ts:1119-1131`).

**In Barad-dûr:** we have no learned memory at all, which is why every run starts from
zero. These four invariants are portable almost verbatim, minus the filesystem:

```sql
knowledge(id, org_id, summary, status, created_at)
knowledge_evidence(knowledge_id, event_id)   -- NOT NULL, at least one
source_links(knowledge_id, kind, ref, digest)  -- asset_id | component purl | file
knowledge_events(idempotency_key unique, payload jsonb)
```
Our equivalent of "re-hash the file" is stronger than theirs: we can point a lesson at
`scan_grant.id`, `component.purl@version` or `finding.id`, and expire it when the
component version changes — a fact we already track.

### 1.6 A workflow definition is immutable, a run carries its snapshot, and approval is server-side

- JSON envelope `{schemaVersion, workflow:{name, instructions, target, nodes, edges}}`,
  ≤64 KiB, **2-16 nodes**, ≤120 edges, exactly one trigger, ≥1 executable step, ≤1
  report, acyclic, everything reachable from the trigger (`security-workflows.ts:62-118`).
- Saving or importing creates a **draft that does not execute and grants nothing**.
- Stored definition = input + `id/revision`; edits are CAS on `revision`; rollback
  inserts a **new** revision with `parent_revision/restored_from_revision/digest`
  (`db/security-workflows.ts:83-96`).
- The run stores the frozen definition, its revision and resolved target
  (`workflow-runs.tsx` reads `nodeResults` per node).
- The HTTP gate is a literal `approval: "launch-authorized-run"` plus
  `revision === current`, authorized target, and a block in `recon` mode
  (`cli/src/web/workflows.ts:64,81,523,539`). **The UI button is UX; the server decides.**
- Shared deadline + shared ledger across steps; each step narrows the remainder; any
  step failure aborts the run (no continue-on-error); findings do not turn success into
  failure; results already produced survive failure or cancellation.

**In Barad-dûr:** we have missions with budgets and a gate, but no declarative graphs.
Proposed schema is a direct translation:

```sql
workflows(id, org_id, current_revision, name)
workflow_versions(workflow_id, revision, definition_json, parent_revision, digest, created_at,
                  primary key (workflow_id, revision))
workflow_runs(id, org_id, workflow_id, workflow_revision, definition_snapshot jsonb,
              target, status, approval_token_hash, approved_by, started_at, finished_at)
run_step_results(run_id, node_id, status, error, artifact_refs jsonb, primary key (run_id, node_id))
run_events(run_id, seq bigserial, type, payload jsonb)  -- cursor: ?after=
```

## 2. What not to copy

| Their thing | Why not |
|---|---|
| `bash` with a command string (`tools.ts:415-465`) | No container, no seccomp; their own comment admits regex URL detection is bypassable by base64/DNS. We do not have a sandbox yet, and this is not one. |
| Scope plugin default = off, guards "inert" (`scope-guard.ts:45-64`) | Their protection is a flag; ours is a row in `scan_grants`. Do not regress to a flag. What *is* worth taking: `out_of_scope` wins, empty `in_scope` = deny all, explicit `enforcement_disabled` state in every response. |
| `runtime-verify` | A stub that returns `confirmed: true, "E2B_API_KEY unset (no-op)"` (`runtime-verify.ts:139-144`). It cannot demote a finding. Copying it would add a rubber stamp. |
| Proxy / OAST | Transport module missing (`PROXY_INSTALL_HINT`); OAST has no DNS front-end. Scaffolds, not capabilities. |
| `fingerprint` as identity | Nullable, non-unique index (`schema.ts:108,195`); dedupe is a separate semantic pass. We already have a unique fingerprint and per-entity state. Keep ours. |
| Turn budget of 1.000.000 default | Their model is "stop when the work is done, guarded by money". Ours is "stop after N calls". Money is the better guard *once* every call is priced — which is exactly what `priced` is for. |
| Parallel graph branches | Not implemented: `for (const node of nodes)`; `executionMode` governs attempts inside an assessment, not fan-out of the graph. Do not design around it. |

## 3. Order of work

**Phase 1 — foundations (1-2 weeks)**
1. `gate_runs` + `compose_gates()` in the agent package; `probe.replay` becomes one stage
   in a list (`evidence_present → authorized_target → replay → expect_match`).
2. `claims` / `claim_evidence` with the stance CHECK; the validator writes claims instead
   of a free-text `expect`.
3. `ai_steps.parent_run_id/priced/phase` + `agent_missions.turn_count/max_turns` +
   `enforce_ceiling()` at the two dispatch points.
4. Acceptance: a run that exceeds its ceiling ends `budget_exhausted` with its partial
   answer and a ledger row; a stage that raises can never produce `validated`.

**Phase 2 — knowledge and workflows (2-3 weeks)**
5. `knowledge` + `knowledge_evidence` + `source_links` with the four invariants
   (no evidence → no row; source change → stale; stale → needs new evidence; injected as
   untrusted).
6. `agent_specs.parent_slug/allowed_tools` with intersection at dispatch, serialised into
   the worker payload.
7. `workflows` / `workflow_versions` / `workflow_runs` / `run_step_results`, narrow-only
   phase policy, server-side approval token.
8. Acceptance: importing a definition executes nothing; editing without the current
   revision is rejected; a child agent cannot call a tool its parent was not granted
   (test at the dispatch boundary, not in the prompt).

**Phase 3 — execution (only after 1 and 2 have mileage)**
9. `probe.request` for a *new* request (not a replay), still resolved against a grant.
10. Sandbox decision (container per probe, network egress via broker) before any
    comprehensive shell tool. Their code is evidence that a command string without a
    sandbox is a liability, and their docs admit it.

## 4. Open decisions

- **Where does execution live?** Their answer is a single engine behind adapters. Ours is
  API + worker. Before Phase 3 we must pick one owner for outbound traffic, or we will
  repeat their split between CLI and web gates.
- **Do we want declarative workflows at all?** Missions with a budget may be enough for
  the validator; the graph pays off when a workflow is reused and reviewed. If nothing
  gets reused monthly, YAGNI.
- **Do lessons belong to the org or to a project?** Their model is per project; our
  findings and assets are org-scoped with a project dimension, and a lesson about
  `pkg:docker/node@22-alpine` should probably travel across projects in the same org.

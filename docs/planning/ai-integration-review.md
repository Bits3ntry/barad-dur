# The AI layer, read against what it actually runs

Review date: 2026-11-14. Everything below was read from the tree and from the live
stack (`platform-api` on 8090, `barad_platform` in `barad-dur-postgres-1`), not from
the design documents. Where the documents and the running system disagree, the
number from the database is quoted.

---

## 1. What this thing is

One sentence, because the rest of the review depends on it:

> **Barad-dûr's AI is an attribution engine, not a chatbot with a scanner attached.**
> The estate already holds the facts (SBOM, builds, deployments, assets,
> observations, findings, grants). The model's job is to resolve *"are we involved?"*
> from those rows, cite them, and say `unknown` with the missing edge when they
> cannot answer.

The architecture is unusually coherent for this class of product, and three
commitments carry it:

| commitment | where it lives | why it matters |
|---|---|---|
| **facts vs interpretation are two endpoints** | `deployment_chain` (no severity, no score) → `exposure_verdict` (`affected \| not_affected \| unknown` + `why`) | the model cannot invent a verdict it did not receive; the chain answers a question a CVE never asks |
| **two brains, one authorization path** | platform: data, scope, budget, audit, the model call. Shauron: tools, sandbox, network position | revoking the key kills every agent at once; one writer for cost |
| **prose is never evidence** | `Claim.evidence_refs` validated against ids the tools returned; gates (`harness/gates.py`) promote candidates, not the model | a wrong sentence is *visibly* uncited |

That is the product. Anything that weakens one of the three is a regression, not a
feature request.

### The four use cases, ranked by what the data says

| # | use case | surface | live evidence | verdict |
|---|---|---|---|---|
| 1 | **Resolve a CVE/advisory against the estate** | Palantír chain (5 specialists) | 1 run recorded, `posture` plan | **the flagship, and the one the live config truncates** (§3.2) |
| 2 | **Ask the estate a question in prose** | `Chat` / `Assistant` | 1 session, 2 turns, 7,156 tokens | works, cheap, and returns no citations (§3.3) |
| 3 | **Autonomously test a cycle's scope** | cycle → mission → tasks → field agents → candidates → findings | **18 missions, 18 tasks, 133 tool rounds, 16 candidates, 11 findings (`origin=shauron-ai`)** | the only half producing new security facts — and the half with no ledger (§3.1) |
| 4 | **Let an external agent ask the same questions** | `mcp/barad_mcp` over `/api/v1` | 18 catalog tools, 4 MCP tools | shipped, unmeasured |

Use case 3 is where the product's value actually lands, and it is the one whose
economics are unmeasured. That asymmetry decides the priorities below.

### What is built, measured

| structure | rows (live) | what it is |
|---|---|---|
| `ai_runs` / `ai_steps` | 1 / 3 | the chat's ledger: question, plan, tool calls, ids, claims |
| `agent_missions` / `agent_tasks` / `agent_task_events` | 18 / 18 / 327 | the field runtime: envelope, contract, event log |
| `agent_specs` / `agent_runs` / `agent_messages` / `agent_artifacts` | 4 / **0** / **0** / **0** | the channel's participant identities; the ledger half is unused and folds into `ai_runs` (§6b) |
| `candidates` | 16 (11 validated, 3 refuted, 2 proposed) | the review queue, gated by `harness/gates.py` |
| `findings` | 1,036 scanner + 11 `shauron-ai` | one queue, three axes |

Code: `app/ai/` 2,184 lines, `app/harness/` 775, `routers/agent.py` 1,545,
`routers/agents.py` 1,247, `routers/ai.py` 375, `routers/chat.py` 368; console
`Chat/AiRuns/AiSettings/Agents/Missions/AgentTrace/Candidates/Assistant` 2,285 lines;
30 migrations since `0054_ai_harness`. 74 AI tests pass.

**None of it is committed.** `git status` still lists `app/ai/`, `routers/agent.py`,
`routers/agents.py`, `routers/chat.py` and every migration from `0052` to `0082` as
untracked (272 dirty entries on `main`). The AI layer therefore has no review, no
history and no rollback, which matters more here than in the rest of the tree: it is
the only subsystem that spends money and touches targets.

---

## 2. What the layer does well, and should not be redesigned

Named so the next session does not "improve" them away:

1. **The router is code.** `router.classify/plan/should_run` are deterministic and
   tested; the model classifies at the door and writes the prose at the exit. A plan
   you can unit-test is the whole difference between this and a prompt pile.
2. **Typed state, not a transcript.** `AgentState` (facts keyed by `tool:args`,
   claims with refs, open questions) keeps step 6 as cheap as step 1, and
   `validate_refs` downgrades a claim citing an id no tool returned.
3. **`projection()` / `brief_result()`.** Scalars first, rows sampled 12/6/3/1,
   `_rows_hidden` stated. This is what stopped a count question from answering "no
   reliable total" over a successful query.
4. **The envelope.** Signed (`barad-mission-v1`, Ed25519), narrower than the org
   scope, a task cannot widen a mission (`422 ... widening scope is a new mission`),
   the kill switch expires tokens, the task token dies with `final`.
5. **Absence has a name.** `stopped_budget`, `stopped_no_provider`, `needs_grant`,
   `not in this task's allowlist`, `outside the mission envelope`, `unknown` with
   `why`. Every refusal is a row. This is the habit that makes the rest debuggable.
6. **The gate chain.** `evidence_present → authorized_target → replay`: a model
   verdict cannot promote a candidate. 11 of 16 candidates survived it, which is a
   believable ratio, not a rubber stamp.
7. **The cycle briefing.** `_cycle_briefing` aims the first run at what the SBOM
   already claims (`N advisories apply to the deployed stack; prove which is
   reachable`) instead of paying the agent to rediscover inventory. That is "read
   before scan" (D45) in working code.

---

## 3. What is broken, with the evidence

### 3.1 The field half spends tokens that the ledger cannot see — so no ceiling binds it

`agent_missions.run_id` is nullable and **never assigned**: `routers/agent.py` reads
it in three places (`:134`, `:184`, `:624`) and writes it in none; neither does
`create_mission`, `scan_cycle` or `routers/cycles.py`.

Everything downstream of that single missing write:

```python
# routers/agent.py:624
run = session.get(models.AiRun, mission.run_id) if mission.run_id else None
# :626
spent = (run.tokens_in or 0) + (run.tokens_out or 0) if run else 0
# :628
if ceiling and spent >= ceiling:      # ← spent is always 0: never fires
# :659
if run is not None:                   # ← no AiStep is ever written
```

Consequences, all of them live today:

- The mission's own `budget.tokens` ceiling **cannot fire**. Every mission on the
  stack is capped at 20,000 tokens on paper and unbounded in practice.
- The monthly cap is computed from `ai_steps` (`engine.month_spend`), so field work
  never counts against it. `budget_check` is blind to the half that costs the most.
- The `/spend` meter reads **7,156 tokens for the month** (3 steps, one chat run).
  The 17 `final` events alone report **143,959 tokens**, and those are only the last
  turn of each task — a 10-step loop re-sends a growing context on every call. The
  meter is at least 20× low, and that is a floor, not an estimate.
- Neither cap is even set on the live row (`monthly_token_cap`, `monthly_cost_cap`
  both `NULL`), so "a budget, not a surprise invoice" is currently "no budget".

This is the highest-value defect in the review: it breaks invariant 7 of the design
("the Settings meter is `sum(ai_steps.tokens)`") precisely where the money is, and it
is fixed by writing one row.

### 3.2 The live settings row truncates the flagship chain below the answer

Model defaults are `max_steps=12`, `max_specialists=6` (`models.py:2800-2801`).
The live `ai_settings` row holds **`max_steps=6`, `max_specialists=3`**.

`CVE_PLAN` is five specialists (`intel.cve → estate.inventory → applicability →
remediation → evidence.report`) and the accepted chain takes 7 calls. Reproduced
against the real orchestrator with a stub provider:

```
DEFAULTS  status=answered            steps=7  specialists: intel.cve, estate.inventory,
                                                            applicability, remediation, evidence.report
LIVE ROW  status=stopped_max_steps   steps=5  stop='max_specialists reached (3)'  answer=''
```

So on the running stack **a CVE question cannot reach `evidence.report`**: it ends
with facts, no sentence, and status `stopped_max_steps`. Worse, the failure reads as
a budget decision when it is a stale configuration row — the exact pitfall already
recorded once in `references/ai-harness.md` ("A default changed in the model does not
migrate the row"). It recurred.

### 3.3 The chat answers without a receipt, on the screen everyone uses

- `chat_turns.citations` is written as `"[]"` at every insert site
  (`routers/chat.py:217`, `:276`) and nothing ever populates it.
- The assistant turn stores `run_id`, and `Chat.jsx` never reads it. The steps, tool
  calls and ids exist — in `AiRuns`, on another screen, behind a nav button.
- `Chat` renders `{turn.content}` as plain text; `AiRuns` renders refs as `<span>`,
  not links.

The design says "every answer renders evidence chips that navigate into the console —
an answer nobody can verify is a liability". On the surface that is actually used,
that is unimplemented. This is the cheapest credibility win in the whole layer: the
data is already fetched in the same request.

### 3.4 A chain longer than 60 seconds dies at the proxy, after it has already cost money

`orchestrator.execute` runs **inside** the HTTP request (`routers/chat.py:269`), and
`deploy/console/nginx.conf` sets no `proxy_read_timeout` (default 60s). Five
specialists × up to three calls each, with a reasoning model at ~10-20s per call, is
minutes. The console then shows a 504 for a run that completed server-side, the turn
is already written, the operator retries, and the estate pays twice.

The UI is honest about the gap ("the server cannot stream steps yet, so the UI shows
elapsed time") but the gap is the problem: `POST /ai/runs` returns the run only when
it is finished, and there is no `GET /ai/runs/{id}/stream` despite the design
promising SSE.

### 3.5 Every field refusal that named a tool was misdiagnosed

Of 42 refusals in 327 task events, 28 are "not in this task's allowlist" — and **all
28 carry `"tool": null`**. None of them was an unlisted tool. The model emitted
`run_tool` with no `tool` and no `argv`; `_parse_call` (shauron `agent.py`) returns
`None`; `tool not in allowed` is true for `None`; and the worker tells the model *"not
in this task's allowlist"* — a false statement it then feeds back into the
conversation.

28 of 133 tool rounds (21%) were burned this way. The fix is not a prompt tweak: the
result payload should say what actually happened (`no tool named; call run_tool with
{"tool": "curl", "argv": [...]}`), the schema should be strict, and the platform
should count malformed calls separately from refusals. A refusal taxonomy that lies
is worse than no taxonomy.

---

## 4. What is thin (data-driven)

| # | finding | evidence | cost of leaving it |
|---|---|---|---|
| 1 | **The gateway offers tools the envelope did not grant.** `/llm/complete` forwards `payload.tools` to the model untouched (`agent.py:652`); only the worker filters, at execution. | 28 refused tool rounds | a step is spent to learn what the platform already knew |
| 2 | **A mission target with a path authorizes only that subtree.** `_envelope_covers` treats an origin as "every path", but a task target with `/rest/user/login` narrows the envelope to it. The create form takes free-text. | 14 refusals "outside the mission envelope" on the **same origin** (`.../ftp`, `/robots.txt`) | a run that looks broken while the operator's intent was "this host" |
| 3 | **Three runtimes, three ledgers, no join.** `ai_runs` (1), `agent_missions/tasks/events` (18/18/327), `agent_specs/agent_runs/messages/artifacts` (4/**0**/**0**/**0**). Nothing ties a mission to a run; nothing ties a spec's `tools` to a mission's `tools`. | `validate.finding` declares `probe.replay` etc.; the missions that ran had `["curl"]` | "what did the AI do and what did it cost" has three answers and one of them is empty |
| 4 | **The Agents catalogue is a second product.** 4 specs, 0 runs, 0 messages, 0 artifacts; its thread is a projection of chat turns + AI steps. | live counts | a nav entry, an editor, 1,247 lines of API and a second vocabulary (`agent_class`, `must_return`, `tech_affinity`) that the field loop never reads |
| 5 | **`engine.execute` is dead.** Only `orchestrator.execute` is called (`routers/ai.py:340`, `chat.py:269`). Two loops with the same job. | grep | every prompt/budget fix lands twice or not at all |
| 6 | **The chat cannot be told "solo DEV".** `subject_kind/subject_id` are stored on the session and `session.assemble()` never reads them; `pins` exist and are assembled, but the UI never creates one. | `ai/session.py:53-78` | the operator re-states constraints every turn, and compaction can drop them |
| 7 | **No price ⇒ no cost.** The only configured provider (`opencode-go`) has both prices `NULL`, so `price_known=false` everywhere. Go reports `usage.opencode.allowance`; nothing reads it. | live provider row | "cost" column permanently says unknown while a real allowance drains |
| 8 | **Dead field / dead pill.** `CompleteIn.max_tokens` is accepted and ignored (`engine.complete` uses the provider row); `AiRuns` renders `run.cached_tokens`, which `_run_data` does not return. | code | small, but they teach the operator to distrust the form |
| 9 | **No quality regression, only a budget one.** 74 AI tests assert wiring; `ai_budget_baseline.json` pins three questions' token cost; there is no golden-answer set and no `ai_feedback` table (D24). | tests/ | prompt changes are unmeasurable in the only dimension that matters |
| 10 | **The field profiles' specialists do not exist.** `profiles.py` lists `validation.technical`, `recon.surface`, `recon.code`, `exploit.chain`, `probe.sibling`; `specialists.SPECIALISTS` has five Palantír entries and none of those. | `ai/profiles.py:34,49` | the field half is one generic agent with `curl`, wearing a hunter's name |

---

## 5. The capability that is missing, not broken

**Reachability.** `exposure_verdict` accepts `depth=full` and degrades to `rules`,
because the code tools do not exist: `ai/tools.py` has no `code.search`,
`code.slice`, `code.analyze`, and `code_files` holds **0 rows across 10 registered
repositories**.

That is the half of the verdict that distinguishes this product from a CVE matcher.
"Component present" is a join. "Code path reachable on the commit that is deployed"
is the answer a customer pays for, and today it is `unknown` for every finding — with
the honest `why` that the design demands, which is the only reason this reads as a
gap rather than a lie.

Order matters here: the index (`code_index`, `repository.code_access`) is the
prerequisite, and it is a scanner-shaped job, not a model job.

---

## 6. The decision that decides the rest

**Do we keep two agent runtimes, or does a mission become the only runtime?**

Two readings of the layer currently coexist:

- *A. The analyst*: one run per question, one ledger, profiles as data, missions as
  the only way to act.
- *B. The agent platform*: a catalogue of named agents (`agent_specs`), each with a
  run, a message log and artifacts, chattable at `@slug`.

B is what `routers/agents.py` + `Agents.jsx` + `AgentTrace.jsx` implement, and it has
**zero runs**. A is what produced 18 missions and 11 findings.

**Decided 2026-11-14: keep the channel, not the runtime.** The Slack-shaped surface
stays — named participants, the orchestrator delegating, refusals as cards, a mission
appearing in the conversation — because seeing *who asked whom for what* is the point
of the product, not decoration. What does not stay is a second execution path: the
channel is a **projection over one ledger**, never its own store.

That dissolves the tradeoff instead of taking a side. The social surface is a read
model; the ledger is the write model. Nothing about a thread needs its own tokens,
its own budgets, its own artifacts or its own lifecycle.

### 6b. The mechanism: one ledger, one thread, N identities

The relation the operator wants to see is **delegation**, and it is already in the
data — it just has no shape in the API:

| relation | stored where | renders as |
|---|---|---|
| **delegation** orchestrator → specialist | `ai_steps.role` + the plan order | `orchestrator delegated to applicability · 2 claims · 1 invalid` |
| **handoff** specialist → orchestrator | `ai_steps.handoff` (`claims`, `open_questions`, `invalid_refs`) | the claim list under the delegation, INVALID marked |
| **task** run → mission → task → field agent | `agent_missions.run_id`, `agent_tasks.worker`, `agent_task_events` | `validate.finding · done · 8 steps · curl ×5 · 12k tokens` |
| **refusal** any participant → the room | `agent_task_events.kind='refusal'`, run `stop_reason` | a card naming the one action that unblocks it |

Four pieces make that work, all of them small:

1. **`ai_runs.session_id`** (nullable, FK). Any run — chat turn, mission, compaction —
   can belong to a thread. Today only chat turns do, which is exactly why a mission
   cannot appear in the conversation.
2. **The mission's run is created with the mission** (§3.1/A1), so a field agent's
   steps land in `ai_steps` with `role = task.kind`. The participant's name *is* the
   task kind; no mapping table.
3. **`agent_specs` survives as identity, not as authority.** Rename in the doc's
   vocabulary to *agent*: avatar, name, colour, class, `tools` as a **ceiling**. The
   effective allowlist is `mission.tools ∩ spec.tools` — narrow-only, the mechanic
   already proven (`None` inherits, `[]` means none). A spec can never grant a tool
   the envelope did not; it can only take one away. That is what makes the catalogue
   meaningful without giving it a second vote on authorization.
4. **`GET /ai/threads/{id}` merges three sources by time**: `chat_turns` (what was
   said), `ai_steps` (what each participant did), `agent_task_events` (what the field
   agent saw). `routers/agents.py` already does two of the three; the missing join is
   the run's session and the mission's run — one column each.

**What the channel must never become, or the whole argument for keeping it collapses:**
a place where an agent talks to another agent without the platform seeing it
(agent-to-agent chat is an anti-goal), a store of its own (`agent_messages`/
`agent_artifacts` fold into `ai_steps`/`agent_task_events`), or a second place where a
budget is decided. The thread reads; the ledger writes.

**Cost, stated:** the four `agent_specs` rows lose the fiction of owning runs
(`agent_runs` is 0 rows), and the channel's data is only as honest as `ai_steps` —
which is why A1 ships before any of this. A pretty conversation over a ledger that
under-counts by 20× is the exact failure this review exists to prevent.

### 6c. Prompts you can see, edit and define — as versions, not as a text box

This revises **D24** ("no runtime self-improvement: feedback is a table plus code
commits") and the Settings rule "specialists live in code, not in an editable prompt
box". The owner wants to read a participant's instructions, improve them, and write
them when creating an agent. That is a legitimate product requirement and the original
rule over-restricted it: it was refusing *mutable in-place* prompts, not *authoring*.

The distinction that keeps both properties:

| what we refuse | what we build |
|---|---|
| a prompt that changes under a running loop | a prompt **frozen per run** when the plan is computed |
| "the prompt is whatever the row says today" | one **active version** per key, every step recording `key@version` |
| the model rewriting its own instructions | the model may write a **draft diff**, a human promotes it |
| behavior changing with no record | `notes` + `activated_by/at` per version, and receipts per version |

**Schema — one table, no new machinery elsewhere:**

```
ai_prompts(id, key, version, body, status draft|active|archived, notes,
           created_by, created_at, activated_by, activated_at)
  unique(key, version) · one row per key may be active
agent_specs.prompt_key   -- nullable: the participant names a prompt, it does not own text
ai_steps.prompt_version -- "intel.cve@3" instead of "f2.0"
```

`specialists.py` keeps its prompt strings as the **seed for v1**: `resolve(key)` reads
the active row and falls back to the code default, so a fresh database, the test suite
and a rollback all work with zero rows. A row only ever *overrides*.

**Three rules make it safe, and each is one line of code:**

1. **Resolve once, at the start of `execute()`**, into a `{key: version}` map passed to
   every specialist. A concurrent edit cannot change step 5 of a loop already running.
2. **Promotion is a human act**, recorded like a grant approval (`activated_by`,
   `activated_at`); the previous active version becomes `archived` and stays readable.
3. **The field agent's prompt comes from the gateway.** `/llm/complete` prepends (or
   replaces) the system message for `role=field` with the platform's active
   `field.generic` body. Shauron keeps no prompt registry — the invariant holds, and the
   field prompt becomes editable in the same screen as the specialists.

**What the editor shows, per version — and this is the feature, not the textarea:**
runs using that version, `answered` rate, median steps, median tokens, `invalid_refs`
count, all read from `ai_runs`/`ai_steps` by `prompt_version`. That is the feedback
loop D24 promised and never shipped: you edit, you run the same question in
`mode="eval"` (a run that writes no chat turn), and you compare two versions on the
same estate before promoting.

**Creating an agent becomes:** identity (name, avatar, class) + `prompt_key` (existing,
or a new key whose v1 is a draft) + a tool **ceiling**. A participant with a `draft`
prompt is visible in the catalogue and unusable in a mission — the `status` column
already models exactly that.

**Cost, stated:** reviewability moves from `git diff` to a console diff. The mitigation
is the graduation path: a version that survives its eval can be copied into
`specialists.py` as the new seed, so code remains the floor and rows remain the fast
loop. What we do not accept is the reverse order — a code-only prompt loop, which is
where the operator cannot experiment at all.

---

## 7. The consolidated plan

Everything this review identified, in one list: the measured defects (§3), the thin
spots (§4), the missing capability (§5), and the two decisions taken after reading it
(§6b the channel, §6c prompts as versions). Nothing else is in scope; if a piece of work
is not below it, it is not a defined improvement.

**Settled, do not re-open:** the Slack-shaped channel stays as a projection over one
ledger; prompts are versioned rows with a code floor; `ai_runs`/`ai_steps` is the only
place where money and execution are recorded.

**Definition of done, every phase:** code + its tests + deployed + a proof read from the
running stack (a curl, a query, a screen) + one conventional commit. Each phase leaves
`make lint` and the backend suite green, and adds at most one alembic head.

| # | what it fixes | effort | depends on | acceptance, in one line |
|---|---|---|---|---|
| **A1** | one ledger for every token (§3.1) | ½ d | — | a mission's tokens move `/ai/spend`, and its own ceiling answers `429 mission token budget reached` |
| **A2** | ceilings that cannot go stale (§3.2) | ½ d | — | a CVE question on the live stack answers through `evidence.report` |
| **A3** | the answer carries its receipt (§3.3, §4.6) | 1 d | — | a chip in `#chat` lands on the finding; the run card's numbers equal `GET /ai/runs/{id}` |
| **A4** | the await stops being a held request (§3.4) | 1-2 d | — | a 7-call chain survives the console proxy; closing the tab still closes the run |
| **A5** | the field loop tells the truth (§3.5, §4.1, §4.2) | 1 d | — | zero `tool: null` allowlist refusals across the next 20 missions |
| **A6** | the channel, on that ledger (§4.3-4.5, §6b) | 3-4 d | A1, A3 | one thread shows five delegations plus a mission, with the same numbers as the ledger |
| **A7** | code reachability (§5) | weeks | — | one verdict names `(repository, ref, commit, fetched_at)` or says `code_access=none` |
| **A8** | prompts as versions (§6c) | 2-3 d | A1, A2 | two versions of `intel.cve` compared on the same question, in the ledger |
| **A9** | the meter says allowance (§4.7) | ½ d | A1 | the meter reads "% of this month's plan" instead of `price unknown` |
| **A10** | quality regression, not just budget (§4.9) | 2 d | A8, A1 | CI fails when a prompt version loses one expected fact from the golden set |

**Sequence, and the reason for it.** A2 → A1 → A3 → A5 → A4 → A8 → A6 → A9 → A10 → A7.

1. **A2 and A1 first**, because everything else is measured through them: one makes the
   flagship answer at all, the other makes the money visible. Half a day each.
2. **A3**, because an answer nobody can verify is a liability, and the data is already
   in the request.
3. **A5 then A4**: stop burning 21% of field steps on a misdiagnosed call, then stop
   paying twice for a chain the proxy killed.
4. **A8 then A6**: the editor and the channel are the two surfaces you asked for, and
   both read from A1/A3 — built earlier they would display numbers that lie.
5. **A9 and A10** close the loop (cost in the unit the plan bills; a regression that
   fails on lost facts, not just tokens).
6. **A7 is its own campaign** — the index and the code tools are scanner-shaped work,
   not a chat feature, and nothing in A1-A6 depends on it.

Rough total for A1-A6 + A8-A10: **11-14 focused days**. A7 is measured in weeks.

### 7b. Detail per phase (acceptance you can run)

**A1 — One ledger for every token (½ day).** Set `agent_missions.run_id` when the
mission is created (both `create_mission` and `scan_cycle`); make `/llm/complete`
write `AiStep(role="field", seq=…)` and increment the run; reject a completion whose
mission has no run rather than silently not counting it.
*Accept:* run one mission; `select sum(tokens_in+tokens_out) from ai_steps` grows by
the sum the gateway returned for that mission; `/ai/spend` moves by the same amount;
a mission with `budget.tokens = 2000` stops at 429 `mission token budget reached`.
This is the first time that sentence becomes true.

**A2 — The ceiling cannot go stale (½ day).** Seed/patch the settings row in the same
migration that declares the defaults, and add a test that the live row equals the model
defaults after `alembic upgrade head`. Set both caps on the live stack.
*Accept:* a CVE question on the running stack answers with `evidence.report` in the
chain; `GET /ai/settings` reads 12/6; the stub test in §3.2 flips to `answered` for the
live row.

**A3 — The answer carries its receipt (1 day).** On the assistant turn, persist
`citations` from the run's `handoff.claims[].evidence_refs` + tool-call refs; render
them in `Chat.jsx` as chips that `onNavigate` into the entity; add a run card
(`12 tool calls · 3 steps · 7,156 tokens · stopped_max_steps`) that opens `/ai-runs/:id`.
*Accept:* ask a question in `#chat`, click an id, land on the finding/asset; the card's
numbers equal `GET /ai/runs/{id}`.

**A4 — The await stops being a held request (1-2 days).** `proxy_read_timeout 300s`
on `/api/` today; then `POST /ai/runs` returns the id immediately, the loop runs in a
background thread, and the console polls `GET /ai/runs/{id}` (SSE later, if the poll
proves insufficient).
*Accept:* a 7-call chain survives the console proxy, and killing the browser tab mid-run
still produces a closed run with an answer.

**A5 — The field loop's refusals tell the truth (1 day).**
- `/llm/complete` filters `payload.tools` to the mission's allowlist and refuses the rest
  with a named error before the model sees them.
- The worker's malformed-call path returns the schema, not an allowlist accusation, and
  the event payload names the real reason (`malformed_call` vs `not_allowed`).
- The mission create form normalizes a URL target to its origin and says so.
*Accept:* the next 20 missions show zero `"not in this task's allowlist"` rows with
`tool: null`; a target pasted with a path produces an envelope that covers the origin.

**A6 — The channel, over that one ledger (3-4 days).** Three commits, in this order:
1. `ai_runs.session_id` (nullable) + `agent_missions.run_id` set at creation; the four
   active `agent_specs` get a `tools` **ceiling** and `effective = mission.tools ∩
   spec.tools`. One line of intersection, applied where the envelope is handed to the
   model.
2. `GET /ai/threads/{id}` merges `chat_turns` + `ai_steps` + `agent_task_events` by
   time, each event carrying `author`, `kind` (`said`/`delegated`/`handoff`/`tool`/
   `observation`/`refusal`/`final`) and the ids it points at. `Chat.jsx` renders it:
   delegation, claims with INVALID, a mission card that expands into its tasks and
   tool calls, refusals as cards.
3. Retire `agent_runs`/`agent_messages`/`agent_artifacts` (0 rows each) behind a
   migration; delete `engine.execute` or make it the L1 fast path.
*Accept:* one thread shows a CVE question as five delegations plus the report, with the
same tokens/steps/cost as `/ai-runs/{id}`; a mission started from that same thread
appears in it with `validate.finding · done · N steps · curl ×M`, its refusals
inline, and its tokens counted once; `sum(thread tokens) == /ai/spend` for the month;
no screen reads a table with 0 rows.

**A7 — Code reachability (weeks, scanner-shaped).** `repository.code_access`, the index
(`code_index`), then `code.search`/`code.slice` (query) and `code.analyze` (field).
*Accept:* one `applicability` verdict names `(repository, ref, commit, fetched_at)` for a
real advisory, or answers `unknown` with `code_access=none`. Never "not reachable"
without a commit.

**A8 — Prompts as versions (2-3 days, §6c).** `ai_prompts` + `resolve(key)` with the
code default as the floor; `ai_steps.prompt_version = "<key>@<version>"`; the set frozen
at the start of `execute()`; `agent_specs.prompt_key`; the editor (active read-only,
"nueva versión" prefilled, diff, notes, activate, archive) with per-version receipts;
`mode="eval"` runs that write no chat turn; `/llm/complete` injecting the active
`field.generic` body.
*Accept:* edit `intel.cve`, run the same question as `eval` against the same estate, and
the two runs appear in the ledger with different `prompt_version` and comparable
claims/tokens/`invalid_refs`; activating a version mid-run does not change the loop
already running; a database with zero `ai_prompts` rows answers exactly as today
(fallback proven by the existing suite); changing the field prompt in the console
changes the worker's brief with **no image rebuild**.

**A9 — The meter says allowance (½ day).** `opencode-go` reports
`usage.opencode.allowance`; read it in `engine.complete`, store it beside
`cached_tokens`, and render `% of plan` when no price exists. Tokens keep being counted
exactly; the dollar column becomes honest instead of permanently `unknown`.
*Accept:* a completion on the live provider writes an allowance figure; `/ai/spend`
shows "N% of this month's allowance" and the token cap still binds.

**A10 — Quality regression, not just budget (2 days).** A golden set of ~12 questions
with their expected facts (ids, verdicts, `unknown`-with-reason) that runs against a
prompt version and diffs the claims against the expectations; `ai_feedback` (D24's
missing half) records a human verdict per run. The existing
`ai_budget_baseline.json` folds into the same file.
*Accept:* `pytest tests/test_ai_golden.py` fails when a prompt version loses an expected
fact or doubles a run's tokens; the editor shows the golden-set score per version;
a thumbs-down writes `ai_feedback(run_id, verdict, note)`.

### 7c. Micro-fixes that ride along (no phase of their own)

| fix | goes with | why it is worth the line |
|---|---|---|
| `CompleteIn.max_tokens` is accepted and ignored | A1 | a field caller sizes its answer and nothing happens |
| `_run_data` never returns `cached_tokens` | A3 | `AiRuns` renders a pill that cannot exist |
| live `monthly_token_cap` / `monthly_cost_cap` are `NULL` | A2 | "a budget, not an invoice" with no budget set |
| `session.subject_kind/subject_id` stored, never in `assemble()` | A3 | the session cannot say "we are talking about AUREA PRO" |
| `chat_pins` has an API and no UI | A3 | pinning is the cheapest context control in the design |
| a mission target with a path narrows the envelope | A5 | normalise to origin in the create form, say so in the field |
| `engine.execute` is dead code | A6 | two loops, one of them never runs |

---

### 7d. Landed on `feat/ai-flow-100` (2026-11-14)

| phase | what changed | proof |
|---|---|---|
| **A2** | `orchestrator` runs the terminal `evidence.report` even when the specialist cap truncates the chain, and records every skip in the step's handoff; migration `0083` reconciles `ai_settings` rows nobody touched (12 steps / 6 specialists) | live `ai_settings` reads 12/6 after boot; a 3-specialist cap now answers `answered` with the skip named instead of `stopped_max_steps` with no answer |
| **A1** | `agent_missions.run_id` is set with the mission (`create_mission`, `scan_cycle`) and healed on the first completion; `/llm/complete` writes `AiStep(role="field", phase=task.kind)`, increments the run, honours `max_tokens`; `_narrow_tools` removes tools the envelope did not grant from the offered schema; revoke/done close the run | `tests/test_ai_ledger.py` — mission owns a run, a completion is a step, the ceiling returns 429, the enum is narrowed, `max_tokens` reaches the provider |
| **A3** | `_citations` writes the ids the run actually read onto the assistant turn (invalid claims excluded); `Chat.jsx` renders them as chips that open `#search::<ref>` plus an "open the run" button that opens `#ai-runs::<id>`; `subject_digest` puts the session's subject in the prompt; `chat_pins` got a UI; `/ai/runs` now returns `cached_tokens` | a chat turn with a CVE question returns a non-empty `citations` and a `run_id`; `assemble()` starts with `Subject: project · …` |
| **A5 (partial)** | the gateway never offers a tool the mission did not grant | 28/28 malformed-call refusals can no longer be generated by an unlisted tool; the worker-side taxonomy is open |
| **A8** | `ai_prompts` (migration `0084`) with one active version per key and the code string as the floor; `prompts.freeze()` resolves the set once, at the start of a run; `ai_steps.prompt_version` now reads `intel.cve@3`; `/ai/prompts` lists versions with per-version receipts (`runs`, `steps`, `tokens`, `invalid_refs`) and drafts/activate are separate human acts; `/llm/complete` injects the active `field.generic` body so the field prompt is editable with no image rebuild; `Prompts.jsx` is the screen | a run's steps carry `estate.inventory@1` and the prompt text sent contains the version marker; a draft leaves the answer unchanged until activation; a live `ai_prompts` table with 0 rows answers exactly as before |
| **A6 (partial)** | `ai_runs.session_id` (migration `0085`); `POST /agent/missions` accepts the thread it was started from and puts it on the mission's run; `GET /ai/sessions/{id}/thread` merges `chat_turns` + `ai_steps` + `agent_task_events` by time, with `said` / `delegated` / `field_step` / `tool` / `observation` / `refusal` / `final` kinds and per-thread totals; `Thread.jsx` renders it behind a *relaciones* tab in the chat | a CVE question's thread shows the orchestrator's delegations with their `prompt_version` and claims; a mission created from the thread shows `validate.finding` speaking, its tool calls and its `final`; `totals.tokens` matches the run |
| **A4** | the console proxy allows 300s, a turn can run off the request (`engine.sweep_stale_runs` closes a run whose process died, on read, so the ledger never shows `running` for something nobody runs), and a run that ends without an answer says why in the chat: `POST /sessions/{id}/turns` with `background: true` writes the run `running`, returns **202** with its id and continues in a daemon thread with its own session; `Chat.jsx` polls `GET /ai/runs/{id}` until it closes, then reads the turn. The synchronous path is unchanged (the default), and both share `_finish_turn` | a background turn returns `pending` with no assistant turn written yet; the worker half writes the same turn, receipt and citations as the synchronous path; `/ai/runs/{id}` closes `answered` |

Still open from the plan: **A5** worker-side refusal
taxonomy (needs the Shauron checkout), **A6** retiring the three unused tables,
**A7** code reachability, **A9** allowance meter, **A10** golden set. The 18 pre-existing missions keep `run_id` null: their usage was never
recorded, and back-filling a run with invented numbers would defeat the ledger.

---

## 8. Anti-goals

Do not build, and say why in the PR if tempted:

- **A vector store.** The estate is structured; retrieval is a paged query.
- **A planner model.** The route table *is* the plan: reviewable in a diff, testable.
- **A per-action approval round trip.** Scope is the network, tools are the registry,
  budget is the gateway. Three brakes that fail closed and cost no latency.
- **Runtime memory or self-editing prompts.** Feedback is a table plus a commit.
- **Any destructive tool in any allowlist.** No writes, deletes, floods, lateral moves.
- **A fourth ledger.** A1 exists to make the ledger true, not to add another one.
- **An AI number that replaces a counter.** `/ctem/overview` stays deterministic.

---

## 9. Open questions (the owner's, not mine)

1. ~~Named agents or profiles?~~ — **answered 2026-11-14: keep the channel.** Agents
   stay as named participants with identity and a tool *ceiling*; execution and money
   stay in one ledger (§6b). The consequence to hold onto: a thread never gets its own
   store, its own budget or its own lifecycle.
2. ~~Can the chat start a mission?~~ — **answered 2026-11-15: it proposes one.** An
   explicit `@angmar` / `@morgoth` with a finding id writes a signed mission in
   `awaiting_approval`, linked to the thread, with `curl`/`python`, an 8-step / 20k-token
   ceiling and `request|response|verdict` as the required proof — and stops there. When
   it cannot, the answer names the real blocker: no finding id, no asset or endpoint to
   talk to (the advisory's own `url` is never a target), or no grant covering the host.
   The chat still never executes; it stops being a dead end.
3. **Does a proposal choose its own capability?** The mention decides today
   (`@angmar → validate`, `@morgoth → discover`). The honest refinement is the evidence,
   not the word: a finding whose deployment has no recorded version needs a
   *fingerprint* (the `runtime` scan task), not a validation — and no model should be
   the one deciding that.
4. **What is "cost" on a flat subscription?** Tokens are honest and free to count;
   dollars are wrong half the day. `usage.opencode.allowance` would let the meter say
   "42% of this month's allowance" instead of "price unknown".

# QA plan — Barad-dûr v0

Objective: know, at any moment, which features work, which are partial, and what
must happen before calling the release good. The plan is written so a second
person can reproduce a result without asking the author.

## 1. What "tested" means here

A feature is **verified** only when all three hold:

1. the backend answers with real data (not a fixture the screen invents);
2. the console shows it and the empty/error/forbidden states are honest;
3. an automated check exists (unit, API or smoke) **or** a numbered manual case
   in `test-cases.md` was executed and its evidence recorded.

A screen alone, a route alone, or "it compiled" is never verified.

## 2. Levels

| Level | What it covers | How | When |
|---|---|---|---|
| L1 unit/logic | parsers, scope semantics, TOTP, closure planning | `pytest` (274 tests) | every change |
| L2 API contract | status + envelope + org isolation per area | `scripts/qa_smoke.py` (64 checks) | every change / before a pass |
| L3 end-to-end API | the full flow on an isolated stack, with assertions | `scripts/demo_v0.py` (25 asserts) | every release |
| L4 UI walkthrough | screens, states, navigation, permissions | browser pass with `scripts/e2e_stack.py --seed` | every release |
| L5 adversarial | IDOR, cross-org reads, malformed imports, oversized payloads | targeted cases (TC-030…) | every release |

## 3. Environments

| Environment | Purpose | Data |
|---|---|---|
| `pytest` (SQLite tmp) | L1 | built per test |
| `scripts/e2e_stack.py --port 8099` | L4, manual QA | **empty** org + one demo user |
| same with `--seed` | L4 with a known world | labelled `demo` fixtures + printed ID manifest |
| `scripts/demo_v0.py` | L3 | in-process, asserts as it goes |
| Disposable PostgreSQL (`v0_mig_check`) | migrations | none |

Never QA against the live stack: the deployment to it is a separate, explicit
action. Any test that writes uses a throwaway database and says so in its report.

## 4. Reproducible setup (the fast path)

```bash
# 1. build the console once
npm run build --prefix frontend

# 2. a stack with a known dataset and an ID manifest
python scripts/e2e_stack.py --port 8099 --seed
#    prints: console URL, the API key, the demo user, and every created id

# 3. the contract gate
python scripts/qa_smoke.py --url http://127.0.0.1:8099 --key <key>
#    64 checks · 0 failures expected (MFA check skips on an API key)

# 4. the end-to-end assertions (no browser)
python scripts/demo_v0.py
```

`--seed` prints a manifest (`finding`, `cycle`, `artifact_v3`, …). Cases in
`test-cases.md` refer to those names, not to hardcoded UUIDs, so the same steps
work on every rebuild.

## 5. Triage workflow

Every observation becomes one row. Nothing is "fixed" without a state change
that a second person can check.

```
new → triaged (severity + owner) → reproduced (evidence) → fixed → verified
                                 ↘ won't-fix (reason)  ↘ blocked (dependency)
```

| Field | Values |
|---|---|
| Severity | **S0** data loss / cross-org leak · **S1** feature unusable · **S2** wrong result, workaround exists · **S3** cosmetic / copy |
| Area | General, Scoping, Discovery, Exposures, Code, Automation, Admin, Auth |
| Evidence | request/response, screenshot path, or the test that reproduces it |
| Fix commit | hash, or `—` while open |

Rules:

- **S0/S1 block a release.** No exceptions for "it's only the demo".
- A bug closed as *fixed* must come back through the same case that found it;
  that is what *verified* means.
- A bug that is really a missing feature moves to `triage-backlog.md` with a
  severity and a proposal, not into a vague TODO.
- Timebox: a full pass is ~90 minutes with the seed stack; if it takes longer,
  the setup or the cases are wrong, not the tester.

## 6. Exit criteria for a pass

- L1 green (0 failures), L2 green (0 failures, skips explained).
- L3 green.
- Every case in `test-cases.md` executed with result recorded.
- No open S0/S1; every open S2 has a written workaround; S3s are listed.
- The report states what was **not** tested and why.

## 7. Where the artefacts live

| Artefact | Path |
|---|---|
| This plan | `docs/qa/plan.md` |
| Feature inventory (what exists, how it works) | `docs/qa/feature-catalog.md` |
| Reproducible cases | `docs/qa/test-cases.md` |
| Known gaps and their severity | `docs/qa/triage-backlog.md` |
| Contract gate | `scripts/qa_smoke.py` |
| Seed stack | `scripts/e2e_stack.py --seed` |
| End-to-end asserts | `scripts/demo_v0.py` |
| Acceptance narrative | `docs/acceptance/e2e-walkthrough.md` |
| Capability report | `docs/planning/barad-v0-final-report.md` |

Delivery is how scanning stops being something a person remembers to do. A **pipeline** announces a commit, the platform mints a ticket for it, the CI runs the scan, and the build waits on the verdict.

### What a pipeline is (and is not)

A pipeline is **a file in your repository**. The console builds that file for you; it does not store a pipeline object that could disagree with what your CI actually runs. The wizard creates nothing on the platform — it reads your project's components and repositories and writes a snippet you commit.

If the file and the console ever disagree, the file wins, because the file is what executes.

### Build one: four questions, one at a time

**Pipelines → new pipeline.**

**1. Where it runs.** Project, then component. The component must have a **repository bound** — that binding is the authorization a CI run relies on, and without it every action would read a checkout that does not exist. The screen says so instead of letting you build a broken file. Then choose the target CI:

| Choice | Result |
|---|---|
| detect from the repository | the snippet follows the remote's provider |
| GitHub Actions / Gitea Actions / GitLab CI | the exact syntax for that one |
| any other CI (portable script) | a shell script you wire yourself |

**2. What it checks.** Pick one or more **actions**. An action is a named bundle of tasks:

| Action | Tasks | Leaves the machine | Answers |
|---|---|---|---|
| Source review (`code`) | `sast`, `secrets` | no | what is in this commit? |
| Dependencies and configuration (`supply-chain`) | `sbom`, `runtime`, `misconfig`, `secrets` | no | what do we depend on, and what is misconfigured? |
| Verified secrets (`secrets-verified`) | `secrets` (live verification) | **yes** | is this credential still alive? |
| Attack surface (`web-surface`) | subdomains, DNS, TLS | **yes** | what do we publish without knowing it? |

An action that leaves the machine is marked `console only` in the wizard and cannot be selected for a push, because a push ticket may never ask for network work. That is not caution — it is the same rule the engine enforces when it validates the ticket.

Two actions can ask for the same task (`secrets` lives in two of them). When that happens the scanner runs twice, and the wizard says so before you discover it in the counters.

**3. When it runs.** `on every push`, `on every pull request`, `on demand`. Pick according to what changed, not by habit: a source change deserves the cheap set (sast, misconfig, secrets), a manifest or lockfile change deserves `supply-chain`, and re-scanning dependencies when nothing depended changed buys nothing and costs a database download.

**4. The file.** The wizard prints the path and the content, ready to copy. Commit it. Add the platform URL, and the key or token your CI already holds as a secret — never as a plain variable a pull request can print.

### The first run, end to end

```
developer pushes
   └─ CI runs the generated file
        ├─ ticket announced (before the slow work)
        ├─ engines installed and verified against their pinned hashes
        ├─ the scan writes artefacts into the run directory
        └─ evidence uploaded: steps, then observations, then finish
   └─ Pipelines shows a commit row with coverage and a verdict
```

Minting the ticket **before** the slow work is deliberate: until the ticket exists the platform has nothing to show, so a failed engine install would look like a run that never happened instead of one recorded as abandoned. Both are observable facts; a silent gap is not.

### Reading Pipelines

Each row is a commit: repository, resolved component and version, commit sha, coverage, scan status, and the findings it produced, with a fail-closed verdict. Rows with no findings are not empty rows — they say whether nothing was found or nothing was looked at.

A commit that cannot be attributed to a component stays visible as *needs attribution* rather than becoming a product-wide release. That row is work, not an error.

### Quality gates

**Quality gates** turns findings into a decision about a build. A policy names what blocks:

- CRITICAL/HIGH from a rule that **proves** a defect (a rule that only audits, like "this call exists", may warn but must not block — six hits on correct code is how a gate gets switched off);
- any exposed credential, forced to CRITICAL regardless of what the engine called it: rotation is the only closure, and it is urgent by definition;
- a CVE that has a fixed version. A CVE with no fix is not blockable — there is nothing to do today, and blocking it teaches people to bypass the gate.

Allowlist test fixtures explicitly. Every secret a real repository produced lived in `tests/`.

### Pentests

**Pentests** holds campaign-level work: a bounded engagement with its own scope and evidence, for the cases where a human attacks the application and the output is a report rather than a scan artefact. It is not a replacement for the automated loop; it is where the parts that need judgement are recorded.

### Regression

**Regression** re-tests fixes. A status of `resolved` is a claim; regression is the run that can contradict it, on the same rule and the same target.

### Jira

**Jira** links findings to tickets and keeps them in sync in both directions: the screen lists the links, can create one, can push a status, and has a **reconcile** button that re-reads the remote side and reports drift. If it says *Jira not configured*, the deployment is missing `JIRA_BASE_URL` and `JIRA_TOKEN` — a deployment setting, not something the console can fix.

### When a pipeline does not do what you expect

Ordered by how often it is the answer:

1. **The job sits at 0s, waiting.** Nothing was dispatched: no runner advertises that label, or it is registered but offline. A queued job never contacts the platform, so "no requests arriving" says nothing about the network.
2. **The announce call is refused.** Test the platform URL from the runner's own network — a platform bound to `127.0.0.1` is intentionally invisible to a job container. `401` instead of `000` is the good sign: the path is open and only the credential is missing.
3. **The scan runs and uploads nothing.** Check the ticket, then the run's coverage — a provider that failed while another delivered keeps the task alive and names the failure in the evidence.
4. **The commit landed on the wrong project.** Attribution uses the canonical remote URL and the component binding, not a guess from the repository name.

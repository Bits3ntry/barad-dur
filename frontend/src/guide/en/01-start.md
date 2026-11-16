Barad-dûr is the console where a security programme keeps its inventory, its evidence and its decisions. It answers four questions with data rather than opinion:

- **What do we have?** — projects, components, builds, domains and everything observed on them.
- **What is missing?** — the gap between what we declare and what we actually analysed.
- **What matters?** — findings ordered by exposure, not by a screenshot of a scanner.
- **Who decided?** — every authorization, approval and dismissal is written down with a name and a time.

It is built for one organization working on its own estate. It is not a SaaS and it does not try to be one.

### The rule that explains the rest of the product

**Barad-dûr decides. Shauron executes.** They are two programs, and the split is not decorative:

| | Barad-dûr (this console) | Shauron (the execution plane) |
|---|---|---|
| What it is | API, console, database | CLI, daemon, CI action, worker, field agent |
| What it keeps | inventory, findings, grants, history, verdicts | nothing permanent: a run directory and the disk |
| What it decides | what may be scanned, at which capability, by whom, what matters | which tool runs each step, with which pinned version |
| What it produces | the verdict and the record | the artefact and the typed observation |

A tool in Shauron never knows the platform exists: it writes a file inside a run directory, and the runner uploads it. That is why the same scan works from a laptop, from CI and from a worker container without a second implementation.

You do not need Shauron installed to read this console. You do need it running somewhere for a scan to produce anything.

### What you are looking at

The **sidebar** is a map of the programme, not a list of tables:

- the first rows are what an operator reads every day: **Dashboard**, **My work**, **Findings**, **Vulnerabilities**, **Chat**, **AI runs**, **Missions**;
- **CTEM cycle** holds the three working areas of the loop — *Scoping* (cycles, scope), *Inventory* (projects, assets, attack surface, components, exposures) and *Prioritization* (rules, business impact);
- **Delivery** holds **Pipelines**, **Quality gates**, **Pentests** and **Regression**;
- **Supply chain** holds **Builds**, **Licenses**, **Orchestration**, **Jira** and **Remediation**;
- **Help → Guide** is this document.

The **top bar** has one search box (`⌘K` / `Ctrl+K` focuses it) that jumps to any screen by name, a theme switch, the identity control (who you are signed in as) and the sign-out button. The crumb under it always tells you where you are: if it says `barad-dûr / dashboard` while you expected another screen, the address you typed is not a route.

A floating button in the bottom-right corner opens the **assistant** — the same Chat screen, in a panel, for the question you do not want to navigate to.

### What you read first, every day

Four screens cover the daily loop, and none of them is the full story:

- **Dashboard** opens with one verdict sentence about the organization's posture — *critical open*, *past due*, or nothing urgent — and the numbers that produced it (critical open, past SLA, known-exploited, coverage). Priority risk, exposure flow, the portfolio by group and the trend hang below it. If you read one screen a day, read this one, then open the rows it points at.
- **My work** is the same estate filtered to you: assignments, requests, tasks and acceptances, each with its deadline.
- **Findings** is the decision queue — what needs a status and a person.
- **Vulnerabilities** is the catalogue: is this famous CVE in our estate?

Everything else in the sidebar exists so those four are worth reading.

**Settings is a full screen with its own navigation**, reached from the organization control under the product name. Organization, account, appearance, delivery, intelligence, AI and service keys live in *Workspace settings*; my security, notifications, grants, runtime, members, audit trail and the setup guide live in *Administration*.

### Addresses you can paste to someone

Most screens ride the fragment (`#findings`, `#assets`, `#orchestration`), and a fragment is invisible to a server but works in a bookmark and in a message. Four things own a real path because people paste them or reload on them: `/projects`, `/projects/{slug}`, `/pipeline` and `/orchestration`.

A fragment can also carry the record: `#findings::<id>`, `#asset::<id>`, `#surface::<full-run-id>`, `#components::<project>/<component>/<version>`. Use the **full** identifier — a shortened prefix opens an empty screen that looks broken.

### What this console will never pretend

Learn these three sentences early; they are the difference between a security programme and a screenshot generator.

1. **An empty table is a question, not an answer.** "No findings" and "never analysed" are different states, and the screens say which one you are looking at: coverage is `full` or `partial`, with a reason.
2. **Unknown is not clean.** A component with no advisory data is unknown, not safe.
3. **The model's text is not evidence.** AI answers are a reading aid over rows the platform already holds; a finding is closed by evidence and a person, never by a paragraph.

### How to use this guide

Read the chapters in order the first time — they follow the order work arrives in. After that, the left column is the index: each chapter is one subject, and every chapter ends with the screens it just described, so the document is also a menu.

Screens are named in **bold** exactly as the sidebar prints them, and values you type are shown `like this`.

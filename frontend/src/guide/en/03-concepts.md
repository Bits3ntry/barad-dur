Every screen uses the same words. This chapter is the vocabulary; if a term in another chapter is unfamiliar, it is defined here.

### Two chains, one product

The platform keeps two inventories, and they meet in the middle.

**Software**: `organization → project → component → version (build) → package`. A build arrives as a CycloneDX SBOM. From it come components, dependency edges, licenses and CVEs.

**Surface**: `asset → observation → finding`. An asset is a host, a URL or an address; an observation is one typed fact about it (`dns`, `tls`, `http_headers`, `technology`, `service`, `port`, `content`); a finding is the conclusion someone can act on.

The two chains answer the same question from opposite sides: a vulnerable package inside a build and an exposed service on a host are both "our exposure", and the console treats them with the same discipline — who produced it, with what coverage, and who decided.

### Model objects

| Term | What it is | Where you see it |
|---|---|---|
| **Organization** | the workspace. One database, one estate | the control under the product name |
| **Role** | `owner`, `admin`, `analyst`, `viewer` — shown as Owner, Administrator, Member, Viewer | Settings → Members |
| **Project** | one application or product; owns components | **Projects** |
| **Component** | a unit of a project: backend, web, mobile, an image | Projects → components, **Components** |
| **Version / build** | one artefact of a component, identified by a label and a content hash | **Builds** |
| **SBOM** | a CycloneDX document listing what a build contains | Builds → component rows |
| **Package / purl** | a dependency and its canonical identity (`pkg:npm/lodash@4.17.20`) | build screens |
| **Asset** | a domain, subdomain, URL or IP under observation | **Assets** |
| **Observation** | one typed fact about an asset, with source and coverage | asset page → evidence |
| **Finding** | the actionable conclusion: a CVE in a component, a secret, a code weakness, an exposure | **Findings** |
| **Exposure** | a finding about reachability, not about a package | **Exposures** |
| **Grant** | an authorization: a principal, a target, a capability set, an expiry | Settings → **Grants** |
| **Scope target** | a declaration of ownership; grants nothing | **Scope** |
| **Zone** | the registrable domain (`a.example.com` → `example.com`); every subdomain shares one concurrency bucket | Settings → Runtime |
| **Cycle** | a time-boxed evaluation: freezes a reference, grants no authorization | **Cycles** |
| **Gate** | a policy that decides whether a build may pass | **Quality gates** |

### Execution objects

| Term | What it is | Where you see it |
|---|---|---|
| **Capability** | the engine's language: `passive_discovery`, `active_verification`, `vulnerability_analysis`, `intrusive_testing` | Grants, Runtime |
| **Lane** | the AI profile's language: `validate`, `discover`, `exploit` | Missions |
| **Scan level** | a bundle of capabilities: basic / advanced / deep recon | Grants |
| **Profile** | a named set of stages and tools with a level — `recon.simple`, `web.redteam`, `code.sast`, `code.secrets`, `code.supply-chain`, `image.supply-chain` | scan dialog, Orchestration |
| **Run** | one execution: a directory, steps, observations, coverage | Orchestration → runs, run screen |
| **Step** | one stage of a run with `items_in` / `items_out` and its own state | run screen |
| **Ticket** | the signed envelope that authorizes one run | not shown; it is what makes a run legal |
| **Scanner** | the named engine that a job is addressed to (`shauron-surface`) | Orchestration |
| **Worker** | the process that claims and executes queued runs, and beats while alive | Orchestration → workers |
| **Schedule** | "this scan, on this asset, every N minutes" | Orchestration |
| **Internal scan** | the platform's own sweeps: advisory feeds, KEV/EPSS, runtime CPEs | Orchestration → internal |
| **Pipeline** | a file in a repository that announces commits to the platform | **Pipelines** |
| **Mission** | a bounded AI task with targets, tools and a budget | **Missions** |
| **AI profile** | the mode a question runs under: Palantír, Angmar, Morgoth | **Chat**, Missions |
| **LLM run** | one model-backed execution with its tokens and cost | **AI runs** |

### The four states that get confused

| State | Means | How it is printed |
|---|---|---|
| **absent** | we looked; there is nothing | an empty row set, with counts |
| **unknown** | we never looked, or the source has no data | `unknown`, `never observed`, `never analysed` |
| **skipped** | the step was not applicable here | `skipped` with the reason, never red |
| **partial coverage** | the profile did not fully run | `partial` + the sentence that explains it |

A scan that skipped a step is not a failed scan, and a build nobody scanned is not a clean build. The console is built to keep those apart; when a screen seems to say otherwise, the honest state is the one with the reason attached.

### Reading a number

- **Counts on a list are the server's**, not the page's. `showing 200 of 268` means there are 268.
- **Risk is explained**: the ordering is severity weight × KEV × EPSS, capped at 100. It is not a hand-tuned score, and the screen says so where it matters.
- **`N of M components`** on a filtered table means a filter is applied. A handful of rows is a filtered slice, rarely missing data.

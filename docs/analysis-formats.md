# Analysis import: supported formats and what each field means

Importer: `POST /api/v1/analysis/import` (`routers/analysis.py`,
parsers in `app/sast.py`). Both parsers are implemented end to end; there is no
"coming soon" format in this list.

## Formats

### SARIF 2.1.0 — `"format": "sarif"`

`report` is one SARIF `run` object.

| Read | From |
|---|---|
| tool name / version | `run.tool.driver.name` / `.version` |
| rules + CWE | `run.tool.driver.rules[].properties.cwe` (or `tags` containing `CWE-*`) |
| result identity | `results[].ruleId` (or `results[].rule.id`) |
| location | `results[].locations[0].physicalLocation.artifactLocation.uri`, `region.startLine`, `region.endLine` |
| message | `results[].message.text`, falling back to the rule's `shortDescription` |
| severity | `properties.security-severity` (numeric CVSS band) else `level` |
| snippet | `region.snippet.text` |
| source→sink | `results[].codeFlows` — only a count is kept; traces are not synthesised |

### OpenGrep / Semgrep JSON — `"format": "opengrep"`

`report` is the whole report object.

| Read | From |
|---|---|
| tool name / version | `tool.name` / `tool.version` (defaults to `opengrep`) |
| result identity | `results[].check_id` (or `rule_id`) |
| location | `results[].path`, `results[].start.line`, `results[].end.line` |
| message | `results[].extra.message` |
| severity | `results[].extra.severity` (`ERROR`→HIGH, `WARNING`→MEDIUM, `INFO`→LOW) |
| CWE | `results[].extra.metadata.cwe` (string or list) |
| snippet | `results[].extra.lines` |
| scanner errors | `errors[]` — reported as uninterpreted coverage, not as findings |

Anything without a rule id or a location is counted in `uninterpreted` and
never turned into a finding.

## Finding identity

Fingerprint recipe: `code-weakness` + org + project + `rule_id` + `path`
(`incidents.recipe_fingerprint`). Re-importing the same report creates no new
finding; each result becomes an `analysis_findings` row (so several lines of the
same rule in the same file show as separate locations pointing at one finding),
and each sighting is recorded as an occurrence.

## Code snapshots

`files: [{path, content, kind}]`, `kind` is `analyzed` (default) or `context`.
Limits: 500 files per import, 400 000 characters each.

A JSON report does not contain the source. If a path is referenced but not
supplied, the tree row is `reported-only`, `available: false`, and the file
endpoint answers with a reason ("no code snapshot was supplied"). The viewer
never draws an empty file as if it were clean.

## Diff

`diff` takes unified diff text. Parsed into per-file added/removed line numbers
and hunks. `on_modified_line` is true when the result's start line is in the
added set for that path.

`introduced_by_pr` is only true when there is a comparable base run AND the
result is `new` AND it sits on an added line. "On a modified line" alone never
claims introduction.

## Baseline and classification

`base_run_id` points at an earlier run of the same project version.

| Condition | `classification` |
|---|---|
| no base run | `no_reference` — not "new" |
| base run used a different tool | 409 — comparing across tools would invent findings |
| base run is another project version | 409 |
| rule+path present in base | `persistent` |
| rule+path absent from base | `new` |
| rule+path in a full base but absent from this full run | `resolved` (row points at the base finding) |

`resolved` is only derived when both runs declare `coverage: "full"`.

## Coverage

`coverage` is `full`, `diff`, `partial` or `unknown` and is what the closure gate
reads (`analysis.plan_closure`): only `full` may close findings, and only those
whose tool matches and whose path was inside `evaluated.paths`.

## What this slice does not do

- No execution of OpenGrep or any scanner; imports only.
- No automatic GitHub PR comments, no PR blocking.
- No source→sink analysis beyond what the report already carries.


## Run identity and navigation

Every run records what it analysed, not just what it found:

| Field | Where it comes from |
|---|---|
| `repository_id` | the repository id or its remote URL; anything outside the caller's organization is a 404 |
| `revision` / `base_revision` | the commit the report was produced on / against |
| `branch` | branch name when the report carries one |
| `pull_request` | PR number or reference when the run belongs to one |
| `coverage` | `full`, `diff`, `partial`; only `full` can close findings |

The console links both ways: `#analysis::run=<id>&path=…&line=…` opens the run,
the file and the line, and `#findings::<finding id>` opens the finding whose
drawer shows the run that last evaluated it. A finding is stamped with
`last_evaluated_run_id` on every import that matches it, not only when a run
closes it.

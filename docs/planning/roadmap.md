# Roadmap — real status table

| Phase | Goal | Status | Evidence |
|---|---|---|---|
| 0 Audit + matrix | KEEP/EXTEND/REPLACE/REMOVE honest baseline | **done** | this repo, docs/planning/*, AUDIT.md ledger history |
| 1 Baseline + branding | Naming, project identity, LICENSE decision | **mostly done; license decision pending** | BARAD-DÛR header in console; LICENSE file absent → decision needed (see compatibility doc) |
| 2 Scope model | Typed temporal M2M, observed vs authorized split | **started**: assets+scope tables live; full model next (BL-010/015) |
| 3 SBOM/SCA/vulns | B-complete: SPDX out, licenses, policies, continuous analysis | **strong core**, license + policy [gap] |
| 4 Pentest + Jira | Campaigns, engagements, Jira bridge | **not started** (BL-050/070) |
| 5 SAST/PR review | SARIF, branch baselines, inline code viewer, QG | **engine exists; screens [gap]** |
| 6 EASM continuous | DNS/TLS probing, snapshots, change history | **CT-only today** (BL-090) |
| 7 Shauron orchestration | Contract v0 + run scoping | **drafted** (`scanner-contract.md`) |
| 8 Regression | Authorized HTTP suites, redaction | **not started** (BL-080) |
| 9 Migration/retire | DT read-only retirement, Dojo drop path | **not started**; adapters already isolated |

Ordering rule: phases 2–3 refinement and 5 are the next code work after the
docs; 4 and 7 can proceed in parallel (independent domains); 8 needs 7's
authorization persistence; 9 is last-by-contract.

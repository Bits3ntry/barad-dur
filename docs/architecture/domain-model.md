# Domain model — current and target

Status labels: **[live]** = migrated + gated in AUDIT.md; **[next]** = designed,
not built; **[gap]** = not started.

## Identity and tenancy
- `Organization` **[live]** — POC single-tenant-per-key; the org is implicit
  (schema/env) at ingest time. Multi-org collections **[gap]** (BL-030).
- `ApiKey` **[live]** — sha256-stored hashes.
- `OrgMember` (owner/admin/analyst/viewer) **[live]** — roles carried, no login
  surface yet (auth plane = API key). OIDC/passwords **[gap]** (BL-020).
- `AuditLog` (per-org hash chain) **[live]**.

## Scope entities
- `Project`, `ProjectVersion` **[live]** — SBOM anchors, gates keyed per version.
- `Component` + `VersionComponent` **[live]** — identity_key (purl/bom-ref or
  `nonpurl:sha256(name:version)`), is_direct, unmapped count.
- `Repository` **[gap]** — today repos are CLI-side (.barad.yml), not platform
  entities (BL-010).
- `Service`, `Deployment` **[gap]** — nothing maps "the thing you deploy".
- `Domain`, `Subdomain`, `Ip`, `Endpoint` → unified as `Asset(type∈domain,ip,url,cidr)`
  **[live for raw storage]**, typed relations to projects/services **[next]**.

## Findings triad (OpenCTEM-parity concepts, own recipe)
- `Finding` **[live]** — one weakness per (org, project, kind, fingerprint);
  fingerprint recipes per kind (`app/incidents.py`, `app/vulns.py`); `last_seen_
  version_id` so version views never join components; priority + priority_reason
  + SLA deadline **[live]**; status/dispositions + suppressions (two layers,
  no-self-approval) **[live]**.
- `Occurrence` **[gap]** — multiple sightings of one finding (per scan/run/asset
  evidence) currently collapsed into refresh counters (BL-040).
- `Issue` (case/ticket abstraction + Jira mirror) **[gap]** (BL-050).

## Supply chain
- SBOM ingest with receipts (`content_sha256` idempotent) **[live]**.
- `Vulnerability` catalog (source_id + cve alias) + reconcile **[live]**.
- KEV/EPSS mirrors, VEX statements **[live]** (unsigned VEX **[next]**).
- License set per component + policies **[gap]** (BL-060).
- Signed feed trust **[gap]** — OSV live only (BL-065).

## CI + scopes
- `CiPipeline`, `CiRun`, `CiRunFindings`, fail-closed gate verdicts **[live]**.
- `scope_targets`/`scope_exclusions` **[live]** — static; observed-inventory vs
  scan-authorization split **[next]** (BL-015).

## Pentest + regression + Jira
- Campaigns/engagements/tests/evidence/reporting/retest **[gap]** (BL-070).
- HTTP regression suites with redaction **[gap]** (BL-080).
- Jira bidirectional bridge **[gap]** (BL-050).

## Provenance rules (always)
Every derived row carries its origin: `source` (cli/web/ci/api on findings),
`fingerprint` (dedup identity), `content_sha256` (ingest identity), audit chain
entries for decisions. Evidence storage stays CLI-side redacted until the
evidence vault entity exists (BL-045).

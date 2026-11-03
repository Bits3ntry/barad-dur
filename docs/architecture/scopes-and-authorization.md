# Scopes and scan authorization

## Principle (hard rule)

**Discovery ≠ authorization.** A subdomain found via certificate transparency
or DNS probing is *observed inventory*. Launching any intrusive test (nuclei
templates, pentest campaigns, active TLS probing that touches the target) over
it requires an explicit, separately-stored authorization. A blocker for one is
never derived from the other.

## Current state

| Concept | Status | Notes |
|---|---|---|
| Observed inventory | **live** | `assets` table (domain/ip/url/cidr), `source` field (`crtsh`, `seed`, `manual`), first/last_seen. Swap = refresh-only, never delete (267 real councilbox.com subdomains proved it). |
| Static scope rules | **live** | `scope_targets` (positive scoping) / `scope_exclusions` with explicit timestamps; gates consult them; resolution answers resolution/unresolved/excluded_count. |
| Scan authorization | **next** | Kept OUT of the assets table by design: `scan_authorizations` (asset/scope, approved_by, valid window, test profile allowed). No intrusive runner consumes assets until this exists. |
| Pentest target surfaces | **gap** | Campaigns bind to `scan_authorizations`, never to raw assets. |
| Wildcard domain handling | **next** | CT logs return wildcard-expanded names; the scope model needs a `.councilbox.com` wildcard scope row meaning "all subdomains, only passive". |

## Rules encoded here

1. Service registry: nothing in Barad-dûr ships an intrusive default. Nuclei
   and any future pentest engine run only through Shauron with an explicit
   `authorization_token` matched against `scan_authorizations`.
2. The Platform-CLI gate (fail-closed, HIGH) applies to the SBOM/SAST gate; it
   is not an authorization store — only scope-tables gating.
3. Distinguishing what is observed by whom: `Asset.source` + audit aromas for
   every sweep/add (already wired: `easm.sweep`, `asset.added`).
4. Ambient evidence: CRT sweep results live in `assets`; no contact with the
   observed host (no DNS record association checks, no port pings).

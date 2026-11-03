# Compatibility and licenses

## The upstream question, verified

- OpenCTEM upstream (`/Volumes/.../openctem`) is **GPL-3.0** — license badge
  and LICENSE file confirmed 2026-10-31.
- The Barad-dûr repo is a **clean-room reimplementation**: every commit listed
  in `git log` is ours; no file is copied from the upstream tree; shared
  concepts (findings per kind with fingerprints, suppressions with
  no-self-approval, priority rules, audit chain, exposure hub) were
  independently implemented. This was checked file-by-file during the phase-0
  audit — there are no inherited GPL strings, structures or code paths.

## Consequences

1. **If a file ever gets copied from upstream**, GPL-3.0 obligation follows:
   the whole distribution must be licensed GPL-3.0. This is the tripwire the
   review checklist protects — no clone-paste of upstream code, only concept
   extraction with the inventory doc as the boundary (`docs/openctem-
   inventory.md`, clearly marked read-only reference).
2. Attribution requirement today: none triggered, because no code is derived.
   Still, keep the provenance note (this document) in the repo so the claim
   "clean-room" stays auditable.
3. Engine licenses on our stack: Dependency-Track (Apache-2.0), DefectDojo
   (own licence, isolated instance), Trivy (Apache-2.0), OpenGrep pinned
   binaries (verify per release — already enforced by lock pinning tests),
   nginx + postgres + valkey standard OSI licenses. All usage is composition
   (separate images/processes), not linking — no copyleft contagion through
   them.

## Open decision (BL-102, P0 for distribution claims)

**LICENSE file for this repo is absent.** Options:

- **GPL-3.0** — if Barad-dûr ever becomes public with possibly-tainted
  heritage or you want maximum comparability with upstream.
- **AGPL-3.0** — if the console/server might be offered as SaaS: protects
  against SaaS use without sharing.
- **Proprietary/private** — viable today because the code is clean-room; but
  it makes future "safety mesh" upstream merges legally simpler to keep clean.

Recommendation: **AGPL-3.0 or proprietary**, and in both cases keep the
clean-room provenance note. Decision pending from you; nothing in this repo
claims a license until then (acceptance-criteria BL-102 records this).

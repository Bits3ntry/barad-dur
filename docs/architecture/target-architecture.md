# Barad-dûr — target architecture

## What this platform is

Barad-dûr is a self-contained ASPM + CTEM + EASM + Pentest-management platform.
Shauron Scanner is a SEPARATE product (CLI, GitHub Action, sensor/worker) that
talks to Barad-dûr through a versioned contract — it is not a module of this
repo. The platform keeps its own operating stack; the scanner ships its own.

## Current, deployed architecture (verified live, AUDIT.md is the ledger)

| Plane | Component | Tech | Where |
|---|---|---|---|
| API | Barad-dûr platform (`barad-platform`) | Python 3.12 + FastAPI + SQLAlchemy + Alembic | `backend/`, containerized `platform-api` (:8090) |
| Console | Barad-dûr console | React 18 (JS, no TS) + Vite, nginx proxy | `frontend/` → `console_html/`, `console` service (:8092) |
| CLI | `barad` scanner CLI | Python, engine pins in `resources/engines.lock.json` | `cli/` |
| Integrations | Dependency-Track + DefectDojo + platform adapters | `integrations/` | .barad.yml-driven |
| Storage | PostgreSQL — single source of truth, two apps DB-per-role (`dtrack`, `defectdojo`, `barad_platform`) | postgres 18.6 | compose `postgres`, loopback :15443 |
| Engines/sensors | Dependency-Track 5.2.1 (SCA UI), DefectDojo 3.4 (legacy opt-in), Trivy server (DT analyzer), Trivy+OpenGrep (CLI-side, pinned) | images in `compose.yaml` | loopback only |
| Intel feeds | OSV live (querybatch), CISA KEV + FIRST EPSS mirrors, crt.sh CT-logs | `backend/src/backend/app/` | no cache proxy yet |

Redis is absent from the platform plane by design; DefectDojo's valkey holds
only Dojo's queues/caches. PostgreSQL is never bypassed for critical data.

## Target stack deltas (what changes, phase by phase)

- **Phases 0–3 (now)**: keep the stack as deployed; evolve the platform schema
  (see `domain-model.md`).
- **Phase 4–8**: pentest campaigns become platform tables; Jira talks from the
  platform (outbox pattern — `outbox` table first, webhooks after); SAST review
  surfaces SARIF + inline code viewer; EASM grows DNS/TLS probing jobs; Shauron
  contract lands (`scanner-contract.md`); regression suites (`security-regressions`).
- **Phase 9**: gradual retirement of the DefectDojo adapter path; Dependency-Track
  stays as a read-only engine while the platform inventory is the master.

Nothing here copies OpenCTM code. OpenCTM concepts (findings lifecycle,
suppressions with approvals, priority rules, audit chain, EASM, exposure hub)
were re-implemented from scratch — contemporary commits never reference the
upstream tree.

## Success criterion to engineer for

From any finding there must be navigable (real FKs, not just text): project →
version → component / repository / code location / service / deployment /
domain-endpoint / audit entries / evidence / ticket / regression test. Missing
links are backlog items with IDs in `docs/planning/backlog.md`.
